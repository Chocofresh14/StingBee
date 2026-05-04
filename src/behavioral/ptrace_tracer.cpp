#include "behavioral/ptrace_tracer.hpp"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <array>
#include <string>
#include <unordered_map>
#include <vector>

#include <dirent.h>
#if defined(__aarch64__)
#include <asm/ptrace.h>
#endif
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

namespace stingbee::behavioral {
namespace {

std::atomic<bool> g_stop_from_signal{false};

void on_termination_signal(int) {
    g_stop_from_signal.store(true);
}

bool is_numeric_name(const char* text) {
    if (text == nullptr || *text == '\0') {
        return false;
    }

    for (const char* ptr = text; *ptr != '\0'; ++ptr) {
        if (*ptr < '0' || *ptr > '9') {
            return false;
        }
    }
    return true;
}

std::vector<pid_t> list_threads(pid_t pid) {
    std::vector<pid_t> tids;
    char path[128] = {};
    std::snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR* dir = ::opendir(path);
    if (dir == nullptr) {
        return tids;
    }

    while (dirent* entry = ::readdir(dir)) {
        if (!is_numeric_name(entry->d_name)) {
            continue;
        }
        tids.push_back(static_cast<pid_t>(std::strtol(entry->d_name, nullptr, 10)));
    }

    ::closedir(dir);
    return tids;
}

pid_t read_tgid_of_tid(pid_t tid) {
    char path[128] = {};
    std::snprintf(path, sizeof(path), "/proc/%d/status", tid);

    FILE* fp = std::fopen(path, "r");
    if (fp == nullptr) {
        return 0;
    }

    char line[256] = {};
    pid_t tgid = 0;
    while (std::fgets(line, sizeof(line), fp) != nullptr) {
        if (std::strncmp(line, "Tgid:\t", 6) == 0) {
            tgid = static_cast<pid_t>(std::strtol(line + 6, nullptr, 10));
            break;
        }
    }

    std::fclose(fp);
    return tgid;
}

struct ThreadState {
    bool in_syscall = false;
    SyscallEvent enter_event{};
};

}

struct PtraceTracer::Impl {
    pid_t target_pid = 0;
    IEventBus* event_bus = nullptr;
    ILogger* logger = nullptr;
    bool prefer_seize = true;
    std::atomic<bool>* stop_requested = nullptr;

    std::unordered_map<pid_t, ThreadState> thread_states;

    bool setup_signal_handler() {
        return true;
    }

    bool should_stop() const {
        return stop_requested->load() || g_stop_from_signal.load();
    }

    long ptrace_options() const {
        return PTRACE_O_TRACESYSGOOD |
               PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEFORK |
               PTRACE_O_TRACEVFORK |
               PTRACE_O_EXITKILL;
    }

    bool set_trace_options(pid_t tid) {
        if (::ptrace(PTRACE_SETOPTIONS, tid, nullptr, ptrace_options()) != 0) {
            logger->error("ptrace_tracer: PTRACE_SETOPTIONS failed");
            return false;
        }
        return true;
    }

    bool resume_syscall(pid_t tid, int sig = 0) {
        if (::ptrace(PTRACE_SYSCALL, tid, nullptr, sig) != 0) {
            if (errno != ESRCH) {
                logger->warn("ptrace_tracer: PTRACE_SYSCALL failed");
            }
            return false;
        }
        return true;
    }

    bool wait_for_initial_stop(pid_t tid) {
        int status = 0;
        const pid_t waited = ::waitpid(tid, &status, __WALL);
        if (waited < 0) {
            logger->error("ptrace_tracer: waitpid failed while attaching");
            return false;
        }
        return WIFSTOPPED(status);
    }

    bool attach_single_tid(pid_t tid) {
        bool attached = false;

        if (prefer_seize) {
            if (::ptrace(PTRACE_SEIZE, tid, nullptr, ptrace_options()) == 0) {
                attached = true;
                if (::ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0) {
                    logger->error("ptrace_tracer: PTRACE_INTERRUPT failed after SEIZE");
                    return false;
                }
                if (!wait_for_initial_stop(tid)) {
                    logger->error("ptrace_tracer: failed to observe initial stop after SEIZE");
                    return false;
                }
            }
        }

        if (!attached) {
            if (::ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != 0) {
                logger->error("ptrace_tracer: PTRACE_ATTACH failed");
                return false;
            }

            if (!wait_for_initial_stop(tid)) {
                logger->error("ptrace_tracer: failed to observe initial stop after ATTACH");
                return false;
            }

            if (!set_trace_options(tid)) {
                return false;
            }
        }

        thread_states.emplace(tid, ThreadState{});
        return resume_syscall(tid);
    }

    bool attach_initial_threads() {
        std::vector<pid_t> tids = list_threads(target_pid);
        if (tids.empty()) {
            tids.push_back(target_pid);
        }

        bool at_least_one = false;
        for (pid_t tid : tids) {
            if (attach_single_tid(tid)) {
                at_least_one = true;
            }
        }

        if (!at_least_one) {
            logger->error("ptrace_tracer: unable to attach to any target thread");
        }
        return at_least_one;
    }

    bool read_syscall_enter(pid_t tid, SyscallEvent* out_event) {
        if (out_event == nullptr) {
            return false;
        }

#if defined(__x86_64__)
        user_regs_struct regs {};
        if (::ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) {
            logger->warn("ptrace_tracer: PTRACE_GETREGS failed on syscall-enter");
            return false;
        }

        out_event->syscall_nr = static_cast<std::int64_t>(regs.orig_rax);
        out_event->args[0] = regs.rdi;
        out_event->args[1] = regs.rsi;
        out_event->args[2] = regs.rdx;
        out_event->args[3] = regs.r10;
        out_event->args[4] = regs.r8;
        out_event->args[5] = regs.r9;
        return true;
    #elif defined(__aarch64__)
        user_pt_regs regs {};
        iovec io {};
        io.iov_base = &regs;
        io.iov_len = sizeof(regs);
        if (::ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &io) != 0) {
            logger->warn("ptrace_tracer: PTRACE_GETREGSET failed on syscall-enter");
            return false;
        }

        out_event->syscall_nr = static_cast<std::int64_t>(regs.regs[8]);
        out_event->args[0] = regs.regs[0];
        out_event->args[1] = regs.regs[1];
        out_event->args[2] = regs.regs[2];
        out_event->args[3] = regs.regs[3];
        out_event->args[4] = regs.regs[4];
        out_event->args[5] = regs.regs[5];
        return true;
#else
        (void)tid;
        logger->warn("ptrace_tracer: no fallback register decoder for this architecture");
        return false;
#endif
    }

    bool read_syscall_exit(pid_t tid, std::int64_t* out_retval) {
        if (out_retval == nullptr) {
            return false;
        }

#if defined(__x86_64__)
        user_regs_struct regs {};
        if (::ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) {
            logger->warn("ptrace_tracer: PTRACE_GETREGS failed on syscall-exit");
            return false;
        }

        *out_retval = static_cast<std::int64_t>(regs.rax);
        return true;
#elif defined(__aarch64__)
        user_pt_regs regs {};
        iovec io {};
        io.iov_base = &regs;
        io.iov_len = sizeof(regs);
        if (::ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &io) != 0) {
            logger->warn("ptrace_tracer: PTRACE_GETREGSET failed on syscall-exit");
            return false;
        }

        *out_retval = static_cast<std::int64_t>(regs.regs[0]);
        return true;
#else
        (void)tid;
        logger->warn("ptrace_tracer: no fallback retval decoder for this architecture");
        return false;
#endif
    }

    void handle_syscall_stop(pid_t tid) {
        auto& state = thread_states[tid];
        if (!state.in_syscall) {
            SyscallEvent enter_event{};
            if (!read_syscall_enter(tid, &enter_event)) {
                return;
            }
            enter_event.tid = tid;
            const pid_t tgid = read_tgid_of_tid(tid);
            enter_event.pid = (tgid != 0) ? tgid : target_pid;
            state.enter_event = enter_event;
            state.in_syscall = true;
            return;
        }

        std::int64_t retval = 0;
        if (!read_syscall_exit(tid, &retval)) {
            state.in_syscall = false;
            return;
        }

        SyscallEvent event = state.enter_event;
        event.retval = retval;
        event_bus->publish(event);
        state.in_syscall = false;
    }

    void handle_new_tracee_event(pid_t origin_tid) {
        unsigned long message = 0;
        if (::ptrace(PTRACE_GETEVENTMSG, origin_tid, nullptr, &message) != 0) {
            logger->warn("ptrace_tracer: PTRACE_GETEVENTMSG failed");
            return;
        }

        const pid_t new_tid = static_cast<pid_t>(message);
        if (new_tid <= 0) {
            return;
        }

        thread_states.emplace(new_tid, ThreadState{});
        (void)set_trace_options(new_tid);
        (void)resume_syscall(new_tid);
    }

    void detach_all() {
        for (const auto& kv : thread_states) {
            const pid_t tid = kv.first;
            if (::ptrace(PTRACE_DETACH, tid, nullptr, nullptr) != 0) {
                if (errno != ESRCH) {
                    logger->warn("ptrace_tracer: PTRACE_DETACH failed for a thread");
                }
            }
        }
        thread_states.clear();
    }

    void trace_loop() {
        while (!should_stop() && !thread_states.empty()) {
            int status = 0;
            const pid_t tid = ::waitpid(-1, &status, __WALL);
            if (tid < 0) {
                if (errno == EINTR) {
                    continue;
                }
                logger->error("ptrace_tracer: waitpid failed in trace loop");
                break;
            }

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                thread_states.erase(tid);
                continue;
            }

            if (!WIFSTOPPED(status)) {
                continue;
            }

            const int signal_number = WSTOPSIG(status);
            const unsigned int ptrace_event = static_cast<unsigned int>(status >> 16);

            if (ptrace_event == PTRACE_EVENT_CLONE ||
                ptrace_event == PTRACE_EVENT_FORK ||
                ptrace_event == PTRACE_EVENT_VFORK) {
                handle_new_tracee_event(tid);
                (void)resume_syscall(tid);
                continue;
            }

            if (signal_number == (SIGTRAP | 0x80)) {
                handle_syscall_stop(tid);
                (void)resume_syscall(tid);
                continue;
            }

            if (signal_number == SIGTRAP) {
                (void)resume_syscall(tid);
                continue;
            }

            (void)resume_syscall(tid, signal_number);
        }
    }
};

PtraceTracer::PtraceTracer(pid_t target_pid, IEventBus& event_bus, ILogger& logger, bool prefer_seize)
    : target_pid_(target_pid), event_bus_(event_bus), logger_(logger), prefer_seize_(prefer_seize) {}

bool PtraceTracer::run() {
    Impl impl{};
    impl.target_pid = target_pid_;
    impl.event_bus = &event_bus_;
    impl.logger = &logger_;
    impl.prefer_seize = prefer_seize_;
    impl.stop_requested = &stop_requested_;

    if (!impl.setup_signal_handler()) {
        return false;
    }

    if (!impl.attach_initial_threads()) {
        return false;
    }

    impl.logger->info("ptrace_tracer: tracing started");
    impl.trace_loop();
    impl.detach_all();
    impl.logger->info("ptrace_tracer: tracing stopped");
    return true;
}

void PtraceTracer::request_stop() {
    stop_requested_.store(true);
}

}
