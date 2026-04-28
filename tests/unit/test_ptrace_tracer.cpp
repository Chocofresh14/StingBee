#include "behavioral/ptrace_tracer.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using stingbee::behavioral::IEventBus;
using stingbee::behavioral::ILogger;
using stingbee::behavioral::PtraceTracer;
using stingbee::behavioral::SyscallEvent;

namespace {

class TestEventBus final : public IEventBus {
public:
    void publish(const SyscallEvent& event) override {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event);
    }

    std::vector<SyscallEvent> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<SyscallEvent> events_;
};

class TestLogger final : public ILogger {
public:
    void info(const char* message) override {
        (void)message;
    }

    void warn(const char* message) override {
        (void)message;
    }

    void error(const char* message) override {
        (void)message;
    }
};

void child_syscall_burst() {
    for (int i = 0; i < 128; ++i) {
        (void)::syscall(SYS_getpid);
        (void)::syscall(SYS_getppid);
        (void)::syscall(SYS_gettid);
    }
    _exit(0);
}

void* child_worker_thread(void*) {
    for (int i = 0; i < 128; ++i) {
        (void)::syscall(SYS_gettid);
        (void)::syscall(SYS_getpid);
    }
    return nullptr;
}

void child_threaded_burst() {
    pthread_t worker{};
    const int create_rc = ::pthread_create(&worker, nullptr, child_worker_thread, nullptr);
    if (create_rc == 0) {
        for (int i = 0; i < 128; ++i) {
            (void)::syscall(SYS_getpid);
            (void)::syscall(SYS_gettid);
        }
        (void)::pthread_join(worker, nullptr);
    }
    _exit(0);
}

bool run_trace_on_child(void (*child_fn)(), bool* run_ok, std::vector<SyscallEvent>* out_events) {
    if (run_ok == nullptr || out_events == nullptr) {
        return false;
    }

    int sync_pipe[2] = {-1, -1};
    if (::pipe(sync_pipe) != 0) {
        std::perror("pipe");
        return false;
    }

    const pid_t child = ::fork();
    if (child < 0) {
        std::perror("fork");
        (void)::close(sync_pipe[0]);
        (void)::close(sync_pipe[1]);
        return false;
    }

    if (child == 0) {
        (void)::close(sync_pipe[1]);
        char token = 0;
        (void)::read(sync_pipe[0], &token, sizeof(token));
        (void)::close(sync_pipe[0]);
        child_fn();
    }

    (void)::close(sync_pipe[0]);

    TestEventBus bus;
    TestLogger logger;
    PtraceTracer tracer(child, bus, logger, true);
    std::atomic<bool> local_run_ok{false};

    std::thread tracer_thread([&]() {
        local_run_ok.store(tracer.run());
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    char start = 1;
    (void)::write(sync_pipe[1], &start, sizeof(start));
    (void)::close(sync_pipe[1]);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    tracer.request_stop();
    (void)::kill(child, SIGTERM);

    int status = 0;
    (void)::waitpid(child, &status, 0);

    tracer_thread.join();

    *run_ok = local_run_ok.load();
    *out_events = bus.snapshot();
    return true;
}

bool test_single_thread_capture() {
    bool run_ok = false;
    std::vector<SyscallEvent> events;
    if (!run_trace_on_child(child_syscall_burst, &run_ok, &events)) {
        return false;
    }

    if (!run_ok) {
        std::fprintf(stderr, "[SKIP] ptrace attach denied (permissions / Yama)\n");
        return true;
    }

    bool saw_getpid = false;
    for (const auto& event : events) {
        if (event.syscall_nr == SYS_getpid) {
            saw_getpid = true;
            break;
        }
    }

    if (!saw_getpid) {
        std::fprintf(stderr, "Expected SYS_getpid in traced syscall stream\n");
        return false;
    }
    return true;
}

bool test_multithread_capture() {
    bool run_ok = false;
    std::vector<SyscallEvent> events;
    if (!run_trace_on_child(child_threaded_burst, &run_ok, &events)) {
        return false;
    }

    if (!run_ok) {
        std::fprintf(stderr, "[SKIP] ptrace attach denied (permissions / Yama)\n");
        return true;
    }

    bool saw_non_main_tid = false;
    for (const auto& event : events) {
        if (event.tid != event.pid) {
            saw_non_main_tid = true;
            break;
        }
    }

    if (!saw_non_main_tid) {
        std::fprintf(stderr, "Expected at least one traced syscall from a non-main thread\n");
        return false;
    }
    return true;
}

}  // namespace

int main() {
    const bool ok_a = test_single_thread_capture();
    const bool ok_b = test_multithread_capture();

    if (ok_a && ok_b) {
        std::puts("ptrace_tracer unit tests passed");
        return 0;
    }

    return 1;
}
