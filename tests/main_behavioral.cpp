#include "behavioral/auditd_event_analyzer.hpp"
#include "behavioral/ebpf_loader.hpp"
#include "behavioral/ptrace_tracer.hpp"
#include "behavioral/seccomp_filter.hpp"
#include "behavioral/syscall_analyzer.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

using stingbee::behavioral::AuditdEventAnalyzer;
using stingbee::behavioral::EbpfLoader;
using stingbee::behavioral::IEventBus;
using stingbee::behavioral::ILogger;
using stingbee::behavioral::PtraceTracer;
using stingbee::behavioral::SeccompFilter;
using stingbee::behavioral::SyscallAnalyzer;
using stingbee::behavioral::SyscallEvent;

namespace {

volatile std::sig_atomic_t g_stop_requested = 0;

void handle_signal(int) {
    g_stop_requested = 1;
}

class ConsoleLogger final : public ILogger {
public:
    void info(const char* message) override {
        write_line("INFO", message, std::cout);
    }

    void warn(const char* message) override {
        write_line("WARN", message, std::cout);
    }

    void error(const char* message) override {
        write_line("ERROR", message, std::cerr);
    }

private:
    std::mutex mutex_;

    void write_line(const char* level, const char* message, std::ostream& stream) {
        std::lock_guard<std::mutex> lock(mutex_);
        stream << '[' << level << "] " << message << '\n';
        stream.flush();
    }
};

class DebugEventBus final : public IEventBus {
public:
    using Subscriber = std::function<void(const SyscallEvent&)>;

    void subscribe(Subscriber subscriber) {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers_.push_back(std::move(subscriber));
    }

    void publish(const SyscallEvent& event) override {
        std::vector<Subscriber> subscribers_copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            subscribers_copy = subscribers_;
        }

        for (const auto& subscriber : subscribers_copy) {
            if (subscriber) {
                subscriber(event);
            }
        }
    }

private:
    std::mutex mutex_;
    std::vector<Subscriber> subscribers_;
};

class ThreadPool {
public:
    explicit ThreadPool(std::size_t worker_count) {
        if (worker_count == 0) {
            worker_count = 1;
        }

        for (std::size_t index = 0; index < worker_count; ++index) {
            workers_.emplace_back([this]() { worker_loop(); });
        }
    }

    ~ThreadPool() {
        stop();
    }

    template <typename Callable>
    auto submit(Callable&& callable) -> std::future<std::invoke_result_t<Callable&>> {
        using Result = std::invoke_result_t<Callable&>;

        auto task = std::make_shared<std::packaged_task<Result()>>(std::forward<Callable>(callable));
        std::future<Result> future = task->get_future();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks_.push([task]() { (*task)(); });
        }

        condition_.notify_one();
        return future;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }

        condition_.notify_all();

        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        workers_.clear();
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;

    void worker_loop() {
        while (true) {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this]() { return stopping_ || !tasks_.empty(); });

                if (stopping_ && tasks_.empty()) {
                    return;
                }

                task = std::move(tasks_.front());
                tasks_.pop();
            }

            task();
        }
    }
};

std::string syscall_event_to_string(const SyscallEvent& event) {
    std::ostringstream output;
    output << "SyscallEvent pid=" << event.pid
           << " tid=" << event.tid
           << " nr=" << event.syscall_nr
           << " retval=" << event.retval
           << " args=[";

    for (std::size_t index = 0; index < event.args.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << std::showbase << std::hex << event.args[index] << std::dec;
    }

    output << ']';
    return output.str();
}

bool parse_pid(const char* text, pid_t* out_pid) {
    if (text == nullptr || out_pid == nullptr) {
        return false;
    }

    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if (end == text || *end != '\0' || value <= 0) {
        return false;
    }

    *out_pid = static_cast<pid_t>(value);
    return true;
}

bool process_exists(pid_t pid) {
    if (::kill(pid, 0) == 0) {
        return true;
    }
    return errno != ESRCH;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <PID>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = 0;
    if (!parse_pid(argv[1], &target_pid)) {
        std::fprintf(stderr, "invalid pid: %s\n", argv[1]);
        return 1;
    }

    if (!process_exists(target_pid)) {
        std::fprintf(stderr, "target pid %d does not exist or cannot be observed\n", static_cast<int>(target_pid));
        return 1;
    }

    struct sigaction action {};
    action.sa_handler = handle_signal;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    (void)::sigaction(SIGINT, &action, nullptr);
    (void)::sigaction(SIGTERM, &action, nullptr);

    ConsoleLogger logger;
    DebugEventBus bus;
    ThreadPool thread_pool(6);

    SyscallAnalyzer syscall_analyzer(bus, logger);

    std::future<void> analyzer_future = thread_pool.submit([&]() {
        syscall_analyzer.subscribe(bus);
        syscall_analyzer.load_rules_from_config("config/thresholds.yaml");
    });

    bus.subscribe([&](const SyscallEvent& event) {
        logger.info(syscall_event_to_string(event).c_str());
    });

    bus.subscribe([&](const SyscallEvent& event) {
        syscall_analyzer.on_syscall_event(event);
    });

    PtraceTracer tracer(target_pid, bus, logger, true);
    EbpfLoader ebpf_loader(bus, logger);
    AuditdEventAnalyzer auditd_analyzer(bus, logger);
    SeccompFilter seccomp_filter(bus, logger, "config/thresholds.yaml");

    std::promise<pthread_t> tracer_thread_id_promise;
    std::future<pthread_t> tracer_thread_id_future = tracer_thread_id_promise.get_future();

    std::future<bool> tracer_future = thread_pool.submit([&]() {
        tracer_thread_id_promise.set_value(::pthread_self());
        return tracer.run();
    });

    std::future<bool> ebpf_future = thread_pool.submit([&]() {
        const bool loaded = ebpf_loader.load_object("ebpf/syscall_hook.bpf.o");
        const bool started = ebpf_loader.start_polling();
        if (!started) {
            logger.warn("ebpf_loader: polling not started");
        }
        return loaded;
    });

    std::future<bool> audit_future = thread_pool.submit([&]() {
        return auditd_analyzer.start();
    });

    std::future<bool> seccomp_future = thread_pool.submit([&]() {
        return seccomp_filter.start();
    });

    const pthread_t tracer_thread = tracer_thread_id_future.get();

    analyzer_future.get();

    if (!ebpf_future.get()) {
        logger.warn("ebpf_loader: start sequence returned false");
    }

    if (!audit_future.get()) {
        logger.warn("auditd_analyzer: start sequence returned false");
    }

    if (!seccomp_future.get()) {
        logger.warn("seccomp_filter: start sequence returned false");
    }

    logger.info("main_behavioral: started, press Ctrl+C to stop");

    bool tracer_finished = false;
    while (!g_stop_requested) {
        if (tracer_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            const bool tracer_ok = tracer_future.get();
            tracer_finished = true;
            if (!tracer_ok) {
                logger.error("ptrace_tracer: run() returned false");
            }
            g_stop_requested = 1;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    tracer.request_stop();
    (void)::pthread_kill(tracer_thread, SIGTERM);

    seccomp_filter.stop();
    auditd_analyzer.stop();
    ebpf_loader.stop();

    if (!tracer_finished && tracer_future.valid()) {
        const bool tracer_ok = tracer_future.get();
        if (!tracer_ok) {
            logger.warn("ptrace_tracer: shutdown completed after an early failure");
        }
    }

    thread_pool.stop();
    logger.info("main_behavioral: stopped");
    return 0;
}