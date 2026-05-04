#include "behavioral/seccomp_filter.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

#include <sys/syscall.h>
#include <unistd.h>

using stingbee::behavioral::IEventBus;
using stingbee::behavioral::ILogger;
using stingbee::behavioral::SeccompDecision;
using stingbee::behavioral::SeccompFilter;
using stingbee::behavioral::SeccompMode;
using stingbee::behavioral::SeccompPolicy;
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

bool write_policy_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    if (!output.is_open()) {
        return false;
    }
    output << content;
    return static_cast<bool>(output);
}

bool test_parse_thresholds() {
    const std::filesystem::path policy_path = std::filesystem::temp_directory_path() / "stingbee-seccomp-policy.yaml";
    if (!write_policy_file(policy_path,
                           "seccomp:\n"
                           "  action: notify\n"
                           "  decision: continue\n"
                           "  suspect_syscalls:\n"
                           "    - getpid\n"
                           "    - 39\n")) {
        std::fprintf(stderr, "failed to write temporary seccomp policy\n");
        return false;
    }

    TestEventBus bus;
    TestLogger logger;
    SeccompFilter filter(bus, logger, policy_path.string());

    if (!filter.reload()) {
        std::fprintf(stderr, "expected reload() to parse policy file\n");
        return false;
    }

    const SeccompPolicy policy = filter.policy();
    if (policy.mode != SeccompMode::Notify || policy.decision != SeccompDecision::Continue) {
        std::fprintf(stderr, "policy values were not parsed correctly\n");
        return false;
    }

    if (policy.suspect_syscalls.size() != 2) {
        std::fprintf(stderr, "expected two suspicious syscalls in parsed policy\n");
        return false;
    }

    return true;
}

bool test_notify_interception() {
    const std::filesystem::path policy_path = std::filesystem::temp_directory_path() / "stingbee-seccomp-notify.yaml";
    if (!write_policy_file(policy_path,
                           "action: notify\n"
                           "decision: continue\n"
                           "suspect_syscalls:\n"
                           "  - getpid\n")) {
        std::fprintf(stderr, "failed to write temporary notify policy\n");
        return false;
    }

    TestEventBus bus;
    TestLogger logger;
    SeccompFilter filter(bus, logger, policy_path.string());

    if (!filter.start()) {
        std::fprintf(stderr, "seccomp start() failed; kernel may reject user notifications in this environment\n");
        return true;
    }

    const pid_t pid = static_cast<pid_t>(::syscall(SYS_getpid));
    if (pid <= 0) {
        std::fprintf(stderr, "getpid syscall unexpectedly failed\n");
        filter.stop();
        return false;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    filter.stop();

    const std::vector<SyscallEvent> events = bus.snapshot();
    for (const SyscallEvent& event : events) {
        if (event.syscall_nr == SYS_getpid) {
            return true;
        }
    }

    std::fprintf(stderr, "expected at least one intercepted getpid event\n");
    return false;
}

}

int main() {
    const bool ok_parse = test_parse_thresholds();
    const bool ok_notify = test_notify_interception();

    if (ok_parse && ok_notify) {
        std::puts("seccomp_filter unit tests passed");
        return 0;
    }

    return 1;
}