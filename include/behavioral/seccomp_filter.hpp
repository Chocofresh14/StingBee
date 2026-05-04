#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "behavioral/ptrace_tracer.hpp"

namespace stingbee::behavioral {

enum class SeccompMode {
    Notify,
    Log,
};

enum class SeccompDecision {
    Block,
    Continue,
};

struct SeccompPolicy {
    SeccompMode mode = SeccompMode::Notify;
    SeccompDecision decision = SeccompDecision::Block;
    std::vector<std::string> suspect_syscalls;
};

class SeccompFilter {
public:
    SeccompFilter(IEventBus& bus, ILogger& logger, std::string thresholds_path = "config/thresholds.yaml");
    ~SeccompFilter();

    bool start();
    bool reload();
    void stop();

    bool running() const;
    SeccompPolicy policy() const;

private:
    struct LoadedFilter {
        void* ctx = nullptr;
        int notify_fd = -1;
    };

    IEventBus& bus_;
    ILogger& logger_;
    std::string thresholds_path_;

    mutable std::mutex mutex_;
    SeccompPolicy policy_;
    std::unordered_set<int> notify_syscalls_;
    std::unordered_set<int> log_syscalls_;
    std::vector<LoadedFilter> loaded_filters_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<std::thread> notify_thread_;

    bool load_policy_from_disk(SeccompPolicy* out_policy, std::string* error_message);
    bool install_rules(const SeccompPolicy& policy, bool force_reinstall);
    bool install_rule_batch(const SeccompPolicy& policy, const std::vector<int>& syscall_numbers);
    void start_notify_thread_if_needed();
    void notify_loop();
    void handle_notify_fd(int notify_fd);
};

}