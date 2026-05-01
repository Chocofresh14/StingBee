#pragma once

#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "behavioral/ptrace_tracer.hpp"

namespace stingbee::behavioral {

enum class AlertSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct DetectionRule {
    std::string name;
    AlertSeverity severity;
    std::function<bool(const SyscallEvent&)> condition;
    int score = 0;
};

struct Alert {
    std::string rule_name;
    AlertSeverity severity;
    pid_t pid = 0;
    pid_t tid = 0;
    std::string syscall_name;
    std::string details;
    std::uint64_t timestamp_us = 0;
};

struct SyscallScore {
    pid_t pid = 0;
    int total_score = 0;
    std::deque<std::pair<std::uint64_t, SyscallEvent>> window;
    static constexpr int WINDOW_SIZE_MS = 5000;
};

class SyscallAnalyzer {
public:
    SyscallAnalyzer(IEventBus& bus, ILogger& logger);
    ~SyscallAnalyzer();

    void subscribe(IEventBus& bus);
    void on_syscall_event(const SyscallEvent& event);

    void add_rule(const DetectionRule& rule);
    void load_rules_from_config(const std::string& config_path);

    struct Metrics {
        std::atomic<std::uint64_t> events_processed{0};
        std::atomic<std::uint64_t> alerts_emitted{0};
        std::atomic<std::uint64_t> rules_triggered{0};
    };

    const Metrics& get_metrics() const { return metrics_; }

private:
    IEventBus& bus_;
    ILogger& logger_;
    std::mutex mutex_;
    std::vector<DetectionRule> rules_;
    std::map<pid_t, SyscallScore> process_scores_;

    Metrics metrics_;

    void evaluate_rules(const SyscallEvent& event);
    void prune_expired_windows();
    std::string get_syscall_name(int nr);
    AlertSeverity calculate_severity(const std::vector<const DetectionRule*>& triggered_rules);
    void emit_alert(const Alert& alert);
};

}
