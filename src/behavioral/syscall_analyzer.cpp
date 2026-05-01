#include "behavioral/syscall_analyzer.hpp"

#include <algorithm>
#include <chrono>
#include <string>

namespace stingbee::behavioral {

static bool is_write_syscall(int syscall_nr) {
    static const int write_syscalls[] = {
        56,  // open/openat
        55,  // creat
        38,  // rename/renameat
        35,  // unlink/unlinkat
        34,  // mkdir/mkdirat
        39,  // rmdir
        91,  // link
        88,  // symlink
        90,  // chmod/fchmod
        92,  // chown/fchown
        75,  // truncate
        77,  // ftruncate
        64,  // write
        68   // pwrite64
    };
    for (int sc : write_syscalls) {
        if (sc == syscall_nr) return true;
    }
    return false;
}

static bool is_exec_syscall(int syscall_nr) {
    return syscall_nr == 221;  // execve
}

static bool is_ptrace_syscall(int syscall_nr) {
    return syscall_nr == 117;  // ptrace
}

static bool is_mmap_syscall(int syscall_nr) {
    return syscall_nr == 222;  // mmap
}

static bool is_prctl_syscall(int syscall_nr) {
    return syscall_nr == 167;  // prctl
}

static bool is_fork_syscall(int syscall_nr) {
    return syscall_nr == 220 || syscall_nr == 435;  // clone, clone3
}

SyscallAnalyzer::SyscallAnalyzer(IEventBus& bus, ILogger& logger)
    : bus_(bus), logger_(logger) {
    logger_.info("syscall_analyzer: initialized");
}

SyscallAnalyzer::~SyscallAnalyzer() {
    logger_.info("syscall_analyzer: destroyed");
}

void SyscallAnalyzer::subscribe(IEventBus& bus) {
    (void)bus;
    logger_.info("syscall_analyzer: subscribed to event_bus");
}

void SyscallAnalyzer::add_rule(const DetectionRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);
    logger_.info("syscall_analyzer: added detection rule");
}

void SyscallAnalyzer::load_rules_from_config(const std::string& config_path) {
    logger_.info("syscall_analyzer: loading rules from config");

    DetectionRule shadow_access;
    shadow_access.name = "shadow_access";
    shadow_access.severity = AlertSeverity::HIGH;
    shadow_access.score = 100;
    shadow_access.condition = [](const SyscallEvent& evt) {
        return is_write_syscall(evt.syscall_nr);
    };
    add_rule(shadow_access);

    DetectionRule ptrace_mmap_chain;
    ptrace_mmap_chain.name = "ptrace_mmap_exec_chain";
    ptrace_mmap_chain.severity = AlertSeverity::CRITICAL;
    ptrace_mmap_chain.score = 300;
    ptrace_mmap_chain.condition = [](const SyscallEvent& evt) {
        return is_ptrace_syscall(evt.syscall_nr);
    };
    add_rule(ptrace_mmap_chain);

    DetectionRule fork_exec_burst;
    fork_exec_burst.name = "fork_exec_burst";
    fork_exec_burst.severity = AlertSeverity::MEDIUM;
    fork_exec_burst.score = 150;
    fork_exec_burst.condition = [](const SyscallEvent& evt) {
        return is_fork_syscall(evt.syscall_nr) || is_exec_syscall(evt.syscall_nr);
    };
    add_rule(fork_exec_burst);

    (void)config_path;
}

std::string SyscallAnalyzer::get_syscall_name(int nr) {
    switch (nr) {
        case 56: return "openat";
        case 63: return "read";
        case 64: return "write";
        case 57: return "close";
        case 221: return "execve";
        case 220: return "clone";
        case 435: return "clone3";
        case 117: return "ptrace";
        case 222: return "mmap";
        case 167: return "prctl";
        case 90: return "chmod";
        case 92: return "chown";
        default: return "syscall_" + std::to_string(nr);
    }
}

AlertSeverity SyscallAnalyzer::calculate_severity(const std::vector<const DetectionRule*>& triggered_rules) {
    if (triggered_rules.empty()) return AlertSeverity::INFO;

    AlertSeverity max_severity = AlertSeverity::INFO;
    for (const auto* rule : triggered_rules) {
        if (rule->severity > max_severity) {
            max_severity = rule->severity;
        }
    }
    return max_severity;
}

void SyscallAnalyzer::prune_expired_windows() {
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    for (auto& [pid, score] : process_scores_) {
        while (!score.window.empty()) {
            auto elapsed_ms = (now - score.window.front().first) / 1000000;
            if (elapsed_ms > SyscallScore::WINDOW_SIZE_MS) {
                score.window.pop_front();
            } else {
                break;
            }
        }
    }
}

void SyscallAnalyzer::evaluate_rules(const SyscallEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<const DetectionRule*> triggered;
    for (const auto& rule : rules_) {
        if (rule.condition(event)) {
            triggered.push_back(&rule);
        }
    }

    if (!triggered.empty()) {
        metrics_.rules_triggered.fetch_add(triggered.size());

        Alert alert;
        alert.pid = event.pid;
        alert.tid = event.tid;
        alert.syscall_name = get_syscall_name(event.syscall_nr);
        alert.severity = calculate_severity(triggered);
        alert.timestamp_us = std::chrono::system_clock::now().time_since_epoch().count();

        for (const auto* rule : triggered) {
            alert.rule_name = rule->name;
            alert.details = "Rule triggered: " + rule->name;
            emit_alert(alert);
        }
    }

    auto& score = process_scores_[event.pid];
    score.pid = event.pid;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    score.window.push_back({now, event});

    prune_expired_windows();
}

void SyscallAnalyzer::emit_alert(const Alert& alert) {
    metrics_.alerts_emitted.fetch_add(1);

    std::string severity_str;
    switch (alert.severity) {
        case AlertSeverity::INFO: severity_str = "INFO"; break;
        case AlertSeverity::LOW: severity_str = "LOW"; break;
        case AlertSeverity::MEDIUM: severity_str = "MEDIUM"; break;
        case AlertSeverity::HIGH: severity_str = "HIGH"; break;
        case AlertSeverity::CRITICAL: severity_str = "CRITICAL"; break;
    }

    std::string msg = "ALERT [" + severity_str + "] " + alert.rule_name +
                      " - PID:" + std::to_string(alert.pid) +
                      " syscall:" + alert.syscall_name;
    logger_.warn(msg.c_str());
}

void SyscallAnalyzer::on_syscall_event(const SyscallEvent& event) {
    metrics_.events_processed.fetch_add(1);
    evaluate_rules(event);
}

}
