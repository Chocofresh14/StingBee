#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "behavioral/ptrace_tracer.hpp"

namespace stingbee::behavioral {

struct AuditEvent {
    std::uint32_t seq = 0;
    std::string type;
    pid_t pid = 0;
    pid_t ppid = 0;
    uid_t uid = 0;
    std::string comm;
    std::string exe;
    std::string cwd;
    std::vector<std::string> args;
    int exit_code = 0;
};

class AuditdEventAnalyzer {
public:
    AuditdEventAnalyzer(IEventBus& bus, ILogger& logger);
    ~AuditdEventAnalyzer();

    bool start();
    void stop();

private:
    IEventBus& bus_;
    ILogger& logger_;
    std::atomic<bool> running_{false};
    int audit_fd_ = -1;
    std::unique_ptr<std::thread> listener_thread_;

    std::map<std::uint32_t, AuditEvent> pending_events_;
    static constexpr int EVENT_TIMEOUT_MS = 500;

    void listen_loop();
    bool reconnect_audit();
    void parse_audit_message(const std::string& message);
    void finalize_event(std::uint32_t seq);
    std::map<std::string, std::string> parse_key_value(const std::string& line);
};

}
