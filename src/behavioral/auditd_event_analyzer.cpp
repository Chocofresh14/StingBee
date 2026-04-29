#include "behavioral/auditd_event_analyzer.hpp"

#include <libaudit.h>
#include <sstream>
#include <chrono>
#include <unistd.h>
#include <cstdlib>

namespace stingbee::behavioral {

AuditdEventAnalyzer::AuditdEventAnalyzer(IEventBus& bus, ILogger& logger)
    : bus_(bus), logger_(logger), audit_fd_(-1) {}

AuditdEventAnalyzer::~AuditdEventAnalyzer() {
    stop();
}

bool AuditdEventAnalyzer::start() {
    if (running_.load()) return true;

    if (!reconnect_audit()) {
        logger_.error("auditd_analyzer: failed to connect to auditd");
        return false;
    }

    running_.store(true);
    listener_thread_ = std::make_unique<std::thread>([this]() { listen_loop(); });

    logger_.info("auditd_analyzer: started");
    return true;
}

void AuditdEventAnalyzer::stop() {
    running_.store(false);
    if (listener_thread_ && listener_thread_->joinable()) {
        listener_thread_->join();
    }
    if (audit_fd_ >= 0) {
        audit_close(audit_fd_);
        audit_fd_ = -1;
    }
    logger_.info("auditd_analyzer: stopped");
}

bool AuditdEventAnalyzer::reconnect_audit() {
    if (audit_fd_ >= 0) {
        audit_close(audit_fd_);
    }

    audit_fd_ = audit_open();
    if (audit_fd_ < 0) {
        logger_.warn("auditd_analyzer: audit_open failed");
        return false;
    }

    if (audit_set_enabled(audit_fd_, 1) < 0) {
        logger_.warn("auditd_analyzer: audit_set_enabled failed");
        audit_close(audit_fd_);
        audit_fd_ = -1;
        return false;
    }

    if (audit_set_backlog_wait_time(audit_fd_, 0) < 0) {
        logger_.warn("auditd_analyzer: audit_set_backlog_wait_time failed");
    }

    logger_.info("auditd_analyzer: connected to auditd");
    return true;
}

std::map<std::string, std::string> AuditdEventAnalyzer::parse_key_value(const std::string& line) {
    std::map<std::string, std::string> kv;
    std::istringstream iss(line);
    std::string token;

    while (iss >> token) {
        size_t eq_pos = token.find('=');
        if (eq_pos != std::string::npos && eq_pos > 0 && eq_pos < token.length() - 1) {
            std::string key = token.substr(0, eq_pos);
            std::string value = token.substr(eq_pos + 1);

            if (value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.length() - 2);
            }

            kv[key] = value;
        }
    }

    return kv;
}

void AuditdEventAnalyzer::parse_audit_message(const std::string& message) {
    auto kv = parse_key_value(message);

    std::uint32_t seq = 0;
    if (kv.count("msg")) {
        sscanf(kv["msg"].c_str(), "audit(%*u.%*u):%u", &seq);
    }

    if (seq == 0) return;

    if (pending_events_.find(seq) == pending_events_.end()) {
        AuditEvent new_event;
        new_event.seq = seq;
        pending_events_[seq] = new_event;
    }

    AuditEvent& event = pending_events_[seq];

    if (kv.count("type")) {
        event.type = kv["type"];
    }

    if (kv.count("pid")) {
        event.pid = std::stoi(kv["pid"]);
    }

    if (kv.count("ppid")) {
        event.ppid = std::stoi(kv["ppid"]);
    }

    if (kv.count("uid")) {
        event.uid = std::stoi(kv["uid"]);
    }

    if (kv.count("comm")) {
        event.comm = kv["comm"];
    }

    if (kv.count("exe")) {
        event.exe = kv["exe"];
    }

    if (kv.count("cwd")) {
        event.cwd = kv["cwd"];
    }

    if (kv.count("exit")) {
        event.exit_code = std::stoi(kv["exit"]);
    }

    if (kv.count("a0")) {
        event.args.push_back(kv["a0"]);
    }
    if (kv.count("a1")) {
        event.args.push_back(kv["a1"]);
    }
    if (kv.count("a2")) {
        event.args.push_back(kv["a2"]);
    }
    if (kv.count("a3")) {
        event.args.push_back(kv["a3"]);
    }
}

void AuditdEventAnalyzer::finalize_event(std::uint32_t seq) {
    auto it = pending_events_.find(seq);
    if (it != pending_events_.end()) {
        pending_events_.erase(it);
    }
}

void AuditdEventAnalyzer::listen_loop() {
    logger_.info("auditd_analyzer: listener thread started");

    audit_reply* reply = (audit_reply*)malloc(sizeof(*reply));
    if (!reply) {
        logger_.error("auditd_analyzer: malloc failed for audit_reply");
        return;
    }

    while (running_.load()) {
        if (audit_fd_ < 0) {
            if (!reconnect_audit()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }

        int ret = audit_get_reply(audit_fd_, reply, GET_REPLY_BLOCKING, 0);

        if (ret > 0) {
                if (reply->type != AUDIT_EOE && reply->len > 0 && reply->message) {
                    parse_audit_message(std::string(reply->message));
                }
        } else if (ret < 0) {
            logger_.warn("auditd_analyzer: audit_get_reply error, attempting reconnect");
            if (audit_fd_ >= 0) {
                audit_close(audit_fd_);
                audit_fd_ = -1;
            }
        }
    }

    free(reply);
    logger_.info("auditd_analyzer: listener thread stopping");
}

}
