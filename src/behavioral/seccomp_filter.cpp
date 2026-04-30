#include "behavioral/seccomp_filter.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <poll.h>
#include <string_view>
#include <thread>
#include <utility>

#include <sys/prctl.h>
#include <unistd.h>

#if defined(STINGBEE_HAVE_SECCOMP)
extern "C" {
using scmp_filter_ctx = void*;

struct seccomp_data {
    std::int32_t nr;
    std::uint32_t arch;
    std::uint64_t instruction_pointer;
    std::uint64_t args[6];
};

struct seccomp_notif {
    std::uint64_t id;
    std::uint32_t pid;
    std::uint32_t flags;
    seccomp_data data;
};

struct seccomp_notif_resp {
    std::uint64_t id;
    std::int64_t val;
    std::int32_t error;
    std::uint32_t flags;
};

scmp_filter_ctx seccomp_init(std::uint32_t def_action);
int seccomp_rule_add(scmp_filter_ctx ctx, std::uint32_t action, int syscall, unsigned int arg_cnt, ...);
int seccomp_load(scmp_filter_ctx ctx);
void seccomp_release(scmp_filter_ctx ctx);
int seccomp_attr_set(scmp_filter_ctx ctx, std::uint32_t attr, std::uint32_t value);
int seccomp_notify_fd(scmp_filter_ctx ctx);
int seccomp_notify_alloc(struct seccomp_notif** req, struct seccomp_notif_resp** resp);
void seccomp_notify_free(struct seccomp_notif* req, struct seccomp_notif_resp* resp);
int seccomp_notify_receive(int fd, struct seccomp_notif* req);
int seccomp_notify_respond(int fd, struct seccomp_notif_resp* resp);
int seccomp_syscall_resolve_name(const char* name);
}

#ifndef SCMP_ACT_ALLOW
#define SCMP_ACT_ALLOW 0x7fff0000U
#endif
#ifndef SCMP_ACT_LOG
#define SCMP_ACT_LOG 0x7ffc0000U
#endif
#ifndef SCMP_ACT_NOTIFY
#define SCMP_ACT_NOTIFY 0x7fc00000U
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1U
#endif
#ifndef SCMP_FLTATR_CTL_NNP
#define SCMP_FLTATR_CTL_NNP 3U
#endif
#ifndef SCMP_FLTATR_CTL_TSYNC
#define SCMP_FLTATR_CTL_TSYNC 4U
#endif
#endif

namespace stingbee::behavioral {
namespace {

constexpr std::uint32_t kAllowAction = 0x7fff0000U;
constexpr std::uint32_t kLogAction = 0x7ffc0000U;
constexpr std::uint32_t kNotifyAction = 0x7fc00000U;
constexpr std::uint32_t kNoNewPrivsAttr = 3U;
constexpr std::uint32_t kTsyncAttr = 4U;

std::string trim(std::string_view text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }

    const auto last = text.find_last_not_of(" \t\r\n");
    return std::string(text.substr(first, last - first + 1));
}

std::string lower_copy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return text;
}

bool parse_action(const std::string& value, SeccompMode* mode) {
    if (mode == nullptr) {
        return false;
    }

    const std::string lowered = lower_copy(trim(value));
    if (lowered == "notify" || lowered == "seccomp_act_notify") {
        *mode = SeccompMode::Notify;
        return true;
    }
    if (lowered == "log" || lowered == "seccomp_act_log") {
        *mode = SeccompMode::Log;
        return true;
    }
    return false;
}

bool parse_decision(const std::string& value, SeccompDecision* decision) {
    if (decision == nullptr) {
        return false;
    }

    const std::string lowered = lower_copy(trim(value));
    if (lowered == "continue") {
        *decision = SeccompDecision::Continue;
        return true;
    }
    if (lowered == "block") {
        *decision = SeccompDecision::Block;
        return true;
    }
    return false;
}

bool parse_syscall_token(const std::string& token, int* syscall_number) {
    if (syscall_number == nullptr) {
        return false;
    }

    const std::string trimmed = trim(token);
    if (trimmed.empty()) {
        return false;
    }

    char* end = nullptr;
    const long numeric = std::strtol(trimmed.c_str(), &end, 10);
    if (end != nullptr && *end == '\0') {
        *syscall_number = static_cast<int>(numeric);
        return true;
    }

#if defined(STINGBEE_HAVE_SECCOMP)
    const int resolved = seccomp_syscall_resolve_name(trimmed.c_str());
    if (resolved >= 0) {
        *syscall_number = resolved;
        return true;
    }
#endif

    return false;
}

std::string format_intercept_message(int syscall_number, pid_t pid, const char* decision) {
    char buffer[256] = {};
    (void)std::snprintf(buffer,
                        sizeof(buffer),
                        "seccomp_filter: intercepted syscall=%d pid=%d decision=%s",
                        syscall_number,
                        static_cast<int>(pid),
                        decision);
    return std::string(buffer);
}

}  // namespace

SeccompFilter::SeccompFilter(IEventBus& bus, ILogger& logger, std::string thresholds_path)
    : bus_(bus), logger_(logger), thresholds_path_(std::move(thresholds_path)) {}

SeccompFilter::~SeccompFilter() {
    stop();
}

bool SeccompFilter::running() const {
    return running_.load();
}

SeccompPolicy SeccompFilter::policy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_;
}

bool SeccompFilter::load_policy_from_disk(SeccompPolicy* out_policy, std::string* error_message) {
    if (out_policy == nullptr) {
        if (error_message != nullptr) {
            *error_message = "null output policy";
        }
        return false;
    }

    SeccompPolicy parsed_policy{};
    std::ifstream input(thresholds_path_);
    if (!input.is_open()) {
        if (error_message != nullptr) {
            *error_message = "thresholds file not found";
        }
        *out_policy = parsed_policy;
        return true;
    }

    std::string line;
    bool in_syscall_list = false;
    while (std::getline(input, line)) {
        const std::size_t comment_pos = line.find('#');
        const std::string content = trim(line.substr(0, comment_pos));
        if (content.empty()) {
            continue;
        }

        const std::string lowered = lower_copy(content);
        if (lowered == "seccomp:" || lowered == "behavioral:") {
            in_syscall_list = false;
            continue;
        }

        if (lowered == "suspect_syscalls:" || lowered == "syscalls:" || lowered == "seccomp_syscalls:") {
            in_syscall_list = true;
            continue;
        }

        const std::size_t colon_pos = content.find(':');
        if (colon_pos != std::string::npos) {
            const std::string key = lower_copy(trim(content.substr(0, colon_pos)));
            const std::string value = trim(content.substr(colon_pos + 1));

            if (key == "action") {
                (void)parse_action(value, &parsed_policy.mode);
                in_syscall_list = false;
                continue;
            }

            if (key == "decision" || key == "notify_decision") {
                (void)parse_decision(value, &parsed_policy.decision);
                in_syscall_list = false;
                continue;
            }
        }

        if (in_syscall_list && content.rfind("-", 0) == 0) {
            const std::string token = trim(content.substr(1));
            if (!token.empty()) {
                parsed_policy.suspect_syscalls.push_back(token);
            }
            continue;
        }

        in_syscall_list = false;
    }

    *out_policy = std::move(parsed_policy);
    return true;
}

bool SeccompFilter::install_rule_batch(const SeccompPolicy& policy, const std::vector<int>& syscall_numbers) {
#if !defined(STINGBEE_HAVE_SECCOMP)
    (void)policy;
    (void)syscall_numbers;
    logger_.warn("seccomp_filter: libseccomp support not available at build time");
    return false;
#else
    if (syscall_numbers.empty()) {
        return true;
    }

    scmp_filter_ctx ctx = seccomp_init(kAllowAction);
    if (ctx == nullptr) {
        logger_.error("seccomp_filter: seccomp_init failed");
        return false;
    }

    if (seccomp_attr_set(ctx, kNoNewPrivsAttr, 1U) != 0) {
        logger_.warn("seccomp_filter: unable to set no_new_privs attribute");
    }

    if (seccomp_attr_set(ctx, kTsyncAttr, 1U) != 0) {
        logger_.warn("seccomp_filter: unable to enable TSYNC on seccomp filter");
    }

    const std::uint32_t action = (policy.mode == SeccompMode::Notify) ? kNotifyAction : kLogAction;
    for (const int syscall_number : syscall_numbers) {
        if (seccomp_rule_add(ctx, action, syscall_number, 0U) != 0) {
            char buffer[160] = {}
            ;
            (void)std::snprintf(buffer, sizeof(buffer), "seccomp_filter: failed to add rule for syscall %d", syscall_number);
            logger_.warn(buffer);
        }
    }

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        logger_.warn("seccomp_filter: prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    if (seccomp_load(ctx) != 0) {
        logger_.error("seccomp_filter: seccomp_load failed");
        seccomp_release(ctx);
        return false;
    }

    LoadedFilter loaded_filter{};
    loaded_filter.ctx = ctx;
    if (policy.mode == SeccompMode::Notify) {
        loaded_filter.notify_fd = seccomp_notify_fd(ctx);
        if (loaded_filter.notify_fd < 0) {
            logger_.error("seccomp_filter: seccomp_notify_fd failed");
            seccomp_release(ctx);
            return false;
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (policy.mode == SeccompMode::Notify) {
            loaded_filters_.push_back(loaded_filter);
        } else {
            seccomp_release(ctx);
        }
    }

    return true;
#endif
}

bool SeccompFilter::install_rules(const SeccompPolicy& policy, bool force_reinstall) {
    std::vector<int> resolved_syscalls;
    resolved_syscalls.reserve(policy.suspect_syscalls.size());

    for (const std::string& token : policy.suspect_syscalls) {
        int syscall_number = -1;
        if (!parse_syscall_token(token, &syscall_number)) {
            char buffer[192] = {};
            (void)std::snprintf(buffer, sizeof(buffer), "seccomp_filter: unable to resolve syscall token '%s'", token.c_str());
            logger_.warn(buffer);
            continue;
        }
        resolved_syscalls.push_back(syscall_number);
    }

    if (resolved_syscalls.empty()) {
        return true;
    }

    std::vector<int> syscalls_to_install;
    syscalls_to_install.reserve(resolved_syscalls.size());

    std::unordered_set<int>* installed_set = (policy.mode == SeccompMode::Notify) ? &notify_syscalls_ : &log_syscalls_;
    for (const int syscall_number : resolved_syscalls) {
        if (force_reinstall || installed_set->find(syscall_number) == installed_set->end()) {
            syscalls_to_install.push_back(syscall_number);
            installed_set->insert(syscall_number);
        }
    }

    return install_rule_batch(policy, syscalls_to_install);
}

bool SeccompFilter::start() {
    if (running_.exchange(true)) {
        return true;
    }

    stop_requested_.store(false);

    SeccompPolicy parsed_policy{};
    std::string error_message;
    if (!load_policy_from_disk(&parsed_policy, &error_message)) {
        logger_.error("seccomp_filter: unable to load thresholds policy");
        running_.store(false);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        policy_ = parsed_policy;
    }

    if (!parsed_policy.suspect_syscalls.empty()) {
        if (!install_rules(parsed_policy, false)) {
            running_.store(false);
            return false;
        }
    } else {
        logger_.info("seccomp_filter: no suspect syscalls configured; running idle");
    }

    if (parsed_policy.mode == SeccompMode::Notify) {
        start_notify_thread_if_needed();
    }

    return true;
}

bool SeccompFilter::reload() {
    SeccompPolicy parsed_policy{};
    std::string error_message;
    if (!load_policy_from_disk(&parsed_policy, &error_message)) {
        logger_.error("seccomp_filter: failed to reload thresholds policy");
        return false;
    }

    SeccompPolicy previous_policy{};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        previous_policy = policy_;
        policy_ = parsed_policy;
    }

    if (!running_.load()) {
        return true;
    }

    const bool force_reinstall = previous_policy.mode != parsed_policy.mode;
    if (!parsed_policy.suspect_syscalls.empty()) {
        if (!install_rules(parsed_policy, force_reinstall)) {
            return false;
        }
    }

    if (parsed_policy.mode == SeccompMode::Notify) {
        start_notify_thread_if_needed();
    }

    return true;
}

void SeccompFilter::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    stop_requested_.store(true);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (LoadedFilter& filter : loaded_filters_) {
            if (filter.notify_fd >= 0) {
                (void)::close(filter.notify_fd);
                filter.notify_fd = -1;
            }
#if defined(STINGBEE_HAVE_SECCOMP)
            if (filter.ctx != nullptr) {
                seccomp_release(static_cast<scmp_filter_ctx>(filter.ctx));
                filter.ctx = nullptr;
            }
#endif
        }
        loaded_filters_.clear();
        notify_syscalls_.clear();
        log_syscalls_.clear();
    }

    if (notify_thread_ != nullptr && notify_thread_->joinable()) {
        notify_thread_->join();
    }
    notify_thread_.reset();
}

void SeccompFilter::start_notify_thread_if_needed() {
#if !defined(STINGBEE_HAVE_SECCOMP)
    return;
#else
    std::vector<int> notify_fds;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const LoadedFilter& filter : loaded_filters_) {
            if (filter.notify_fd >= 0) {
                notify_fds.push_back(filter.notify_fd);
            }
        }
    }

    if (notify_fds.empty()) {
        return;
    }

    if (notify_thread_ != nullptr && notify_thread_->joinable()) {
        return;
    }

    notify_thread_ = std::make_unique<std::thread>([this]() {
        notify_loop();
    });
#endif
}

void SeccompFilter::notify_loop() {
#if !defined(STINGBEE_HAVE_SECCOMP)
    return;
#else
    while (!stop_requested_.load()) {
        std::vector<pollfd> poll_fds;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            poll_fds.reserve(loaded_filters_.size());
            for (const LoadedFilter& filter : loaded_filters_) {
                if (filter.notify_fd >= 0) {
                    pollfd entry{};
                    entry.fd = filter.notify_fd;
                    entry.events = POLLIN;
                    poll_fds.push_back(entry);
                }
            }
        }

        if (poll_fds.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        const int rc = ::poll(poll_fds.data(), static_cast<nfds_t>(poll_fds.size()), 250);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger_.warn("seccomp_filter: poll on notify fds failed");
            continue;
        }

        for (const pollfd& entry : poll_fds) {
            if ((entry.revents & POLLIN) != 0) {
                handle_notify_fd(entry.fd);
            }
        }
    }
#endif
}

void SeccompFilter::handle_notify_fd(int notify_fd) {
#if !defined(STINGBEE_HAVE_SECCOMP)
    (void)notify_fd;
    return;
#else
    seccomp_notif* request = nullptr;
    seccomp_notif_resp* response = nullptr;
    if (seccomp_notify_alloc(&request, &response) != 0 || request == nullptr || response == nullptr) {
        logger_.error("seccomp_filter: seccomp_notify_alloc failed");
        return;
    }

    const int receive_rc = seccomp_notify_receive(notify_fd, request);
    if (receive_rc != 0) {
        seccomp_notify_free(request, response);
        if (!stop_requested_.load()) {
            logger_.warn("seccomp_filter: seccomp_notify_receive failed");
        }
        return;
    }

    const SeccompPolicy current_policy = policy();
    const bool continue_syscall = current_policy.decision == SeccompDecision::Continue;

    SyscallEvent event{};
    event.pid = static_cast<pid_t>(request->pid);
    event.tid = static_cast<pid_t>(request->pid);
    event.syscall_nr = static_cast<std::int64_t>(request->data.nr);
    for (std::size_t index = 0; index < event.args.size(); ++index) {
        event.args[index] = request->data.args[index];
    }
    event.retval = continue_syscall ? 0 : -EPERM;

    bus_.publish(event);
    logger_.info(format_intercept_message(request->data.nr, static_cast<pid_t>(request->pid), continue_syscall ? "continue" : "block").c_str());

    response->id = request->id;
    response->val = 0;
    response->error = 0;
    response->flags = 0;
    if (continue_syscall) {
        response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    } else {
        response->error = -EPERM;
    }

    if (seccomp_notify_respond(notify_fd, response) != 0) {
        logger_.warn("seccomp_filter: seccomp_notify_respond failed");
    }

    seccomp_notify_free(request, response);
#endif
}

}