#pragma once

#include <array>
#include <atomic>
#include <cstdint>

#include <sys/types.h>

namespace stingbee::behavioral {

struct SyscallEvent {
    pid_t pid = 0;
    pid_t tid = 0;
    std::int64_t syscall_nr = -1;
    std::array<std::uint64_t, 6> args{};
    std::int64_t retval = 0;
};

class IEventBus {
public:
    virtual ~IEventBus() = default;
    virtual void publish(const SyscallEvent& event) = 0;
};

class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void info(const char* message) = 0;
    virtual void warn(const char* message) = 0;
    virtual void error(const char* message) = 0;
};

class PtraceTracer {
public:
    PtraceTracer(pid_t target_pid, IEventBus& event_bus, ILogger& logger, bool prefer_seize = true);

    bool run();
    void request_stop();

private:
    struct Impl;

    pid_t target_pid_;
    IEventBus& event_bus_;
    ILogger& logger_;
    bool prefer_seize_;
    std::atomic<bool> stop_requested_{false};
};

}  // namespace stingbee::behavioral
