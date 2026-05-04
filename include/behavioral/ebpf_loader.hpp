#pragma once

#include <string>
#include <atomic>
#include <cstdint>
#include <functional>

#include "behavioral/ptrace_tracer.hpp"

namespace stingbee::behavioral {

class EbpfLoader {
public:
    EbpfLoader(IEventBus& bus, ILogger& logger);
    ~EbpfLoader();

    bool load_object(const std::string& bpf_obj_path);

    bool start_polling();

    void stop();

    static bool kernel_version_at_least(int major, int minor);

private:
    IEventBus& bus_;
    ILogger& logger_;
    std::atomic<bool> running_{false};
    int poll_timeout_ms_ = 200;

    struct Impl;
    Impl* impl_ = nullptr;
};

}
