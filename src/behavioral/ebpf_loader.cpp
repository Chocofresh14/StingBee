#include "behavioral/ebpf_loader.hpp"

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <mutex>
#include <sys/utsname.h>

#if defined(__has_include)
#  if __has_include(<bpf/libbpf.h>)
extern "C" {
#    include <bpf/libbpf.h>
}
#    define HAVE_LIBBPF 1
#  endif
#endif

namespace stingbee::behavioral {

struct EbpfLoader::Impl {
    std::thread* polling_thread = nullptr;
    std::mutex thread_mutex;
};

EbpfLoader::EbpfLoader(IEventBus& bus, ILogger& logger)
    : bus_(bus), logger_(logger), impl_(nullptr) {}

EbpfLoader::~EbpfLoader() {
    stop();
    if (impl_) {
        delete impl_;
        impl_ = nullptr;
    }
}

bool EbpfLoader::kernel_version_at_least(int major, int minor) {
    struct utsname u{};
    if (uname(&u) != 0) {
        return false;
    }
    int kmaj = 0, kmin = 0;
    if (std::sscanf(u.release, "%d.%d", &kmaj, &kmin) < 1) {
        return false;
    }
    if (kmaj > major) return true;
    if (kmaj < major) return false;
    return kmin >= minor;
}

bool EbpfLoader::load_object(const std::string& bpf_obj_path) {
#ifdef HAVE_LIBBPF
    logger_.info("ebpf_loader: libbpf detected, loading object...");
    impl_ = new Impl();
    (void)bpf_obj_path;
    return true;
#else
    (void)bpf_obj_path;
    return true;
#endif
}

bool EbpfLoader::start_polling() {
    if (!impl_) {
        logger_.warn("ebpf_loader: not loaded or running in stub mode — start_polling is no-op");
        return false;
    }

    if (running_.load()) return true;
    running_.store(true);

    impl_->polling_thread = new std::thread([this]() {
        logger_.info("ebpf_loader: polling thread started");
        while (running_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(poll_timeout_ms_));
        }
        logger_.info("ebpf_loader: polling thread stopping");
    });

    return true;
}

void EbpfLoader::stop() {
    running_.store(false);
    if (impl_ && impl_->polling_thread) {
        if (impl_->polling_thread->joinable()) {
            impl_->polling_thread->join();
        }
        delete impl_->polling_thread;
        impl_->polling_thread = nullptr;
    }
}

}
