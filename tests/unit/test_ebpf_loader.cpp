#include "behavioral/ebpf_loader.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

using stingbee::behavioral::EbpfLoader;
using stingbee::behavioral::IEventBus;
using stingbee::behavioral::ILogger;

class TestEventBus final : public IEventBus {
public:
    void publish(const stingbee::behavioral::SyscallEvent& event) override {
        (void)event;
    }
};

class TestLogger final : public ILogger {
public:
    void info(const char* message) override { (void)message; }
    void warn(const char* message) override { (void)message; }
    void error(const char* message) override { (void)message; }
};

int main() {
    TestEventBus bus;
    TestLogger logger;
    EbpfLoader loader(bus, logger);

    const std::string obj_path = "ebpf/syscall_hook.bpf.o";
    const bool obj_exists = std::filesystem::exists(obj_path);

    const bool loaded = loader.load_object(obj_path);
    if (!loaded) {
        std::fprintf(stderr, "EbpfLoader::load_object returned false\n");
        return 1;
    }

    const bool started = loader.start_polling();
    if (started) {
        loader.stop();
    }

    if (!obj_exists) {
        std::puts("ebpf object not present; test exercised loader/stub path");
    }

    return 0;
}
