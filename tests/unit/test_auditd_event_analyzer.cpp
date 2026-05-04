#include "behavioral/auditd_event_analyzer.hpp"

#include <chrono>
#include <thread>

using stingbee::behavioral::AuditdEventAnalyzer;
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
    AuditdEventAnalyzer analyzer(bus, logger);

    const bool started = analyzer.start();
    if (!started) {
        logger.warn("analyzer.start() returned false — auditd may not be running");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    analyzer.stop();

    return 0;
}
