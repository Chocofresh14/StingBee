#include "behavioral/syscall_analyzer.hpp"

using stingbee::behavioral::SyscallAnalyzer;
using stingbee::behavioral::SyscallEvent;
using stingbee::behavioral::IEventBus;
using stingbee::behavioral::ILogger;
using stingbee::behavioral::AlertSeverity;

class TestEventBus final : public IEventBus {
public:
    void publish(const SyscallEvent& event) override {
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
    SyscallAnalyzer analyzer(bus, logger);

    analyzer.subscribe(bus);
    analyzer.load_rules_from_config("");

    SyscallEvent evt1;
    evt1.pid = 1234;
    evt1.tid = 1234;
    evt1.syscall_nr = 101;
    evt1.retval = 0;

    analyzer.on_syscall_event(evt1);

    SyscallEvent evt2;
    evt2.pid = 1235;
    evt2.tid = 1235;
    evt2.syscall_nr = 101;
    analyzer.on_syscall_event(evt2);

    const auto& metrics = analyzer.get_metrics();
    if (metrics.events_processed.load() < 2) {
        logger.error("analyzer: expected at least 2 events processed");
        return 1;
    }

    return 0;
}
