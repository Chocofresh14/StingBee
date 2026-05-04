#include "main.hpp"
#include "behavioral/syscall_analyzer.hpp"
#include "behavioral/seccomp_filter.hpp"
#include "behavioral/auditd_event_analyzer.hpp"
#include "behavioral/ebpf_loader.hpp"
#include "behavioral/ptrace_tracer.hpp"

#include <cstdio>
#include <memory>
#include <thread>

using namespace stingbee::behavioral;

namespace {
class LocalLogger : public ILogger {
public:
    void info(const char* message) override { std::printf("INFO: %s\n", message); }
    void warn(const char* message) override { std::printf("WARN: %s\n", message); }
    void error(const char* message) override { std::printf("ERROR: %s\n", message); }
};

class LocalEventBus : public IEventBus {
public:
    void publish(const SyscallEvent& event) override {
        if (listener_) listener_->on_syscall_event(event);
    }
    void set_listener(SyscallAnalyzer* l) { listener_ = l; }
private:
    SyscallAnalyzer* listener_ = nullptr;
};
}

void run_behavioral_components() {
    LocalLogger logger;
    LocalEventBus bus;

    SyscallAnalyzer analyzer(bus, logger);
    bus.set_listener(&analyzer);
    analyzer.load_rules_from_config("config/thresholds.yaml");

    SyscallEvent example_event{};
    example_event.pid = 1001;
    example_event.tid = 1001;
    example_event.syscall_nr = 1;
    analyzer.on_syscall_event(example_event);

    EbpfLoader ebpf(bus, logger);
    ebpf.kernel_version_at_least(3, 10);
    ebpf.load_object("ebpf/net_monitor.bpf.o");
    ebpf.start_polling();

    SeccompFilter seccomp(bus, logger);
    seccomp.start();

    AuditdEventAnalyzer audit(bus, logger);
    audit.start();
    audit.stop();

    ebpf.stop();
    seccomp.stop();
}
