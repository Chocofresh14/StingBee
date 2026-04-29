#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct syscall_event_t {
    __u32 pid;
    __u32 tid;
    char comm[16];
    __u32 syscall_nr;
    __u64 args[6];
    __s64 retval;
    __u64 ts_enter;
    __u64 ts_exit;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct syscall_event_t);
    __uint(max_entries, 10240);
} syscall_data SEC(".maps");

static __always_inline __u64 gen_pid_tgid(__u32 pid, __u32 tid) {
    return ((__u64)pid << 32) | tid;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = pid;
    event->tid = tid;
    event->syscall_nr = ctx->id;
    event->args[0] = ctx->args[0];
    event->args[1] = ctx->args[1];
    event->args[2] = ctx->args[2];
    event->args[3] = ctx->args[3];
    event->args[4] = ctx->args[4];
    event->args[5] = ctx->args[5];
    event->retval = 0;
    event->ts_enter = bpf_ktime_get_ns();
    event->ts_exit = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    struct syscall_event_t temp_event = {};
    temp_event.pid = pid;
    temp_event.tid = tid;
    temp_event.syscall_nr = ctx->id;
    temp_event.ts_enter = event->ts_enter;
    bpf_map_update_elem(&syscall_data, &pid_tgid, &temp_event, 0);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct syscall_event_t *exit_event = bpf_ringbuf_reserve(&events, sizeof(*exit_event), 0);
    if (!exit_event) {
        bpf_map_delete_elem(&syscall_data, &pid_tgid);
        return 0;
    }

    exit_event->pid = pid;
    exit_event->tid = tid;
    exit_event->syscall_nr = ctx->id;
    exit_event->retval = ctx->ret;
    exit_event->ts_exit = bpf_ktime_get_ns();
    exit_event->ts_enter = 0;
    exit_event->args[0] = 0;
    exit_event->args[1] = 0;
    exit_event->args[2] = 0;
    exit_event->args[3] = 0;
    exit_event->args[4] = 0;
    exit_event->args[5] = 0;

    bpf_get_current_comm(&exit_event->comm, sizeof(exit_event->comm));

    bpf_ringbuf_submit(exit_event, 0);

    bpf_map_delete_elem(&syscall_data, &pid_tgid);

    return 0;
}

char _license[] SEC("license") = "GPL";
