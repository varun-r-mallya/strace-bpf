#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} input_map SEC(".maps");

// map to throw out the syscall numbers
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1000);
} syscall_map SEC(".maps");

// trigger on every syscall
SEC("tracepoint/raw_syscalls/sys_enter")
int syscall_tracker(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    u32 *input_value;
    // PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    input_value = bpf_map_lookup_elem(&input_map, &key);
    // find out the type of syscall performed

    if (input_value && *input_value == pid)
    {
        u64 syscall_nr = ctx->id;
        bpf_printk("Syscall: %d\n", syscall_nr);
        bpf_map_update_elem(&syscall_map, &pid, &syscall_nr, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
