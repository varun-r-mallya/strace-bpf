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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 20);
} output_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int str(struct pt_regs *regs)
{
    __u32 key = 0;
    __u32 *input_value;
    input_value = bpf_map_lookup_elem(&input_map, &key);
    if (input_value)
    {
        bpf_printk("this does not work\n");
        bpf_map_update_elem(&output_map, &key, input_value, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
