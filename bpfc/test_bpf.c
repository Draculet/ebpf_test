#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


/*
struct bpf_map_def SEC("maps") inner_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};*/

struct bpf_map_def SEC("maps") outer_map = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32), // Must be u32 because it's inner map id
    .max_entries = 128,
};

SEC("kprobe/tcp_rcv_established")
int test_func(struct pt_regs *ctx) {
    //struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    bpf_printk("hook tcp_rcv_established\n");
    return 0;
}

unsigned int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
