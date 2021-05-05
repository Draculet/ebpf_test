from bcc import BPF
from time import sleep
import ctypes

bpf_source = """
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
#include <uapi/linux/ptrace.h>

struct stack_t {
    int pid;
    int stacksize;
    u8 buf[200];
};


BPF_HASH(stack, u32, struct stack_t);
//BPF_HASH(sizes, u64);
//BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);
//BPF_STACK_TRACE(stack_traces, 10240);

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        u32 pid = bpf_get_current_pid_tgid();
        //u64 size64 = size;
        //sizes.update(&pid, &size64);
        struct stack_t data = {};
        //data = stack.lookup(&pid);
        data.stacksize = bpf_get_stack(ctx, data.buf, 200, BPF_F_USER_STACK);
        data.pid = pid;
        stack.update(&pid, &data);
        for (int i = 0; i < 24; i++)
            bpf_trace_printk("%d\\n", data.buf[i]);
        bpf_trace_printk("bufsize: %u\\n", data.stacksize);
        bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

//size可能是第一个参数
int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

"""

pid = input("input pid: ")
bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="malloc", fn_name="malloc_enter", pid=int(pid))
#bpf.attach_uretprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym = "malloc", fn_name="malloc_exit", pid=int(pid))
#bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="free", fn_name="free_enter", pid=int(pid))
#bpf.attach_uretprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym = "free", fn_name="free_exit", pid=int(pid))

while True:
    alloc_info = {}
    #allocs = bpf["allocs"]
    #stack_traces = bpf["stack_traces"]
    #for address, info in allocs.items():
    #    print(str(address) + "|" + str(info))
    stack = bpf["stack"]
    for key,val in stack.items():
        print(str(key.value) + ":" + str(val.buf) + ":" + str(val.stacksize))
    sleep(1)
