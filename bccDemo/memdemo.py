from bcc import BPF
from time import sleep

bpf_source = """
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
#include <uapi/linux/ptrace.h>

struct mem_info_t {
        u32 pid;
        u64 size;
};


BPF_HASH(memused, u32, u64, 100000);//key:pid value:memused
BPF_HASH(allocs, u64, struct mem_info_t, 1000000);//key:address value:memsize

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 memsize = size;
        u64* val = memused.lookup(&pid);
        if (val)
            memsize += *val;
        memused.update(&pid, &memsize);
        //临时结构,存储申请内存大小,key为0
        u64 address = 0;
        struct mem_info_t info = {};
        info.size = size;
        info.pid = pid;
        allocs.update(&address, &info);
        bpf_trace_printk("alloc entered, size = %u\\n", memsize);
        return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 add = 0;
        struct mem_info_t *info;
        info = allocs.lookup(&add);
        if (!info) return 0;
        if (info->pid != pid) return 0;

        allocs.update(&address, info);
        allocs.delete(&add);

        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct mem_info_t *info = allocs.lookup(&addr);
        if (!info) return 0;
        u64 *memsize = memused.lookup(&(info->pid));
        if (!memsize) return 0;
        *memsize = *memsize - info->size;
        memused.update(&(info->pid), memsize);
        allocs.delete(&addr);
        
        return 0;
}

//size可能是第一个参数
int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int malloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int free_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

"""
bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="malloc", fn_name="malloc_enter")
bpf.attach_uretprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym = "malloc", fn_name="malloc_exit")
bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="free", fn_name="free_enter")
#bpf.attach_uretprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym = "free", fn_name="free_exit", pid=int(pid))
pid = input("input pid: ")
while True:
    alloc_info = {}
    #allocs = bpf["allocs"]
    memused = bpf["memused"]
    for key, val in memused.items():
        if str(key.value) == str(pid):
                print("pid " + str(key.value) + " use memory " + str(val.value) + "byte")
    sleep(1)
