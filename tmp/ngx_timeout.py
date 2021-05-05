import bcc
import sys
import socket
import time
import json
import struct

bpf_code = '''
    #ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
    #endif
    #ifndef KBUILD_MODNAME
    #define KBUILD_MODNAME "bcc"
    #endif
    #include <uapi/linux/ptrace.h>

    BPF_HASH(timeout_count, u32, u32);
    struct ngx_log_t {
    };
    int hook_ngx_log_error(struct pt_regs *ctx, u64 level, struct ngx_log_t *log, int err){
        //日志级别不够
        //if (err == 110){
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //u32 c = 1;
        //u32 *count = timeout_count.lookup(&pid);
        //if (count) c = *count + 1;
        timeout_count.update(&pid, &err);
        //}
        return 0;
    }
'''

def getQuery(pid, count):
    return 'pid=%d value=%d' %(pid, count)

bpf = bcc.BPF(text=bpf_code)
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_log_error_core",
                fn_name="hook_ngx_log_error")

while True:
    datam = bpf["timeout_count"]
    for key,val in datam.items():
        #data = json.dumps(getData(key.value, val.value))
        data = getQuery(key.value, val.value)
        print(data)
    print('loop')
    time.sleep(1)

s.close()