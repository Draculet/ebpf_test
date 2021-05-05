import bcc
import sys
import socket
import time
import json
import struct

#解析http头部所花的时间

bpf_code = '''
    BPF_HASH(req_begin, u32, u64);
    BPF_HASH(req_duration, u32, u64);
    
    int hook_ngx_http_create_request(struct pt_regs *ctx){
        u64 begintime = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        req_begin.update(&pid, &begintime);
        return 0;
    }

    int hook_ngx_http_process_request(struct pt_regs *ctx){
        u64 endtime = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 *begintime = req_begin.lookup(&pid);
        u64 duration = 0;
        if (begintime) 
            duration = endtime - *begintime;
        req_duration.update(&pid, &duration);
        return 0;   
    }
'''

def getQuery(pid, count):
    return 'pid=%d value=%f ms' %(pid, count / 1000000)

bpf = bcc.BPF(text=bpf_code)
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_process_request",
                fn_name="hook_ngx_http_process_request")
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_create_request",
                fn_name="hook_ngx_http_create_request")

while True:
    datam = bpf["req_duration"]
    for key,val in datam.items():
        #data = json.dumps(getData(key.value, val.value))
        data = getQuery(key.value, val.value)
        print(data)
        datam.clear()
    print('loop')
    time.sleep(1)

s.close()