import bcc
import sys
import socket
import time
import json
import struct

bpf_code = '''
    #include <uapi/linux/ptrace.h>

    BPF_HASH(reqs, u32, u64);

    int sock_rcv(struct pt_regs *ctx){
        struct sock *sk = (void *)PT_REGS_PARM1(ctx);
        struct tcp_sock *tp = tcp_sk(sk);
        unsigned int srtt = 0;
        return 0;   
    }
'''

def getQuery(measurement, pid, count):
    return '%s,item=nginx_req_count,pid=%d value=%d' %(measurement, pid, count)

ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])

bpf = bcc.BPF(text=bpf_code)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("tcp_rcv_established"), fn_name="sock_rcv")

s = socket.socket()
#直接发往traceserver,不再经过agent
print("measurement: %s" %(measurement))
print("connect %s:%d" %(ip, port))
s.connect((ip, port))

while True:
    data = bpf["reqs"]
    for key,val in data.items():
        #data = json.dumps(getData(key.value, val.value))
        data = getQuery(measurement, key.value, val.value)
        bytes = struct.pack('>I', len(data))
        s.send(bytes)
        s.send(data.encode('ascii'))
        print(data)
    print('sleep')
    time.sleep(interval)

s.close()