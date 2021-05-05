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

    struct info{
        u32 pid;
        u32 fd;
    };
    
    BPF_HASH(sendfile_flow, struct info, u64);
    BPF_HASH(sendfile_flow_show, struct info, u64);

    int kretprobe__do_sendfile(struct pt_regs *ctx, int out_fd, int in_fd, loff_t *ppos, size_t count, loff_t max){
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 flow = ret;
        struct info inf;
        inf.pid = pid;
        inf.fd = out_fd;
        u64 *flowsize = sendfile_flow.lookup(&inf);
        if (flowsize)
            flow += *flowsize;
        sendfile_flow.update(&inf, &flow);
        sendfile_flow_show.update(&inf, &flow);
        return 0;
    }
'''

#def getQuery(measurement, sip, sport, dip, dport, rtt):
#    return '%s,item=tcp_recvflow,sip=%s,sport=%d,dip=%s,dport=%d value=%f' %(measurement, sip, sport, dip, dport, rtt)

def getSendQuery(pid, socketfd, flow):
    return 'item=tcp_sendfile_flow,pid=%d,socketfd=%d value=%f kB' %(pid, socketfd, flow)
#ip = sys.argv[1]
#port = int(sys.argv[2])
#measurement = sys.argv[3]
#interval = int(sys.argv[4])
bpf = bcc.BPF(text=bpf_code)
#bpf.attach_kprobe(event="tcp_rcv_established", fn_name="rcv_user")
#bpf.attach_kprobe(event="tcp_ack_update_rtt.isra.45", fn_name="kprobe_tcp_ack_update_rtt")

#s = socket.socket()
#s.connect((ip, port))
datam = bpf["sendfile_flow_show"]

while True: 
    for key,val in datam.items():
        result = struct.unpack('ii', key)
        data = getSendQuery(result[0], result[1], val.value / 1000)
        print(data)
    datam.clear()
    print("loop")
    #time.sleep(interval)
    time.sleep(1)

#s.close()
