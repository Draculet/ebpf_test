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
    #include <linux/tcp.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <bcc/proto.h>

    //BPF_HASH(reqs, u32, u64);
    struct tcp_addr_t {
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
    };
    
    BPF_HASH(rttm, struct tcp_addr_t, u32);

    int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk){
        struct tcp_sock *ts = tcp_sk(sk);
        u32 srtt = ts->srtt_us >> 3;
        struct inet_sock *inet = inet_sk(sk);
        u32 *val;
        u16 sport = 0;
        u16 dport = 0;
        u32 saddr = 0;
        u32 daddr = 0;
        /*
        bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
        bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
        bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
        */
    
        sport = inet->inet_sport;
        dport = inet->inet_dport;
        saddr = inet->inet_saddr;
        daddr = inet->inet_daddr;
    


        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        rttm.update(&entry, &srtt);
        return 0;
    }
'''

bpf = bcc.BPF(text=bpf_code)
#bpf.attach_kprobe(event="tcp_rcv_established", fn_name="rcv_user")

while True:
    data = bpf["rttm"]
    for key,val in data.items():
        result = struct.unpack('IIHH', key)
        #print(result)
        
        #sip = socket.inet_ntoa(result[0])
        #dip = socket.inet_ntoa(result[1])
        sip = socket.inet_ntoa(struct.pack('I', result[0]))
        dip = socket.inet_ntoa(struct.pack('I', result[1]))
        sport = socket.ntohs(result[2])
        dport = socket.ntohs(result[3])
        if sport == 80:
            #print("rtt: " + str(val.value / 1000) + "ms")
            print(sip + " " + str(sport) + " " + dip + " " + str(dport) + " rtt: " + str(val.value / 1000) + "ms")
        #dip = socket.inet_ntoa(struct.pack('I', key))
        #print("key: " + str(sip) + " " + str(dip) + " value: " + val.value)
    print('sleep')
    time.sleep(1)

s.close()