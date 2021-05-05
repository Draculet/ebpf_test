import bcc
import sys

for i in range(0, len(sys.argv)):
    print(sys.argv[i])
data = open("/home/ubuntu/ebpf/nginxDemo/nginx_demo.c", 'r').read()
bpf = bcc.BPF(text=data)
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_create_request",
                fn_name="hook_ngx_http_create_req")

while True:
    data = bpf["reqs"]
    for key,val in data.items():
        print(str(key.value) + ":" + str(val.value))