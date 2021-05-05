BPF_HASH(reqs, u32, u64);

static void req_count(void){
    u32 pid;
    u64 *cnt, count = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    cnt = reqs.lookup(&pid);
    if (cnt) count = *cnt + 1;
    reqs.update(&pid, &count);
}

int hook_ngx_http_create_req(struct pt_regs *ctx){
    req_count();
    return 0;   
}