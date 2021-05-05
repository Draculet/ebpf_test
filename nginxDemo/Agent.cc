#include <unistd.h>
#include <cstdio>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <event2/bufferevent.h>
#include <event2/listener.h>

using namespace std;
//Agents->BackendServer->infudb
//                     ->grafana

class Agent{
    public:
    void start(string type){
        if (type == "nginx_req"){
            int pid = 0;
            if ((pid = fork()) == -1){
                perror("fork");
                return;
            }
            if (pid == 0){
                string path = "/usr/bin/python";
                vector<string> args;
                args.push_back("python");
                args.push_back("demo.py");
                args.push_back("d31");
                args.push_back("d2313");
                const char *argv[args.size() + 1];
                for (int i = 0; i < args.size(); i++){
                    argv[i] = args[i].c_str();
                    printf("test: %s\n", argv[i]);
                }
                argv[args.size()] = nullptr;
                execv(path.c_str(), (char *const*)argv);
                perror("exec");
                return;
            } else {
                pids.push_back(pid);
            }
        }
    }
    
    void wait(){
        for (auto pid: pids){
            waitpid(pid, nullptr, 0);
            printf("wait pid: %d\n", pid);
        }
    }

    void ThreadFunc(){
        
    }
    
    evconnlistener *listener;
    vector<string> monitorTarget;
    vector<int> pids;
};

int main(void){
    Agent a;
    a.start("nginx_req");
    a.wait();
}

/*
config:
    时间间隔
    机器标识 外网ip+hostname(后端确定)
    measurement 机器标识
    tags   指标+pid
    fields  值
    agent进程端口
    管理服务器ip端口
*/

/*
    nginx各进程请求分布
    tag: item:nginx_req_count + pid:xxxx
    value: xxx
*/
/*
    nginx各进程的长连接数
    tag: item:nginx_persistconn_count + pid:xxxx
    value: xxx
*/
/*
    nginx各进程的平均rtt
    tag: item: nginx_worker_rtt + pid:xxxx
    value: xxx
*/
/*
    qps
    tag: item: nginx_qps + pid:xxxxx
*/