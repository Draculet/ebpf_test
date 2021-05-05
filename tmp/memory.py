import psutil
import time

def getQuery(pid, val):
    return 'item=ngx_mem,pid=%d value=%f MB' %(pid, val)

def getMemSize(pid):
    # 根据进程号来获取进程的内存大小
    process = psutil.Process(pid)
    memInfo = process.memory_info()
    return memInfo.rss / 1024 / 1024


def getMem(processName):
    # 一个进程名对应的可能有多个进程
    # 进程号才是进程的唯一标识符，进程名不是
    for i in psutil.process_iter():
        #print(i.name())
        if i.name() == processName:
            mem = getMemSize(i.pid)
            print(getQuery(i.pid, mem))
    return mem

while True:
    getMem("nginx")
    print("loop")
    time.sleep(1)