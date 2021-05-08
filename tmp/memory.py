import psutil
import time

def getQuery(pid, val):
    return 'item=ngx_mem,pid=%d value=%f MB' %(pid, val)

def getMemSize(pid):
    process = psutil.Process(pid)
    memInfo = process.memory_info()
    return memInfo.rss / 1024 / 1024


def getMem(processName):
    for i in psutil.process_iter():
        if i.name() == processName:
            mem = getMemSize(i.pid)
            print(getQuery(i.pid, mem))
    return mem

while True:
    getMem("nginx")
    print("loop")
    time.sleep(1)