import requests
import time

def getQuery(index, duration):
    return 'req%d value=%f ms' %(index, duration * 1000)

index = 0
while True:
    now = time.time()
    r = requests.get('http://192.168.1.238/test2.mp4')
    print(len(r.content))
    end = time.time()
    index += 1
    print(getQuery(index, end - now))
    time.sleep(5)