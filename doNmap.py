#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import threading
from time import sleep
from nmap import nmap
from lib.consle_width import getTerminalSize

class doNmap:

    def __init__(self, all_ip, arguments, thread_count):
        self.arguments = arguments
        self.nm = nmap.PortScanner()
        #self.thread_count = len(all_ip)/3 if len(all_ip) % 3 == 0 else len(all_ip)/3 + 1    #每个线程扫描3个IP
        #self.thread_count = 10 if self.thread_count > 10 else self.thread_count
        self.thread_count = 30 if thread_count > 30 else thread_count 
        self.all_ip = all_ip
        self.lock = threading.Lock()
        #self.hosts = [self.all_ip[index: index+3] for index in range(0, len(all_ip), 3)]  #将ip每3个进行等分
        #print(self.thread_count, len(self.hosts))
        self.thread = []
        self.console_width = getTerminalSize()[0]
        self.console_width -= 2    # Cal width when starts up
        print('\033[1;33;40m[*]Count of All Thread: ' + str(self.thread_count) + '\033[0m')
        for thread_name in range(self.thread_count):       #根据线程数创建线程
            self.thread.append(threading.Thread(target=self._do_Scan, name=str(thread_name)))
        #print(self.thread)

    def _do_Scan(self):
        #try:
        #hosts = ' '.join(hosts)
        self.lock.acquire() #请求锁来对all_ip进行操作
        while len(self.all_ip) > 0:
            host = self.all_ip.pop()    #存在ip没有进行扫描，则获取ip进行扫描
            self.lock.release() #获取ip后释放锁
            self.result = self.nm.scan(hosts = host, arguments = self.arguments)
            self._get_Result()  #打印结果
            self.lock.acquire() #结束扫描后再次进行判断all_ip中是否还有ip未扫描
        self.lock.release()
                
    def _get_Result(self):
        self.result = self.result['scan']
        for target in self.result:
            print('\033[1;32;40mHost: \033[0m\033[1;34;40m' + target + '\033[0m\033[1;32;40m    Name: \033[0m\033[1;34;40m'),
            #print(self.result)
            #print(self.result[target])
            target = self.result[target]
            print(str('None' if not target['hostnames'][0]['name'] else target['hostnames'][0]['name']) + '\033[0m\033[1;32;40m')
            print("%-8s\t|%-8s\t|%-8s\t|%-8s\t|%-8s" % ('Port', 'Status', 'Name', 'Vsersion', 'Extrainfo'))
            tcp = target['tcp']
            for port in tcp:
                print("%-8s\t|%-8s\t|%-8s\t|%-8s\t|%-8s" % (str(port), tcp[port]['state'], tcp[port]['name'], tcp[port]['version'], tcp[port]['extrainfo']))
            #print(target['hostnames'][0]['name'] + ' is ' + target['status'][0]['state'] + '.')
            print('-' * (self.console_width))
            print('\033[0m')

    def _detection_Thread_Status(self): #检测每个线程的运行状态
        All_Is_Over = self.thread_count
        count = 0
        self.lock.acquire()
        while All_Is_Over > 0:
            self.lock.release()
            for index in range(self.thread_count):
                if self.thread[index].isAlive():    #判断每个线程是否运行中
                    count = count % 3 + 1
                    self.lock.acquire()
                    out = '\033[1;33;40m\r[*]Thread ' + str(index) + ' is Running' + '.' * (count) + ' '*(self.console_width-20-count) + '\033[0m\r'
                    sys.stdout.write(out)
                    sys.stdout.flush()
                    self.lock.release()
                    sleep(1)
                else:
                    self.lock.acquire() #获取ip后释放锁
                    All_Is_Over -= 1    #每结束一个线程, All_Is_Over数量减1
                    self.lock.release()
            self.lock.acquire()
        self.lock.release()

    def run(self):
        #print('Total Thread Count: ', self.thread_count)
        for i in range(self.thread_count):
            #self.thread[i].setDaemon(True)
            self.thread[i].start()
            sleep(0.2)    #等待线程启动正常
            if not self.thread[i].isAlive(): #线程启动失败则退出
                print('[-]\033[1;33;31mThread number ' + str(i) + ' Start Fail!\nExit the program\033[0m')
                exit(-1)
            #print('\033[1;33;40m[+]Thread number ' + str(i) + ' Start\033[0m')
        
        detection = threading.Thread(target=self._detection_Thread_Status)
        detection.setDaemon(True)
        detection.start()

        for i in range(self.thread_count):
            self.thread[i].join()

