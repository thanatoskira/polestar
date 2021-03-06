#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import re
import sys
import threading
import requests
from time import sleep
from nmap import nmap
from prettytable import PrettyTable
from lib.consle_width import getTerminalSize

class doNmap:

    def __init__(self, output, all_ip, arguments, thread_count):
        self.arguments = arguments
        self.nm = nmap.PortScanner()
        self.thread_count = 30 if thread_count > 30 else thread_count 
        self.all_ip = all_ip
        self.lock = threading.Lock()
        self.thread = []
        self.r = re.compile("^(192\.168|169|172\.[0-3][0-9]|127|10).*") #正则匹配保留地址
        self.console_width = getTerminalSize()[0]
        self.console_width -= 2    # Cal width when starts up
        self.output = open('nmap_' + output + '.txt', 'w')
        print('\033[1;33;40m[*]Count of All Thread: ' + str(self.thread_count) + '\033[0m')
        for thread_name in range(self.thread_count):       #根据线程数创建线程
            self.thread.append(threading.Thread(target=self._do_Scan, name=str(thread_name)))

    def _do_Scan(self):
        self.lock.acquire() #请求锁来对all_ip进行操作
        while len(self.all_ip) > 0:
            host = self.all_ip.pop()    #存在ip没有进行扫描，则获取ip进行扫描
            if self.r.findall(host):
                continue
            self.lock.release() #获取ip后释放锁
            self.result = self.nm.scan(hosts = host, arguments = self.arguments)
            try: ####待修复。。。
                self._get_Result()  #打印结果
            except Exception as e:
                print(e)
                exit(-1)
            self.lock.acquire() #结束扫描后再次进行判断all_ip中是否还有ip未扫描
        self.lock.release()

    def _get_Title(self, host, port):
        r = re.compile("'(.*?)'")
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'}
        proc = 'https://' if port == '443' or port == '8443' else 'http://'
        url = proc + host + ":" + str(port)
        try:
            response = requests.get(url, headers=headers, timeout=3)
            title = re.search('<title>(.*?)</title>',response.content.decode('utf-8')).group(1)
            return (response.reason, title)
        except Exception as e:
            if str(e).find("has no attribute 'group'") != -1:
                return (response.status_code, "None")
            elif str(e).find("Read timed out") != -1:
                return ('TimeOut', 'None')
            elif r.findall(str(e)) != []:
                return (r.findall(str(e))[0], 'None')
            else:
                return (str(e), 'None')


                
    def _get_Result(self):
        #使用prettytable格式化输出
        ptable = PrettyTable(['Port', 'Status', 'Name', 'Reason', 'Title'])
        ptable.align = 'l'  #靠左输出
        #ptable.align['Port'] = '1'
        ptable.padding_width = 1    

        self.result = self.result['scan']
        for target in self.result:
            self.lock.acquire()
            print('\033[1;32;40mHost: \033[0m\033[1;34;40m' + target + '\033[0m\033[1;32;40m    Name: \033[0m\033[1;34;40m'),
            self.output.writelines('Host: ' + target + '    Name: ')
            host = target   #记录host
            #print(self.result)
            #print(self.result[target])
            target = self.result[target]
            hostnames = str('None' if not target['hostnames'][0]['name'] else target['hostnames'][0]['name'])
            print(hostnames + '\033[0m\033[1;32;40m')
            self.output.writelines(hostnames + '\n')
            tcp = target['tcp']
            for port in tcp:
                reason, title = self._get_Title(host, port)
                ptable.add_row([str(port), tcp[port]['state'], tcp[port]['name'], reason, title])
            print(ptable)
            self.output.writelines(str(ptable)+'\n\n')
            print('\033[0m')
            self.lock.release()

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
                    out = '\033[1;33;40m\r[*]Thread ' + str(index) + ' is Running' + '.' * (count) + ' '*(self.console_width-24-count) + '\033[0m\r'
                    sys.stdout.write(out)
                    sys.stdout.flush()
                    self.lock.release()
                    sleep(0.2)

                else:
                    self.lock.acquire() #获取ip后释放锁
                    All_Is_Over -= 1    #每结束一个线程, All_Is_Over数量减1
                    self.lock.release()
            self.lock.acquire()
        self.lock.release()

    def run(self):
        #print('Total Thread Count: ', self.thread_count)
        try:
            for i in range(self.thread_count):
                #self.thread[i].setDaemon(True)
                self.thread[i].start()
                sleep(0.2)    #等待线程启动正常
                """
                if not self.thread[i].isAlive(): #线程启动失败则退出
                    print('[-]\033[1;33;31mThread number ' + str(i) + ' Start Fail!\nExit the program\033[0m')
                    exit(-1)
                """
        except Exception as e:
            pass
        
        detection = threading.Thread(target=self._detection_Thread_Status)
        detection.setDaemon(True)
        detection.start()
        #detection.join()

        for i in range(self.thread_count):
            self.thread[i].join()

        self.output.close()

