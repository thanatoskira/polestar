#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A simple and fast sub domain brute tool
# my[at]lijiejie.com (http://www.lijiejie.com)

import optparse
import Queue
import sys
import dns.resolver
import threading
import time
import optparse
from lib.consle_width import getTerminalSize
from nmap import nmap
from time import sleep


class DNSBrute:
    def __init__(self, target, names_file, threads_num, output):
        self.target = target.strip()
        self.names_file = names_file
        self.thread_count = self.threads_num = threads_num
        self.scan_count = self.found_count = 0
        self.lock = threading.Lock()
        self.console_width = getTerminalSize()[0]
        self.console_width -= 2    # Cal width when starts up
        self.resolvers = [dns.resolver.Resolver() for _ in range(threads_num)]
        self._load_dns_servers()
        self._load_sub_names()
        self._load_next_sub()
        self.outfilename = target + '.txt' if not output else output
        self.outfile = open(self.outfilename , 'w')   # won't close manually
        self.ipfile = open('ip_' + self.outfilename, 'w')    #记录下扫描结果中的所有IP
        self.ip_dict = {}
        self.all_ip = set()

    def _load_dns_servers(self):
        dns_servers = []
        with open('dns_servers.txt') as f:
            for line in f:
                server = line.strip()
                if server.count('.') == 3 and server not in dns_servers:
                    dns_servers.append(server)
        self.dns_servers = dns_servers
        self.dns_count = len(dns_servers)

    def _load_sub_names(self):
        self.queue = Queue.Queue()
        with open(self.names_file) as f:
            for line in f:
                sub = line.strip()
                if sub: self.queue.put(sub)

    def _load_next_sub(self):
        next_subs = []
        with open('next_sub.txt') as f:
            for line in f:
                sub = line.strip()
                if sub and sub not in next_subs:
                    next_subs.append(sub)
        self.next_subs = next_subs

    def _update_scan_count(self):
        self.lock.acquire()
        self.scan_count += 1
        self.lock.release()

    def _print_progress(self):
        self.lock.acquire()
        msg = '\033[1;34;40m%s found | %s remaining | %s scanned in %.2f seconds\033[0m' % (
            self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time)
        sys.stdout.write('\r' + ' ' * (self.console_width - len(msg) + 14) + msg)
        sys.stdout.flush()
        self.lock.release()

    def _scan(self):
        thread_id = int( threading.currentThread().getName() )
        self.resolvers[thread_id].nameservers = [self.dns_servers[thread_id % self.dns_count]]    # must be a list object
        self.resolvers[thread_id].lifetime = self.resolvers[thread_id].timeout = 1.0
        while self.queue.qsize() > 0 and self.found_count < 3000:    # limit found count to 3000
            sub = self.queue.get(timeout=1.0)
            try:
                cur_sub_domain = sub + '.' + self.target
                answers = d.resolvers[thread_id].query(cur_sub_domain)
                is_wildcard_record = False
                if answers:
                    for answer in answers:
                        self.lock.acquire()
                        self.all_ip.add(answer.address)
                        if answer.address not in self.ip_dict:
                            self.ip_dict[answer.address] = 1
                        else:
                            self.ip_dict[answer.address] += 1
                            if self.ip_dict[answer.address] > 6:    # a wildcard DNS record
                                is_wildcard_record = True
                        self.lock.release()
                    if is_wildcard_record:
                        self._update_scan_count()
                        self._print_progress()
                        continue
                    self.lock.acquire()
                    self.found_count += 1
                    ips = ', '.join([answer.address for answer in answers])
                    msg = cur_sub_domain.ljust(30) + ips
                    sys.stdout.write('\033[1;32;40m\r[+]' + msg + ' ' * (self.console_width- len(msg) - 3) + '\033[0m\n\r')
                    sys.stdout.flush()
                    self.outfile.write(cur_sub_domain.ljust(30) + '\t' + ips + '\n')
                    self.lock.release()
                    for i in self.next_subs:
                        self.queue.put(i + '.' + sub)
            except Exception as e:
                pass
            self._update_scan_count()
            self._print_progress()
            
        self._print_progress()
        self.lock.acquire()
        self.thread_count -= 1
        self.lock.release()

    def run(self):
        self.start_time = time.time()
        for i in range(self.threads_num):
            t = threading.Thread(target=self._scan, name=str(i))
            t.setDaemon(True)
            t.start()
        while self.thread_count > 0:
            time.sleep(0.01)
        
        print('\033[1;33;40m\n\n[*]Total number of IP : ' + str(len(self.all_ip)) + ', Saved in "ip_' + self.outfilename + '"\033[0m')
        self.all_ip = list(self.all_ip)
        self.all_ip.sort()  #将获取的ip进行排序
        print('\033[1;34;40m')
        print('\n'.join(self.all_ip))
        print('\033[0m')
        self.ipfile.write('\n'.join(self.all_ip))     #将扫出的域名所有ip导出到文件中

class DoScan:

    def __init__(self, all_ip, arguments):
        self.arguments = arguments
        self.nm = nmap.PortScanner()
        self.thread_count = len(all_ip)/3 if len(all_ip) % 3 == 0 else len(all_ip)/3 + 1    #每3个ip放在一个线程里
        all_ip = list(all_ip)
        #print(all_ip)
        #print(self.thread_count)
        self.hosts = [all_ip[index: index+self.thread_count] for index in range(0, len(all_ip), self.thread_count)]  #将ip根据线程数进行等分
        self.thread = []
        print('Count of All Thread: ' + str(self.thread_count))
        for thread_name in range(self.thread_count):       #根据线程数创建线程
            self.thread.append(threading.Thread(target=self.do_Scan, args=(self.hosts[thread_name],), name=str(thread_name)))
        #print(self.thread)

    def do_Scan(self, hosts):
        #try:
        hosts = ' '.join(hosts)
        self.result = self.nm.scan(hosts = hosts, arguments = self.arguments)
        self.get_Result()
        """
        except Exception as e:
            print('\033[1;31;40m[-]Thread Start Failure...')
            print('[-]Error: ' + str(e) + '\n\033[0m')
            exit(-1)
        """
                
    def get_Result(self):
        self.result = self.result['scan']
        for target in self.result:
            print('\n\033[1;32;40m' + target + ' named ')
            print(self.result)
            print(self.result[target])
            target = self.result[target]
            print(target['hostnames']['name'] + ' is ' + target['status']['state'] + '.')
            for tcp_port in target['tcp']:
                state = target['tcp'][tcp_port]['state']
                version = target['tcp'][tcp_port]['version']
                print(tcp_port + '\t' + state + '\t' + version)
                print('\033[0m')

    def run(self):
        for i in range(self.thread_count):
            print('[*]Thread number ' + str(i) + ' Start')
            self.thread[i].setDaemon(True)
            self.thread[i].start()
            #sleep(1)    #等待线程启动正常
            #if not self.thread[i].isAlive(): #线程启动失败则退出
            #    exit(-1)
        
        for i in range(self.thread_count):
            self.thread[i].join()
        """
        while self.thread[i].isAlive():
            for i in range(3):
                out = '\033[1;33;40m\r[*]Start Namp Scaning' + '.' * (i+1) + ' '*(3-i) + '\033[0m\r'
                sys.stdout.write(out)
                sys.stdout.flush()
                sleep(1)
        """

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog [options] target')
    parser.add_option('-t', '--threads', dest='threads_num',
              default=10, type='int',
              help='Number of threads. default = 10')
    parser.add_option('-f', '--file', dest='names_file', default='subnames.txt',
              type='string', help='Dict file used to brute sub names')
    parser.add_option('-o', '--output', dest='output', default=None,
              type='string', help='Output file name. default is {target}.txt')
    parser.add_option('-a', '--append', dest='arguments', default='--open -v -p-',
              type='string', help='The arguments of Nmap, like "-sS -sV"')

    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    d = DNSBrute(target=args[0], names_file=options.names_file,
                 threads_num=options.threads_num,
                 output=options.output)
    d.run()

    scan = DoScan(d.all_ip, options.arguments)

    scan.run()
    #scan.get_Result()
    

