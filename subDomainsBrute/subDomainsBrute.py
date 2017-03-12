#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A simple and fast sub domain brute tool
# my[at]lijiejie.com (http://www.lijiejie.com)

import sys
import gc
import os
import time
#import Queue
import queue
import platform
import threading
import gevent.pool
import dns.resolver
from lib.console import 
from prettytable import PrettyTable
#from IPy import IP
from gevent import monkey
from lib.consle_width import getTerminalSize
from publicsuffix import PublicSuffixList
from publicsuffix import fetch
monkey.patch_all()


class DNSBrute:
    def __init__(self, target, threads_num, names_file, output): #缺少threads_num
        self.target = target
        self.names_file = names_file
        #参数提供的线程个数，默认10
        self.threads_num = threads_num
        #根据域名个数来划分进程池的个数
        self.segment_num = 2500
        #用于记录总的爆破域名个数
        self.total = 0
        self.found_count = 0
        #显示运行时间
        self.start_time = time.time()
        #用于输出
        self.console_width = getTerminalSize()[0]
        self.console = Console()
        #self.console_width -= 2    # Cal width when starts up
        self.ptable = PrettyTable(['Domain', 'IS_CDN', 'DICT_IP'])
        self.ptable.align = 'l'  #靠左输出
        #ptable.align['Port'] = '1'
        self.ptable.padding_width = 1 
        self._load_dns_servers()
        self._load_sub_names()
        self._load_cdn()
        self.lock = threading.Lock()
        time_start = time.time()
        self._get_suffix()
        print('\033[1;33;40m[!]Use Seconds: ' + str(time.time() - time_start) + '\033[0m')
        #self._add_ulimit()

    #不变
    def _load_dns_servers(self):
        #print('_load_dns_servers')
        dns_servers = []
        with open('./wordlist/dns_servers.txt') as f:
            for line in f:
                server = line.strip()
                if server.count('.') == 3 and server not in dns_servers:
                    dns_servers.append(server)
        self.dns_servers = dns_servers
        self.dns_count = len(dns_servers)

    #不变
    def _load_cdn(self):
        #print('_load_cdn')
        set_cdn = set()
        with open('./wordlist/cdn_servers.txt','r') as file_cdn:
            for line in file_cdn:
                line = line.strip()
                set_cdn.add(line)
        self.set_cdn = set_cdn
        #print('_end_load_cdn')


    #不变
    def _load_sub_names(self):
        #print('_load_sub_names')
        self.queues = []
        q = queue.Queue() #Queue.Queue()
        with open(self.names_file) as f:
            for line in f:
                domain = "{sub}.{target_domain}".format(sub=line.strip(), target_domain=self.target)
                if q.qsize() < self.segment_num:  #按照self.segment_num大小将域名划分到多个Queue中
                    #print('put ' + domain)
                    q.put(domain)
                else:                               #当queue数量满了，则换一个Queue
                    self.total += self.segment_num
                    self.queues.append(q)
                    q = queue.Queue()
        self.total += q.qsize()
        self.rest = self.total  #rest记录剩余的个数        
        self.queues.append(q)

    #不变
    def _thread_pool(self, q, pool_name):
        #print('_thread_pool')
        #根据给定的线程数创建线程
        #print('Start Process ' + str(pool_name))
        threads = [threading.Thread(target=self._query_domain, args=(q, pool_name)) for _ in range(self.threads_num)]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        except Exception as e:
            print(e)
            pass
        #self._handle_data(pool_name)

    #不变
    def run(self):
        #print('run')
        #进程池
        #pool_threads = []
        #print(len(self.queues))
        #for queue in range(len(self.queues)):
            #pool_threads.append(threading.Thread(target=self._thread_pool, args=(self.queues[thread_name],), name=str(thread_name)))
        #print("Start At "),
        #print(time_start)
        coroutine_pool = gevent.pool.Pool(len(self.queues))
        coroutine_pools = []
        for pool_name in range(len(self.queues)):
            coroutine_pools.append(coroutine_pool.apply_async(self._thread_pool, args=(self.queues[pool_name], pool_name)))
        self.resolvers = [dns.resolver.Resolver() for _ in range(len(coroutine_pools))]
        #设置dns解析服务器
        for resolver in self.resolvers:
            resolver.nameservers = self.dns_servers
            resolver.timeout = 4
            #print(resolver.nameservers)
        #self.dict_ips = [{} for _ in range(len(coroutine_pools))]
        #self.dict_cnames = [{} for _ in range(len(coroutine_pools))]
        self.dict_domain = {}
        self.ip_flags = [{} for _ in range(len(coroutine_pools))]
        #print('\033[1;34;40m%-30s\t|%-5s\t|%-15s\033[0m' % ("Domain", "IS_CDN", 'DICT_IP'))
        for coroutine in coroutine_pools:
            coroutine.join()
        """
        for pool_name in range(len(self.queues)):
            #print(self.dict_ips[pool_name])
            #print(self.dict_cnames[pool_name])
            for ip, times in self.ip_flags[pool_name].items():
                print(str(ip) + '\t\t' + str(times))
        """
        """
        for thread in pool_threads:
            thread.start()
        for thread in pool_threads:
            thread.join()
        """
        #self._handle_data(pool_name)
        del coroutine_pools
        #print('End At '),
        #print(time_end)
        
    """
    #不变
    def _add_ulimit(self):
        if(platform.system()!="Windows"):
            os.system("ulimit -n 65535")
    """

    #不变
    def _query_domain(self, q, pool_name):
        while q.qsize() > 0:
            domain = q.get(timeout=1.0)
            self.lock.acquire()
            self.rest -= 1
            self.lock.release()
            #print(domain)
            list_ip=list()
            list_cname=list()
            msg = '\033[1;34;40m%s found | %s remaining | %s scanned in %.2f seconds\033[0m' % (
                self.found_count, self.rest, self.total-self.rest, time.time() - self.start_time)
            sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)+14) + msg)
            sys.stdout.flush()
            try:
                record = self.resolvers[pool_name].query(domain)
                for A_CNAME in record.response.answer:
                    for item in A_CNAME.items:
                        if item.rdtype == self.get_type_id('A'):
                            list_ip.append(str(item))
                            #self.dict_ips[pool_name][domain]=list_ip
                        elif(item.rdtype == self.get_type_id('CNAME')):
                            list_cname.append(str(item))
                            #print(str(item))
                            #self.dict_cnames[pool_name][domain] = list_cname
                        elif(item.rdtype == self.get_type_id('TXT')):
                            pass
                        elif item.rdtype == self.get_type_id('MX'):
                            pass
                        elif item.rdtype == self.get_type_id('NS'):
                            pass
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.Timeout:
                pass
            except Exception as e:
                pass
            finally:
                #每获取一个域名及其IP，都将对该域名进行判断是否为cdn
                #print('_finally_method_')
                if list_ip:
                    self._handle_data(domain, list_ip, list_cname)
                del list_ip
                del list_cname

    
    #不变
    def _handle_data(self, domain, list_ip, list_cname):

        #判断域名是否为cdn
        iscdn = False
        for cname in list_cname:
            if(self._check_cdn(cname)):
                iscdn = True
            else:
                iscdn = False
        self.dict_domain[domain] = (str(iscdn), sorted(list_ip))
        self.ptable.add_row([domain.ljust(30), str(iscdn), ', '.join(sorted(list_ip))])
        print('%s' % str(self.ptable), flush=True)
        #sys.stdout.write(str(self.ptable) + ' ' * (self.console_width - len(str(self.ptable))))
        #msg = "%-30s\t|%-5s\t|%-15s" % (domain.ljust(30), str(iscdn), ', '.join(sorted(list_ip)))
        #sys.stdout.write('\r' + msg + ' ' * (self.console_width - len(msg)))
        #domain计数器
        self.lock.acquire()
        self.found_count = self.found_count + 1
        self.lock.release()
    
    #不变
    def _get_suffix(self):
        print('\033[1;33;40m[!]GET PublicSuffixList, Please Wait Some Times...\033[0m')
        suffix_list = fetch()
        self.psl = PublicSuffixList(suffix_list)
    
    #不变
    def get_type_id(self, name):
        return dns.rdatatype.from_text(name)

    #不变
    def _check_cdn(self,cname):
        cdn_name=self.psl.get_public_suffix(cname)
        if cdn_name in self.set_cdn:
            return True
        else:
            return False


    """
    def judge_speed(self,speed):
        if(speed == "low"):
            self.coroutine_num = 1000
            self.segment_num = 7000
        elif(speed =="high"):
            self.coroutine_num == 2500
            self.segment_num = 20000
        else:
            self.coroutine_num =1500
            self.segment_num = 10000

    
    
    def get_subname(self):
        with open('dict/wydomain.csv', 'r') as file_sub:
            for subname in file_sub:
                domain = "{sub}.{target_domain}".format(sub=subname.strip(), target_domain=self.target_domain)
                self.queues.put(domain)
    
    


    def generate_sub(self):
        for k,v in self.dict_ip.items():
            if (str(k).count(".")<self.level):
                file_next_sub = open('dict/next_sub_full.txt', 'r')
                for next_sub in file_next_sub:
                    subdomain = "{next}.{domain}".format(next=next_sub.strip(), domain=k)
                    self.queues.put_nowait(subdomain)
                file_next_sub.close()

    

    def raw_write_disk(self):
        self.flag_count = self.flag_count+1
        with open('result/{name}.csv'.format(name=self.target_domain), 'a') as csvfile:
            writer = csv.writer(csvfile)
            if(self.flag_count == 1):
                writer.writerow(['domain', 'CDN', 'IP'])
                for k,v in self.dict_ip.items():
                    try:
                        tmp = self.dict_cname[k]
                    except:
                        tmp="No"
                    writer.writerow([k,tmp,self.dict_ip[k]])
            else:
                for k,v in self.dict_ip.items():
                    try:
                        tmp = self.dict_cname[k]
                    except:
                        tmp="No"
                    writer.writerow([k,tmp,self.dict_ip[k]])
        self.dict_ip.clear()
        self.dict_cname.clear()

    def deal_write_disk(self):
        ip_flags = sorted(self.ip_flag.items(), key = lambda d: d[1], reverse = True)
        with open('result/deal_{name}.csv'.format(name = self.target_domain), 'a') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'frequency'])
            for ip in ip_flags:
                writer.writerow(ip)
    """