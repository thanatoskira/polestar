#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A simple and fast sub domain brute tool
# my[at]lijiejie.com (http://www.lijiejie.com)

import sys
import gc
import os
import time
import Queue
import platform
import threading
import gevent.pool
import dns.resolver
from IPy import IP
from gevent import monkey
from lib.consle_width import getTerminalSize
from publicsuffix import PublicSuffixList
from publicsuffix import fetch
monkey.patch_all()


class DNSBrute:
    def __init__(self, target, names_file, output): #缺少threads_num
        self.target = target
        self.names_file = names_file
        self.coroutine_num = 500
        self.segment_num = 7000
        self._load_dns_servers()
        self._load_sub_names()
        self._load_cdn()
        self.lock = threading.Lock()
        self._get_suffix()

    #不变
    def _load_dns_servers(self):
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
        self.set_cdn = set()
        with open('./wordlist/cdn_servers.txt','r') as file_cdn:
            for line in file_cdn:
                line = line.strip()
                self.set_cdn.add(line)


    #不变
    def _load_sub_names(self):
        self.queues = []
        queue = Queue.Queue()
        with open(self.names_file) as f:
            for line in f:
                domain = "{sub}.{target_domain}".format(sub=line.strip(), target_domain=self.target)
                if queue.qsize < self.segment_num:  #按照self.segment_num大小将域名划分到多个Queue中
                    if sub: queue.put(domain)
                else:                               #当queue数量满了，则换一个Queue
                    self.queues.append(queue)
                    queue = Queue.Queue()

    #不变
    def _thread_pool(self, queue):
        thread_id = int(threading.currentThread().getName())    #获取线程名称
        coroutine_pool = gevent.pool.Pool(self.coroutine_num)
        while queue.qsize > 0:
            coroutine_pool.apply_async(self._query_domain, args=(queue.get(), thread_id))
        self._handle_data(thread_id)
        coroutine_pool.join(20)
        coroutine_pool.kill()
        del coroutine_pool

    #不变
    def run(self):
        #进程池
        pool_threads = []
        for thread_name in range(len(self.queues)):
            pool_threads.append(threading.Thread(target=self._thread_pool, args=(self.queues[thread_name],), name=thread_name))
        self.resolvers = [dns.resolver.Resolver() for _ in range(len(pool_threads))]
        self.dict_ips = [{} for _ in range(len(pool_threads))]
        self.dict_cnames = [{} for _ in range(len(pool_threads))]
        for thread in pool_threads:
            thread.start()
        for thread in pool_threads:
            thread.join()
        
        del pool_threads

    #不变
    def _add_ulimit(self):
        if(platform.system()!="Windows"):
            os.system("ulimit -n 65535")

    #不变
    def _query_domain(self, domain, thread_id):
        list_ip=list()
        list_cname=list()
        try:
            record = self.resolvers[thread_id].query(domain)
            for A_CNAME in record.response.answer:
                for item in A_CNAME.items:
                    if item.rdtype == self.get_type_id('A'):
                        list_ip.append(str(item))
                        self.dict_ips[thread_id][domain]=list_ip
                    elif(item.rdtype == self.get_type_id('CNAME')):
                        list_cname.append(str(item))
                        self.dict_cnames[thread_id][domain] = list_cname
                    elif(item.rdtype == self.get_type_id('TXT')):
                        pass
                    elif item.rdtype == self.get_type_id('MX'):
                        pass
                    elif item.rdtype == self.get_type_id('NS'):
                        pass
            del list_ip
            del list_cname
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception as e:
            pass
    
    #不变
    def _get_suffix(self):
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
    #不变
    def _handle_data(self, thread_id):
        for k, v in self.dict_cnames[thread_id].items():
            for c in v:
                if(self._check_cdn(c)):
                    self.dict_cnames[thread_id][k] = "Yes"
                else:
                    self.dict_cnames[thread_id][k] = "No"
        invert_dict_ip={str(sorted(value)):key for key,value in self.dict_ips[thread_id].items()}
        invert_dict_ip={value:key for key,value in invert_dict_ip.items()}
        #这里多个线程修改同一个参数，所以加锁
        self.lock.acquire()
        self.found_count = self.found_count + invert_dict_ip.__len__()
        self.lock.release()
        for keys,values in self.dict_ips[thread_id].items():
            if(invert_dict_ip.__contains__(keys)):
                for value in values:
                    if(IP(value).iptype() =='PRIVATE'):
                        self.dict_ips[thread_id][keys] = "private address"
                    else:
                        try:
                            key_yes=self.dict_cnames[thread_id][keys]
                        except KeyError:
                            key_yes="No"
                        if(key_yes=="No"):
                            CIP = (IP(value).make_net("255.255.255.0"))
                            self.lock.acquire()
                            if CIP in self.ip_flag:
                                self.ip_flag[CIP] = self.ip_flag[CIP]+1
                            else:
                                self.ip_flag[CIP] = 1
                            self.lock.release()

        self.dict_ips[thread_id]=invert_dict_ip
    




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