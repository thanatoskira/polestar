#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import optparse
from subDomainsBrute import DNSBrute
from doNmap import doNmap

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog [options] target')
    parser.add_option('-t', '--threads', dest='threads_num',
              default=10, type='int',
              help='Number of threads. default = 10')
    parser.add_option('-f', '--file', dest='names_file', default='subnames.txt',
              type='string', help='Dict file used to brute sub names')
    parser.add_option('-o', '--output', dest='output', default=None,
              type='string', help='Output file name. default is {target}.txt')
    parser.add_option('-a', '--append', dest='arguments', default='--open -v',
              type='string', help='Nmap arguments, default is "--open -v". eg: "-sS -sV"')
    parser.add_option('-n', '--nthread', dest='nmap_thread', default='10',
              type='int', help='Number of Nmap threads, default = 10, max = 30')

    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit(0)
    
    print(args[0], options.names_file, options.threads_num, options.output)

    dnsBrute = DNSBrute(target=args[0], names_file=options.names_file,
                 threads_num=options.threads_num,
                 output=options.output)
    
    dnsBrute.run()
    scan = doNmap(dnsBrute.all_ip, options.arguments, options.nmap_thread)

    scan.run()