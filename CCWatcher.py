import re
import sys
import argparse
from scapy.all import *

def arguments():
    parser = argparse.ArgumentParser(description = 'Network Sniffer Tool, to find unencrypted Credit Card data.')
    parser.add_argument('-i', '--iface', action = 'store', dest = 'iface',required = True, help = 'Interface to sniff')
    parser.add_argument('-f', '--filter', action = 'store', dest = 'filter', default='tcp', required = False, help = 'Filter in wireshark style. Ex.: "tcp and port 80"')
    parser.add_argument('-r', '--regex-file', action = 'store', dest = 'regex', default='regex_cc.txt', required = False, help = 'File with regex rules to find Credit Card')
    return parser.parse_args()

def regex_gen():
    x = list()
    for regex in open('regex_cc.txt'):
        x.append(regex.split(':',1)[1].strip())
    return re.compile('|'.join(x))

def monitor(pkt):
    if 'TCP' in pkt and pkt[TCP].payload:
        data = str(pkt[TCP].payload)
        if pattern.match(data):
            print "%s:%s============>%s:%s" % (pkt[IP].src,pkt[IP].sport,pkt[IP].dst,pkt[IP].dport)
            print 'Credit card Found!'
            print data

    elif pkt.getlayer(Raw):
        data = pkt.getlayer(Raw).load
        if pattern.match(data):
            print "%s:%s============>%s:%s" % (pkt[IP].src,pkt[IP].sport,pkt[IP].dst,pkt[IP].dport)
            print 'Credit card Found!'
            print data

args = arguments()
pattern = regex_gen()
sniff(prn=monitor,iface=args.iface,filter=args.filter,count=0)
