import re
import sys
import argparse
from scapy.all import *
from colorama import init
from termcolor import colored

init()

def arguments():
    parser = argparse.ArgumentParser(description = 'Network Sniffer Tool, to find unencrypted Credit Card data.')
    parser.add_argument('-i', '--iface', action = 'store', dest = 'iface',required = True, help = 'Interface to sniff')
    parser.add_argument('-f', '--filter', action = 'store', dest = 'filter', default='tcp', required = False, help = 'Filter in wireshark style. Ex.: "tcp and port 80"')
    parser.add_argument('-rf', '--regex-file', action = 'store', dest = 'regex_file', default='regex_cc.txt',required = False, help = 'Regex to find another informations')
    parser.add_argument('-r', '--regex', action = 'store', dest = 'regex', required = False, help = 'File with regex rules to find Credit Card')
    return parser.parse_args()

def regex_gen():
    if args.regex:
        return re.compile(args.regex)
    else:
        x = dict()
        for regex in open(args.regex_file):
            regex = regex.split(':',1)
            x[regex[0]]=regex[1]
        return x

def verify(data):
    for cc,pattern in patterns.items():
            if re.findall(pattern.strip(),data,re.MULTILINE):
                return cc

def monitor(pkt):
    data = str()
    if 'TCP' in pkt and pkt[TCP].payload:
        data = str(pkt[TCP].payload)

    elif pkt.getlayer(Raw):
        data = pkt.getlayer(Raw).load

    if data:
        cc = verify(data)
        if cc:
            print colored('[ %s Credit card Found! ]', 'white', 'on_green') % cc
            print "%s:%s============>%s:%s" % (pkt[IP].src,pkt[IP].sport,pkt[IP].dst,pkt[IP].dport)
            print data

args = arguments()
patterns = regex_gen()
sniff(prn=monitor,iface=args.iface,filter=args.filter,count=0)

