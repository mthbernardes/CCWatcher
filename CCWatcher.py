import re
import sys
import logging
import argparse
import requests
from scapy.all import *
from colorama import init
from threading import Thread
from termcolor import colored

#Color Windows
init()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def arguments():
    parser = argparse.ArgumentParser(description = 'Network Sniffer Tool, to find unencrypted Credit Card data.')
    parser.add_argument('-i', '--iface', action = 'store', dest = 'iface',required = True, help = 'Interface to sniff')
    parser.add_argument('-f', '--filter', action = 'store', dest = 'filter', default='tcp', required = False, help = 'Filter in wireshark style. Ex.: "tcp and port 80"')
    parser.add_argument('-rf', '--regex-file', action = 'store', dest = 'regex_file', default='regex_cc.txt',required = False, help = 'Regex to find another informations')
    parser.add_argument('-r', '--regex', action = 'store', dest = 'regex', required = False, help = 'File with regex rules to find Credit Card')
    parser.add_argument('-o', '--output', action = 'store', dest = 'output', default='credit_cards_output.txt',required = False, help = 'Output file where creditcards infos will be stored')
    parser.add_argument('-l', '--log', action = 'store', dest = 'log', default='ccwatcher.log',required = False, help = 'Output file where log will be stored')
    return parser.parse_args()

def save_cc(results):
    for result in results:
        f = open(args.output,'a')
        url = 'https://binlist.net/json/%s' % result
        r = requests.get(url)
        if status_code == 200:
            for key,value in r.json().items():
                msg = '%s\t\t\t%s\n' % (key,value)
                f.write(msg)
            f.close()

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
        result = re.findall(pattern.strip(),data,re.MULTILINE)
        if len(result) > 0:
            t = Thread(target=save_cc, args=(result,))
            t.start()
            return result

def monitor(pkt):
    data = str()
    if 'TCP' in pkt and pkt[TCP].payload:data = str(pkt[TCP].payload)

    elif pkt.getlayer(Raw):data = pkt.getlayer(Raw).load

    if data:
        cc = verify(data)
        if cc:
            #print
            logger.info(colored('Credit Cards Numbers\n%s', 'white', 'on_green') % ' | '.join(cc))
            logger.info("%s:%s============>%s:%s" % (pkt[IP].src,pkt[IP].sport,pkt[IP].dst,pkt[IP].dport))
            logger.info(data)

args = arguments()

# create a file handler
handler = logging.FileHandler(args.log)
handler.setLevel(logging.INFO)
logger.addHandler(handler)

patterns = regex_gen()
sniff(prn=monitor,iface=args.iface,filter=args.filter,count=0)
