#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_req_broad = broadcast/arp_request
    answ, unansw = scapy.srp(arp_req_broad, timeout = 1)
    print(unansw.summary())


scan('10.0.2.1/24')