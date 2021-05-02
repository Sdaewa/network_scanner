#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_req_broad = broadcast/arp_request
    answ_list = scapy.srp(arp_req_broad, timeout = 1, verbose = False)[0]


    print('IP\t\t\tMAC Address\n------------------------------------------')


    for element in answ_list:
        print(element[1].psrc + '\t\t' + element[1].hwsrc)




scan('10.0.2.1/24')