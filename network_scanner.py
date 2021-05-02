#!/usr/bin/env python
import scapy.all as scapy
import optparse


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_req_broad = broadcast/arp_request

    answ_list = scapy.srp(arp_req_broad, timeout = 1, verbose = False)[0]

    print('IP\t\t\tMAC Address\n------------------------------------------')

    for element in answ_list:
        print(element[1].psrc + '\t\t' + element[1].hwsrc)



def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--IP', dest = 'ip_address', help = 'IP Address in subnet to scan')
    (options, arguments) = parser.parse_args()

    if not options.ip_address:
        print('[-] Specify IP Address')
        parser.exit()


    return options.ip_address



range = get_arguments()
scan(range)