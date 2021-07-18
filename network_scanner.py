#!/usr/bin/env python3
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--Range', dest = 'ip_target', help = 'IP Address in subnet to scan')
    options = parser.parse_args()

    if not options.ip_target:
        print('[-] Specify a range')
        parser.exit()

    return options.ip_target


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answ_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]

    clients_list = []

    for element in answ_list:
        client_dictionary = {'ip': element[0].psrc, 'mac': element[0].hwsrc}
        clients_list.append(client_dictionary)
        
    return clients_list


def print_result(results_list):
    print('IP\t\t\tMAC Address\n------------------------------------------')
    for client in results_list:
        print(client['ip'] + '\t\t' + client['mac'])




range = get_arguments()
scan_result = scan(range)
print_result(scan_result)