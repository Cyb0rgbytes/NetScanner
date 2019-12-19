#!/user/bin/env python
# Title........: NetScanner.py
# Description..: This is a Python script for Linux systems to Scan for Devices on the subnet with ARP requests.
# Author.......: SoftAddict
# Version......: 1.0
# Usage........: python3 or python NetScanner.py --target 192.168.1.1/24 or any similar subnet masks
# Python Version.: 2 compatible with 3 as well

import scapy.all as scapy
import argparse
import colorama
from colorama import Fore, Style

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print(Fore.GREEN + "[+] Initializing...")
    print(Fore.GREEN + "[+] Summoning the Network Scanner wizard")

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
# print(element[1].psrc + "\t\t" + element[1].hwsrc)

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
