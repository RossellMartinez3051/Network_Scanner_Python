#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parse = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="target", help="Target IP / IP range.")
#The user will be able to use these commands on the terminal to refine their search results during execution
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
#We will create our ARP request with scapy and ask who has X IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#Create an Ethernet frame to make sure packet we are sending will be
#sent to the broadcast MAC address and not to only one device
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
#Send the packet that we give and receive the response, wait one second for response, also simplify view
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
#Make a dictionary to access IP address of source and MAC address of client
        clients_list.append(client_dict)
    return clients_list
def print_result(results_list):
    print("IP\t\t\tMAC Address\n----------------------------")
    for client in results_list:
        print(client)
#This will iterate over the result and print dictionaries along with their keys and values       
       
       

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)