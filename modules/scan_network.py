import tempfile
import scapy.all as scapy 
import argparse
from colorama import Fore,Style
from colorama import init 
init(autoreset=True)


def scan_network(network_ip,timeout , interface):
    arp_boradcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req = scapy.ARP(pdst=network_ip)
    boradcast_packet= arp_boradcast/arp_req
    answerd,unanswered =scapy.srp(boradcast_packet,timeout=timeout,verbose=False ,iface=interface)
    client_list=[]

    for sent , recived in answerd:
        client_dec={"ip":recived.psrc,"mac":recived.hwsrc}
        client_list.append(client_dec)
    return client_list





def display(client_list):
    print("\n")
    print(Fore.LIGHTRED_EX + "💻 IP ADDRESS           📡 MAC ADDRESS" + Style.RESET_ALL)
    print(Fore.RED + "-" * 42 + Style.RESET_ALL)

    for client in client_list:
        ip = client["ip"]
        mac = client["mac"]
        print(Fore.CYAN + f"{ip:<20} {mac}" + Style.RESET_ALL)




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i",type=str,required=True,help="target ip_adresse")
    parser.add_argument('--interface', type=str, required=False,help="Select interface")
    parser.add_argument("-t","-timeout",type=int,required=False,default=10,help="Set the timeout (in seconds) to wait for ARP responses. Default is 1.")
    option= parser.parse_args()
    interface=option.interface
    network_ip=option.i 
    timeout=option.t
    client_list=scan_network(network_ip,timeout,interface)
    display(client_list)


if __name__=="__main__":
    main()
