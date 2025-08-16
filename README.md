
# NetKing: Advanced Network Toolkit

**NetKing** is a powerful Python-based network toolkit designed for network scanning, traffic sniffing, Wi-Fi password cracking, and user blocking. It provides a unified interface to perform advanced network tasks with ease. Ideal for penetration testers, ethical hackers, and cybersecurity enthusiasts.  

---

## Features

- 🔍 **Network Scanning**: Discover active hosts in your network range.  
- 🚫 **User Blocking**: Block specific IP addresses from your router.  
- 📡 **Traffic Sniffing**: Capture packets from selected IPs and analyze traffic.  
- 🔓 **Wi-Fi Cracking**: Attempt to crack Wi-Fi passwords using a wordlist.  
- ⚡ **Flexible Options**: Specify interfaces, timeouts, and custom keyword detection.  

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/netking.git
cd netking
```

2. Ensure Python 3.x is installed.
3. Install required dependencies (if any):

```bash
pip install -r requirements.txt
```

4. Make the script executable:

```bash
chmod +x netking.py
```

---

## Usage

**Basic Command Structure:**

```bash
python netking.py [OPTIONS] {crack}
```

### Examples

- **Scan network:**

```bash
sudo python netking.py --scan --range 192.168.1.1/24 --interface wlan0
```

- **Block users:**

```bash
sudo python netking.py --block 192.168.1.10,192.168.1.20 -r 192.168.1.1 --interface wlan0
```

- **Sniff traffic:**

```bash
sudo python netking.py --sniff 192.168.1.10 -r 192.168.1.1 --interface wlan0
```

- **Crack Wi-Fi:**

```bash
sudo python netking.py crack -i wlan1 -w /path/to/wordlist.txt
```

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |
| `--keywords KEYWORDS` | File with secret keywords to detect in sniffed packets |
| `-r ROUTER_IP` | Router IP address (required for block/sniff) |
| `--interface IFACE` | Network interface to use (e.g., wlan0) |
| `--scan` | Scan the network for active hosts |
| `--range IP_RANGE` | IP range to scan (e.g., 192.168.1.1/24) |
| `--timeout TIMEOUT` | Timeout for ARP scan (default: 8 seconds) |
| `--block IP_LIST` | Block users (comma-separated IPs) |
| `--sniff IP_LIST` | Sniff packets from specified IPs (comma-separated) |
| `crack` | Run crack.sh to attempt Wi-Fi password cracking |

---

## Safety & Legal Disclaimer

⚠️ **Important:** This tool is intended for educational and authorized penetration testing purposes **only**. Do **not** use it on networks you do not own or have explicit permission to test. Unauthorized access is illegal and punishable by law.

