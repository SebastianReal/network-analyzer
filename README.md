# Python Network Analyzer

A network analyzer built with Python and Scapy that captures live packets, extracts source and destination IPs, identifies protocol types (TCP, UDP, ICMP), and summarizes traffic activity in real-time.

---

## How It Works

For each captured packet:
- It checks for IP, TCP, UDP, or ICMP layers
- Extracts the relevant IP addresses and protocol
- Updates a running count of protocols
- Prints a summary to the console
- Saves all results in a log file for later review

---

## Requirements

- Python 3.8 or higher
- [Scapy](https://scapy.net/)
- [Npcap](https://npcap.com/) (Windows users) – required for packet capture
- Administrator privileges (to run sniffing)

---

## Example output

TCP  | 192.168.1.10 -> 172.217.6.78 </br>
UDP  | 192.168.1.10 -> 8.8.8.8 <\br>
ICMP | 192.168.1.10 -> 192.168.1.1 <\br>

Packet Counts by Protocol:<\br>
TCP:  6<\br>
UDP:  3<\br>
ICMP: 1<\br>

---

## Installation & Usage

```bash
# Step 1: Create a virtual environment
python -m venv venv
.\venv\Scripts\activate

# Step 2: Install dependencies
pip install scapy

# Step 3: Run the analyzer with admin rights
python analyzer.py

