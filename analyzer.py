
# What exactly is a network packet?
# A network packet is a small unit of data used to transmit information over a network. 
# At Layer 3, it includes IP header details such as source and destination addresses, and it may also contain transport layer data 
# like TCP/UDP headers and application payloads.

# What kind of information do packets carry that would be useful to analyze?
# Packets carry IP addresses, ports, protocols (TCP, UDP, ICMP), payload sizes, and flags (like SYN/ACK).
# Analyzing this can reveal who’s talking to whom, which protocols are in use, and whether suspicious traffic is present.

# How does a computer “listen” to network traffic? Are there Python libraries for that?
# A computer can use a network interface in promiscuous mode to capture all packets on the network. 
# In Python, libraries like Scapy or pyshark allow sniffing and analyzing packets.

# Should the tool display live output or save results for later?
#The tool will show the results and save  it in a document with the timestamp

# What is gonna be shown
# Ip source Ip destiny, port, protocol, size of the packege 

#LIBRARY Scrapy
# ACTIVATE VIERTUAAL ENVIROMENT .\venv\Scripts\Activate.ps1

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Count packets by protocol
protocol_counts = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0
}

# Store processed packet summaries
packet_summaries = []

# Function to run on each captured packet
def analyze_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            protocol_counts["TCP"] += 1
        elif packet.haslayer(UDP):
            proto = "UDP"
            protocol_counts["UDP"] += 1
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            protocol_counts["ICMP"] += 1
        else:
            proto = "Other"

        summary = f"{proto} | {src} -> {dst}"
        print(summary)
        packet_summaries.append(summary)

# Start sniffing packets (change count as needed)
print("Starting packet capture...\n")
sniff(prn=analyze_packet, count=10)
print("\nCapture complete.\n")

# Display protocol count summary
print("Packet Counts by Protocol:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")

# Save results to a file
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"packet_log_{timestamp}.txt"
with open(filename, "w") as file:
    file.write("Protocol | Source IP -> Destination IP\n")
    for entry in packet_summaries:
        file.write(entry + "\n")

print(f"\nResults saved to {filename}")