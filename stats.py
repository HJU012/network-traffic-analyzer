from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from collections import Counter
import time

protocol_counts = Counter()
talker_counts = Counter()
port_counts = Counter()
start_time = time.time()
packet_total = 0

def handle(packet):
    global packet_total
    if IP in packet:
        src = packet[IP].src
    elif IPv6 in packet:
        src = packet[IPv6].src
    else:
        return

    packet_total += 1
    talker_counts[src] += 1

    if TCP in packet:
        protocol_counts["TCP"] += 1
        port_counts[packet[TCP].dport] += 1
    elif UDP in packet:
        protocol_counts["UDP"] += 1
        port_counts[packet[UDP].dport] += 1
    elif ICMP in packet:
        protocol_counts["ICMP"] += 1
    else:
        protocol_counts["OTHER"] += 1

    if packet_total % 10 == 0:
        show_stats()

def show_stats():
    elapsed = time.time() - start_time
    print(f"\n--- {packet_total} packets in {elapsed:.1f}s ---")
    print("Protocols:", dict(protocol_counts))
    print("Top talkers:", talker_counts.most_common(3))
    print("Top ports:", port_counts.most_common(3))

try:
    sniff(prn=handle, store=False)
except KeyboardInterrupt:
    show_stats()
