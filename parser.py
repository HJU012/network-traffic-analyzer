from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

print(f"{'PROTO':<7}{'SOURCE':<40}{'SPORT':<8}{'DEST':<40}{'DPORT':<8}{'SIZE'}")

def parse(packet):
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return

    if TCP in packet:
        proto, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet:
        proto, sport, dport = "ICMP", "-", "-"
    else:
        proto, sport, dport = "OTHER", "-", "-"

    print(f"{proto:<7}{src:<40}{str(sport):<8}{dst:<40}{str(dport):<8}{len(packet)}")

sniff(count=30, prn=parse, store=False)
