from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR
from collections import defaultdict
import time

PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 5
DNS_QUERY_THRESHOLD = 20
DNS_WINDOW = 10

port_activity = defaultdict(list)
dns_activity = defaultdict(list)
alerted_scanners = set()
alerted_dns = set()

def log_alert(message):
    line = f"[{time.strftime('%H:%M:%S')}] {message}"
    print(line)
    with open("alerts.log", "a") as f:
        f.write(line + "\n")

def check_port_scan(src, dport, now):
    port_activity[src].append((dport, now))
    port_activity[src] = [(p, t) for p, t in port_activity[src] if now - t <= PORT_SCAN_WINDOW]
    unique_ports = {p for p, t in port_activity[src]}
    if len(unique_ports) >= PORT_SCAN_THRESHOLD and src not in alerted_scanners:
        log_alert(f"POSSIBLE PORT SCAN from {src}: {len(unique_ports)} ports in {PORT_SCAN_WINDOW}s")
        alerted_scanners.add(src)

def check_dns_flood(src, now):
    dns_activity[src].append(now)
    dns_activity[src] = [t for t in dns_activity[src] if now - t <= DNS_WINDOW]
    if len(dns_activity[src]) >= DNS_QUERY_THRESHOLD and src not in alerted_dns:
        log_alert(f"UNUSUAL DNS ACTIVITY from {src}: {len(dns_activity[src])} queries in {DNS_WINDOW}s")
        alerted_dns.add(src)

def handle(packet):
    now = time.time()
    if IP in packet:
        src = packet[IP].src
    elif IPv6 in packet:
        src = packet[IPv6].src
    else:
        return

    if TCP in packet:
        check_port_scan(src, packet[TCP].dport, now)
    elif UDP in packet:
        check_port_scan(src, packet[UDP].dport, now)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            check_dns_flood(src, now)

print("Monitoring... press Ctrl+C to stop. Alerts also saved to alerts.log")
try:
    sniff(prn=handle, store=False, iface="eth0")
except KeyboardInterrupt:
    print("\nStopped.")
