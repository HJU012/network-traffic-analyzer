# Testing Notes

## Cross-check against Wireshark
- Captured live traffic on eth0 using Wireshark while running ping -c 5 google.com.
- Wireshark showed 10 ICMP packets (5 echo requests, 5 echo replies) between 10.0.2.15 and 142.250.193.174.
- Ran parser.py during the same ping and saved output to parser_output.txt.
- parser.py output showed 10 ICMP lines with the same source/destination IPs (142.250.193.174), confirming accurate packet parsing.

## stats.py
- Ran for extended periods during normal browsing; protocol counts, top talkers, and top ports updated correctly every 10 packets.

## detector.py
- Ran nmap -p 1-100 against the VM's own IP (10.0.2.15) with iface set to "lo".
- Detector correctly logged "POSSIBLE PORT SCAN" alerts to alerts.log with accurate timestamps, confirmed across multiple repeated test runs.
