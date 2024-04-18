from scapy.all import sr,IP,ICMP,TCP,sniff,wrpcap
import os
import sys

# Requesting root privileges
if os.geteuid() != 0:
    print("This script needs root privileges.")
    sys.exit()

# Constants
DEST_IP_ADDR = "99.99.99.254"
DEST_PORT_RANGE = (0, 100)
PACKET_ANS_TIMEOUT = 5
VULNERABLE_SERVICE_PORT = 80

try:
    # Sending SYN packets and receiving responses.
    print("Starting port scanner...")
    ans, unans = sr(IP(dst = DEST_IP_ADDR)/TCP(dport = DEST_PORT_RANGE, flags = "S"), timeout = PACKET_ANS_TIMEOUT, verbose=0)

    # Formatting and printing them
    print("Answered packets:")
    ans.summary(lambda s, r: r.sprintf(f"%TCP.sport%\t\t{'Open' if r[TCP].flags == 'SA' else 'Closed'}"))

    print("\nUnanswered ones:")
    unans.summary(lambda s: s.sprintf(f"%TCP.dport%\t\tFiltered"))

    # print("Sending ICMP echo-request instruction to the vulnerable machine...")
    # Exploiting any available service...
    # Running some instructions... injecting commands...
    # Sending ICMP echo-request command as instruction to the vulnerable machine to execute.
    # Something like the following packet could be constructed and sended:
    # inj_packet = IP(dst = DEST_IP_ADDR)/TCP(dport = VULNERABLE_SERVICE_PORT)/"| ping 99.99.99.50 -n 5"
    # sr(inj_packet)

    # Sniffing network activity
    cap = sniff(iface = "eth0", count = 5, filter = "icmp and host 99.99.99.254", prn = lambda p: p.sprintf("Received ICMP packet from %IP.dst%"))

    # Saving captured data in a pcap file.
    wrpcap("captured.pcap", cap)
except Exception as e:
    print("An exception has occurred:")
    print(e)
