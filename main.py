from scapy.all import sr,IP,ICMP,TCP,sniff,wrpcap,AsyncSniffer
import os
import sys
import time

# Requesting root privileges
if os.geteuid() != 0:
    print("This script needs root privileges.")
    sys.exit()

# Validating port range
valid_range = False
if len(sys.argv) == 3:
    try:
        initial = int(sys.argv[1])
        last = int(sys.argv[2])

        if initial < last:
            valid_range = True
        else:
            raise Exception("Invalid specified range.")
    except:
        print("Using (0, 9000) as default port range.")
            

# Constants
DEST_IP_ADDR = "99.99.99.254"
DEST_PORT_RANGE = (0 if not valid_range else int(sys.argv[1]), 9000 if not valid_range else int(sys.argv[2]))
PACKET_ANS_TIMEOUT = 5
VULNERABLE_SERVICE_PORT = 80

try:
    # Sending SYN packets and receiving responses.
    print("Starting port scanner...")
    ans, unans = sr(IP(dst = DEST_IP_ADDR)/TCP(dport = DEST_PORT_RANGE, flags = "S"), timeout = PACKET_ANS_TIMEOUT, verbose=0)

    # Formatting and printing them
    if len(ans) > 1:
        print("Answered packets:")
        ans.summary(lambda s, r: r.sprintf(f"%TCP.sport%\t\t{'Open' if r[TCP].flags == 'SA' else 'Closed'}"))

    if len(unans) > 1:
        print("\nUnanswered ones:")
        unans.summary(lambda s: s.sprintf(f"%TCP.dport%\t\tFiltered"))

    # print("Exploiting the vulnerable service.")
    # Exploiting the vulnerable service.
    # Running some instructions... injecting commands...
    
    # Asynchronously Sniffing network activity
    print("\nStarting sniff for ten seconds...")
    cap = AsyncSniffer(iface = ["eth0", "lo"], count = 10, filter = "icmp", prn = lambda p: p.sprintf("Received ICMP packet from %IP.dst%"))
    cap.start()

    # print("Sending ICMP echo-request instruction to the vulnerable machine...")
    # Sending ICMP echo-request command as instruction to the vulnerable machine to execute.
    # Something like the following packet could be constructed and sended:
    # inj_packet = IP(dst = DEST_IP_ADDR)/TCP(dport = VULNERABLE_SERVICE_PORT)/"| ping 99.99.99.50 -n 5"
    # sr(inj_packet)
    
    time.sleep(10)
    if cap.running: cap.stop()

    # Writting to pcap file
    if len(cap.results) > 0:
        wrpcap("capture.pcap", cap.results)
except Exception as e:
    print("An exception has occurred:")
    print(e)
