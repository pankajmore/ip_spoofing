#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#from arp_posion_using_scapy import *

# Import scapy
from scapy.all import *

#source="172.27.22.160"
#source="172.27.19.20"

# Execute this to drop RST packets
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <local-ip-address> -j DROP

# Prepare GET statement
get='GET / HTTP/1.0\n\n'

# Set up target IP
if len(sys.argv) == 4:
    destination=sys.argv[2]
    destination_port=int(sys.argv[3])
    ip=IP(src=sys.argv[1],dst=destination)
else:
    print "Usage: <script> spoofed_ip server_ip port"
    exit()
    #ip=IP(dst=destination)

# Generate random source port number
port=RandNum(1024,65535)

# Create SYN packet
SYN=ip/TCP(sport=port, dport=destination_port, flags="S", seq=0)

# Send SYN and receive SYN,ACK
print "\n[*] Sending SYN packet"
SYNACK=sr1(SYN)

# Create ACK with GET request
ACK=ip/TCP(sport=SYNACK.dport, dport=destination_port, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)/get

# SEND our ACK-GET request
print "\n[*] Sending ACK-GET packet"
reply,error=sr(ACK)

# print reply from server
print "\n[*] Reply from server:"
print reply.show()

print '\n[*] Done!'

def parse(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        print pkt.getlayer(Raw).load


    #sniff(prn=parse)
print "Payload"
parse(reply[0][0])
parse(reply[0][1])
