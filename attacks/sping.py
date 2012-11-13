from scapy.all import srloop, IP, ICMP
import sys
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(1)

def ping(spoofed_src, destination):
    srloop(IP(src=spoofed_src,dst=destination)/ICMP())

def main():
    if len(sys.argv) !=3:
        print "Usage : <script> spoofed_src destination_ip"
    else:
        ping(sys.argv[1],sys.argv[2])

if __name__ == "__main__":
    main()

