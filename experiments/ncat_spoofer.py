from scapy.all import *
from copy import deepcopy

while 1:
    pkts = sniff(count=5,filter="udp and dst port 55555",prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))

    op = pkts[UDP][-1]
    etp = deepcopy(op)
    etp.show()
    del etp[IP].chksum
    del etp[UDP].chksum
    del etp[UDP].len
    (etp[Ether].dst,etp[Ether].src) = (etp[Ether].src,etp[Ether].dst)
    (etp[IP].dst,etp[IP].src) = (etp[IP].src,etp[IP].dst)
    #etp[Raw].load = etp[Raw].load[:-1]+"-reply\n"
    #etp[Raw].load = "bye\n"
    (etp[UDP].dport,etp[UDP].sport) = (etp[UDP].sport,etp[UDP].dport)

    print etp

    etp.show2()

    sendp(etp)

