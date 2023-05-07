from scapy.all import *
from scapy.layers.l2 import ARP, Ether


def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        if pkt[ARP].psrc == pkt[ARP].pdst:
            return  # ignore gratuitous ARP
        if pkt[ARP].hwsrc != pkt[Ether].src:
            print(f"ARP spoofing detected! Attacker IP: {pkt.src}")


sniff(prn=arp_display, filter="arp", store=0)