from scapy.all import *
from scapy.layers.l2 import ARP, Ether

ip_to_mac = {}


def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        if pkt[ARP].psrc in ip_to_mac != pkt[ARP].hwsrc:
            if ip_to_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
                print(f"ARP spoofing detected! Attacker IP: {pkt[ARP].psrc}")
        else:
            ip_to_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc


sniff(prn=arp_display, filter="arp", store=0)
