from scapy.all import *
from scapy.layers.l2 import ARP

ip_mac_pairs = {}

mac_to_ip = {}
def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        if pkt[ARP].hwsrc in mac_to_ip != pkt[Ether].src:
            if mac_to_ip[pkt[ARP].hwsrc] != pkt[Ether].src:
            	print(f"ARP spoofing detected! Attacker IP: {pkt.src}")
        else:
            mac_to_ip[pkt[ARP].hwsrc] = pkt[Ether].src
            
def arp(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        if pkt[ARP].hwsrc !=  pkt[ARP].hwdst:
           print("fuck you")     
	   	


sniff(prn=arp, filter="arp", store=0)
