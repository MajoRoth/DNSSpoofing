from scapy.all import *
from scapy.layers.l2 import ARP, Ether

mac_to_ip = {}
def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        if pkt[ARP].psrc == pkt[ARP].pdst:
            return  # ignore gratuitous ARP
        if pkt[ARP].hwsrc in mac_to_ip != pkt[Ether].src:
            if mac_to_ip[pkt[ARP].hwsrc] != pkt[IP].src:
            	print(f"ARP spoofing detected! Attacker IP: {pkt.src}")
        else:
            mac_to_ip[pkt[ARP].hwsrc] = pkt[IP].src
	   	


sniff(prn=arp_display, filter="arp", store=0)
