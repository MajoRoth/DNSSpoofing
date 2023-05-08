from scapy.all import *
from scapy.layers.l2 import ARP

ip_mac_pairs = {}


def arp_display(pkt):
    if pkt[ARP].op == 1:  # If this is an ARP request
        if pkt[ARP].psrc in ip_mac_pairs and ip_mac_pairs[pkt[ARP].psrc] != pkt[ARP].hwsrc:
            # If the IP address is already in our dictionary and the MAC address doesn't match
            print("Possible ARP spoofing detected: IP: {} MAC: {}".format(pkt[ARP].psrc, pkt[ARP].hwsrc))
        else:
            ip_mac_pairs[pkt[ARP].psrc] = pkt[ARP].hwsrc  # Add the IP/MAC pair to our dictionary


sniff(prn=arp_display, filter="arp", store=0)
