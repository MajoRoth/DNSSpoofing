This code uses the Scapy library to perform ARP sniffing on a network.
It captures ARP packets and checks if they are ARP replies.
If an ARP reply is detected and the source IP address does not match the corresponding
MAC address stored in the dictionary "ip_to_mac,"
it prints a message indicating ARP spoofing detection.
Otherwise, it updates the dictionary with the new IP-to-MAC mapping.
The sniff() function is used to start the packet sniffing process,
with the "arp" filter specified and the arp_display() function as the callback
to handle each captured packet.