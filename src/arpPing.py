#!/usr/bin/env python

# This script will ARP-Ping all machines on the network you specify
# Example of CIDR format: 192.168.1.0/24

from scapy.all import *
 
def main(cidr_network):

    # Change verbosity of Scapy to be almost mute
    conf.verb=0

    answered_packets,unanswered_packets = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr_network), timeout=2)

    # Print out the Mac and IP
    print ("MAC, IP")
    for sent_packets,received_packets in answered_packets:
        # Check just the received packets for the Target's Hardware Address and Target's Protocol Address
        # See Scapy source's l2.py for details on Ether and ARP
        # See Scapy source's packet.py for sprintf definition:
            # sprintf(format) where format is a string that can include directives
            # A directive begins and ends with %
        print (received_packets.sprintf(r"%Ether.src%, %ARP.psrc%"))

if __name__ == "__main__":
    cidr_network = raw_input("What is the network you want to scan in CIDR format ? ")
    main(cidr_network)