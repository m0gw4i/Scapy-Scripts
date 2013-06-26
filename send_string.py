#!/usr/bin/python

import os
import sys
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #disable Scapy IPv6 message
from scapy.all import *

def help():
	print "Usage: send_string.py <tcp|udp> <dest ip> <random|dest port> <string> [<packet count>]"

def main():
	# Check first to see if user running script is root/sudo
	if os.getuid() == 0:
		if len(sys.argv) <= 4:
			help()
			sys.exit(1)
		else:
			if sys.argv[1] == "help":
				help()
				sys.exit(1)
			else:
				proto = sys.argv[1].upper()
				ip = sys.argv[2]
				dport = sys.argv[3]
				string = sys.argv[4]
				
				# Validate IP
				try:
					socket.inet_aton(ip)
				except:
					print >> sys.stderr, "Error: Not a valid IP"
					sys.exit(1)
				else:
					# Check to see if protocol is valid
					if not (proto == "TCP" or proto == "UDP"):
						print >> sys.stderr, "Error: Protocol must be either TCP or UDP"
						sys.exit(1)
					else:	
						# Check to see if packet count is specified
						try:
							sys.argv[5]
						except: 
							pcount = 1 # if not specified, set to 1
						# Make sure count is an integer
						else:
							try:
								int(sys.argv[5])
							except:
								print >> sys.stderr, "Error: Packet count must be an integer"
								sys.exit(1)
							else:
								pcount = int(sys.argv[5])
		
					if dport == "random":
						if proto == "TCP":
							packet = (IP(dst=ip)/fuzz(TCP())/string)
						else:
							packet = (IP(dst=ip)/fuzz(UDP())/string)
					else:
						# Make sure destination port is an integer. Also takes care of != "random"
						try:
							int(dport)
						except:
							print >> sys.stderr, "Error: Destination port must be an integer or \"random\""
							sys.exit(1)
						else:
							if proto == "TCP":
								packet = (IP(dst=ip)/fuzz(TCP(dport=int(dport)))/string)
							else: 
								packet = (IP(dst=ip)/fuzz(UDP(dport=int(dport)))/string)

					# Actually send the final packet
					send(packet, count=pcount)

	else:
		print "Must run as root/sudo!"
		help()
		sys.exit(1)

# Run this shit!
if __name__ == "__main__":
	sys.exit(main())
