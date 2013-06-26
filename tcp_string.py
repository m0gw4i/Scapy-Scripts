#!/usr/bin/python

import os
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #disable Scapy IPv6 message
from scapy.all import *

def help():
	print "Usage: udp_string.py <ip> <random>|<dport> <string> [<count>]"

def main():
	if os.getuid() == 0:
		if len(sys.argv) <= 3:
			help()
			sys.exit(1)
		else:
			if sys.argv[1] == "help":
				help()
				sys.exit(1)
			else:
				ip=sys.argv[1]
				dport=sys.argv[2]
				string=sys.argv[3]
				try:
					sys.argv[4]
				except:
					pcount = 1
				else:
					pcount = int(sys.argv[4])
			if dport == "random":
					p=(IP(dst=ip)/fuzz(TCP())/string)

			else:
					p=(IP(dst=ip)/fuzz(TCP(dport=int(dport)))/string)
			send(p, count=pcount)
	else:
		print "Must run as root/sudo!"
		help()
		sys.exit(1)
if __name__ == "__main__":
	    sys.exit(main())
