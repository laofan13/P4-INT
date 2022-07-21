#!/usr/bin/env python3

import sys
from scapy.all import sniff
from colllector import *

def handle_pkt(pkt,c):
    if INTREP in pkt :
        print("\n\n********* Receiving Telemtry Report ********")
        flow_info = c.parser_int_pkt(pkt)
        flow_info.show()

def main():
    iface = 's3-cpu-eth1'
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    c = Collector()
    sniff(iface = iface,filter='inbound and tcp or udp',
        prn = lambda x: handle_pkt(x,c))

if __name__ == '__main__':
    main()
