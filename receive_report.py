#!/usr/bin/env python3

import sys

import io

from scapy.all import sniff
from scapy.all import Packet
from scapy.all import ShortField, BitField
from scapy.layers.inet import Ether,IP, TCP, UDP, bind_layers

class INTREP(Packet):
    name = "INT Report Header v2.0"
    fields_desc =  [
        BitField("version", 0, 4),
        BitField("hw_id", 0, 6),
        BitField("seq_number", 0, 22),
        BitField("node_id", 0, 32)]

class INTIndiviREP(Packet):
    name = "INT Report Individual Header v2.0"

    fields_desc =  [
        BitField("rep_type", 0, 4),   
        BitField("in_type", 0, 4),
        BitField("rep_len", 0, 8),
        BitField("md_len", 0, 8),
        BitField("flag", 0, 4),
        BitField("rsvd", 0, 4),
        ShortField("RepMdBits", 0),
        ShortField("DomainID", 0),
        ShortField("DSMdBits", 0),
        ShortField("DSMdstatus", 0)]
                    
class INTShim(Packet):
    name = "INT Shim header v2.1"
    fields_desc = [
        BitField("type", 0, 4),
        BitField("next_protocol", 0, 2),
        BitField("rsvd", 0, 2),
        BitField("int_length", 0, 8),
        ShortField("NPT Dependent Field", 0)]

class INTMD(Packet):
    name = "INT-MD Header v2.1"
    fields_desc =  [
        BitField("version", 0, 4),
        BitField("flags", 0, 3),
        BitField("reserved", 0, 12),
        BitField("HopMetaLength", 0, 5),
        BitField("RemainingHopCount", 0, 8),
        BitField("instruction_mask_0003", 0, 4),
        BitField("instruction_mask_0407", 0, 4),
        BitField("instruction_mask_0811", 0, 4),
        BitField("instruction_mask_1215", 0, 4),
        ShortField("DomainID", 0),
        ShortField("DomainInstructions", 0),
        ShortField("DomainFlags", 0)]

bind_layers(UDP,INTREP,dport=1234)
bind_layers(INTREP,INTIndiviREP)
bind_layers(INTIndiviREP,Ether,in_type=3)
bind_layers(INTShim,INTMD,type  = 1)

SWITCH_ID_BIT =             0b10000000
L1_PORT_IDS_BIT =           0b01000000
HOP_LATENCY_BIT =           0b00100000
QUEUE_BIT =                 0b00010000
INGRESS_TSTAMP_BIT =        0b00001000
EGRESS_TSTAMP_BIT =         0b00000100
L2_PORT_IDS_BIT =           0b00000010
EGRESS_PORT_TX_UTIL_BIT =   0b00000001


class HopMetadata():
    def __init__(self):
        self.switch_id = None
        self.l1_ingress_port_id = None
        self.l1_egress_port_id = None
        self.hop_latency = None
        self.q_id = None
        self.q_occupancy = None
        self.ingress_tstamp = None
        self.egress_tstamp = None
        self.l2_ingress_port_id = None
        self.l2_egress_port_id = None
        self.egress_port_tx_util = None
    
    @staticmethod
    def from_bytes(data, ins_map):
        hop = HopMetadata()
        d = io.BytesIO(data)
        if ins_map & SWITCH_ID_BIT:
            hop.switch_id = int.from_bytes(d.read(4), byteorder='big')
        if ins_map & L1_PORT_IDS_BIT:
            hop.l1_ingress_port_id = int.from_bytes(d.read(2), byteorder='big')
            hop.l1_egress_port_id = int.from_bytes(d.read(2), byteorder='big')
        if ins_map & HOP_LATENCY_BIT:
            hop.hop_latency = int.from_bytes(d.read(4), byteorder='big')
        if ins_map & QUEUE_BIT:
            hop.q_id = int.from_bytes(d.read(1), byteorder='big')
            hop.q_occupancy = int.from_bytes(d.read(3), byteorder='big')
        if ins_map & INGRESS_TSTAMP_BIT:
            hop.ingress_tstamp = int.from_bytes(d.read(8), byteorder='big')
        if ins_map & EGRESS_TSTAMP_BIT:
            hop.egress_tstamp = int.from_bytes(d.read(8), byteorder='big')
        if ins_map & L2_PORT_IDS_BIT:
            hop.l2_ingress_port_id = int.from_bytes(d.read(4), byteorder='big')
            hop.l2_egress_port_id = int.from_bytes(d.read(4), byteorder='big')
        if ins_map & EGRESS_PORT_TX_UTIL_BIT:
            hop.egress_port_tx_util = int.from_bytes(d.read(4), byteorder='big')
        return hop

    def __str__(self):
        return str(vars(self))


def parse_metadata(int_pkt):
    int_pkt.show()
    
    instructions = (int_pkt[INTMD].instruction_mask_0003 << 4) + int_pkt[INTMD].instruction_mask_0407
    int_len = int_pkt.int_length-3
    hop_meta_len = int_pkt[INTMD].HopMetaLength
    int_metadata = int_pkt.load[:int_len<<2]

    hop_count = int(int_len /hop_meta_len)
    hop_metadata = []
    for i in range(hop_count):
        metadata_source = int_metadata[i*hop_meta_len<<2:(i+1)*hop_meta_len<<2]
        meta = HopMetadata.from_bytes(metadata_source, instructions)
        print(meta)
        hop_metadata.append(meta)

    return hop_metadata
        

def handle_pkt(pkt):
    if IP in pkt :
        print("\n\n********* Receiving Telemtry Report ********")
        pkt[INTREP].show()
        parse_metadata(INTShim(pkt.load))

def main():
    iface = 's3-cpu-eth1'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,filter='inbound and tcp or udp',
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()