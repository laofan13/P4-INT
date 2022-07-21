
import sys
import io
import time

from scapy.all import Packet
from scapy.all import BitField,ShortField
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

class FlowInfo():
    def __init__(self):
        # flow information
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.ip_proto = None

        # flow hop count and flow total latency
        self.hop_cnt  = 0
        self.flow_latency = 0

        # flow telemetry metadata
        self.switch_ids = []
        self.l1_ingress_ports = []
        self.l1_egress_ports = []
        self.hop_latencies = []
        self.queue_ids = []
        self.queue_occups = []
        self.ingress_tstamps = []
        self.egress_tstamps = []
        self.l2_ingress_ports = []
        self.l2_egress_ports = []
        self.egress_tx_utils = []

        self.e_new_flow = None
        self.e_flow_latency = None
        self.e_sw_latency = None
        self.e_link_latency = None
        self.e_q_occupancy = None

    def show(self):
        print("src_ip %s" % (self.src_ip))
        print("dst_ip %s" % (self.dst_ip))
        print("src_port %s" % (self.src_port))
        print("dst_port %s" % (self.dst_port))
        print("ip_proto %s" % (self.ip_proto))

        print("hop_cnt %s" % (self.hop_cnt))
        print("flow_latency %s" % (self.flow_latency))
       
        #switch_ids
        if len(self.switch_ids) > 0:
            print("switch_ids %s" % (self.switch_ids))
        # l1_ingress_ports and l1_egress_ports
        if len(self.l1_ingress_ports) > 0:
            print("l1_ingress_ports %s" % (self.l1_ingress_ports))
            print("l1_egress_ports %s" % (self.l1_egress_ports))
        # hop_latencies
        if len(self.hop_latencies) > 0:
            print("hop_latencies %s" % (self.hop_latencies))
        # queue_ids and queue_occups
        if len(self.queue_ids) > 0:
            print("queue_ids %s" % (self.queue_ids))
            print("queue_occups %s" % (self.queue_occups))
        # ingress_tstamps and egress_tstamps
        if len(self.ingress_tstamps) > 0:
            print("ingress_tstamps %s" % (self.ingress_tstamps))
            print("egress_tstamps %s" % (self.egress_tstamps))
        # l2_ingress_ports and l2_egress_ports
        if len(self.l2_ingress_ports) > 0:
            print("l2_ingress_ports %s" % (self.l2_ingress_ports))
            print("l2_egress_ports %s" % (self.l2_egress_ports))
        # egress_tx_utils
        if len(self.egress_tx_utils) > 0:
            print("egress_tx_utils %s" % (self.egress_tx_utils))
    
    def __str__(self) -> str:
        pass


class Collector():
    def __init__(self,influx_client) -> None:
        self.influx_client = influx_client

    def parse_flow_info(self,flow_info,ip_pkt):
        flow_info.src_ip = ip_pkt.src
        flow_info.dst_ip = ip_pkt.dst
        flow_info.ip_proto = ip_pkt.proto

        if UDP in ip_pkt:
            flow_info.src_port = ip_pkt[UDP].sport
            flow_info.dst_port = ip_pkt[UDP].dport
        elif TCP in ip_pkt:
            flow_info.src_port = ip_pkt[TCP].sport
            flow_info.dst_port = ip_pkt[TCP].dport

    def parse_int_metadata(self,flow_info,int_pkt):
        if INTShim not in int_pkt:
            return
        # telemetry instructions
        ins_map = (int_pkt[INTMD].instruction_mask_0003 << 4) + int_pkt[INTMD].instruction_mask_0407
        # telemetry metadata length
        int_len = int_pkt.int_length-3
        # hop telemetry metadata length
        hop_meta_len = int_pkt[INTMD].HopMetaLength
        # telemetry metadata
        int_metadata = int_pkt.load[:int_len<<2]
        # hop count
        hop_count = int(int_len /hop_meta_len)
        flow_info.hop_cnt = hop_count

        hop_metadata = []

        for i in range(hop_count):
            index = i*hop_meta_len << 2
            hop_metadata = io.BytesIO(int_metadata[index:index+(hop_meta_len << 2)])
            # switch_ids
            if ins_map & SWITCH_ID_BIT:
                flow_info.switch_ids.append(int.from_bytes(hop_metadata.read(4), byteorder='big'))
            # ingress_ports and egress_ports
            if ins_map & L1_PORT_IDS_BIT:
                flow_info.l1_ingress_ports.append(int.from_bytes(hop_metadata.read(2), byteorder='big'))
                flow_info.l1_egress_ports.append(int.from_bytes(hop_metadata.read(2), byteorder='big'))
            # hop_latencies
            if ins_map & HOP_LATENCY_BIT:
                flow_info.hop_latencies.append(int.from_bytes(hop_metadata.read(4), byteorder='big'))
                flow_info.flow_latency += flow_info.hop_latencies[i]
            # queue_ids and queue_occups
            if ins_map & QUEUE_BIT:
                flow_info.queue_ids.append(int.from_bytes(hop_metadata.read(1), byteorder='big'))
                flow_info.queue_occups.append(int.from_bytes(hop_metadata.read(3), byteorder='big'))
            # ingress_tstamps
            if ins_map & INGRESS_TSTAMP_BIT:
                flow_info.ingress_tstamps.append(int.from_bytes(hop_metadata.read(8), byteorder='big'))
            # egress_tstamps
            if ins_map & EGRESS_TSTAMP_BIT:
                flow_info.egress_tstamps.append(int.from_bytes(hop_metadata.read(8), byteorder='big'))
            # l2_ingress_ports and l2_egress_ports
            if ins_map & L2_PORT_IDS_BIT:
                flow_info.l2_ingress_ports.append(int.from_bytes(hop_metadata.read(4), byteorder='big'))
                flow_info.l2_egress_ports.append(int.from_bytes(hop_metadata.read(4), byteorder='big'))
            # egress_tx_utils
            if ins_map & EGRESS_PORT_TX_UTIL_BIT:
                flow_info.egress_tx_utils.append(int.from_bytes(hop_metadata.read(4), byteorder='big'))

    def parser_int_pkt(self,pkt):
        if INTREP not in pkt:
            return
        int_rep_pkt = pkt[INTREP]
        # int_rep_pkt.show()

        flow_info = FlowInfo()
        # parse five tuple (src_ip,dst_ip,src_port,dst_port,ip_proto)
        self.parse_flow_info(flow_info,int_rep_pkt[IP])
        # int metadata
        int_shim_pkt = INTShim(int_rep_pkt.load)
        self.parse_int_metadata(flow_info,int_shim_pkt)
        sys.stdout.flush()

        return flow_info

    def export_influxdb(self,flow_info):
        if self.influx_client is None:
            print("collector.influx_client is Uninitialized")
            sys.exit(0)
        
        if not flow_info:
            return
        
        metric_timestamp = int(time.time()*1000000000)
        metrics = []
        if flow_info.flow_latency:
            metrics.append({
                    'measurement': 'flow_latency',
                    'tags': {
                        'src_ip': str(flow_info.src_ip),
                        'dst_ip': str(flow_info.dst_ip),
                        'src_port': flow_info.src_port,
                        'dst_port': flow_info.dst_port,
                        'protocol': flow_info.ip_proto
                    },
                    'time': metric_timestamp,
                    'fields': {
                        'value': flow_info.flow_latency
                    }
                })

        if len(flow_info.switch_ids) > 0 and len(flow_info.egress_tstamps) > 0 and len(flow_info.hop_latencies) > 0:
            for i in range(flow_info.hop_cnt):
                metrics.append({
                    'measurement': 'switch_latency',
                    'tags': {
                        'switch_id': flow_info.switch_ids[i]
                    },
                    'time': flow_info.egress_tstamps[i]*1000,
                    'fields': {
                        'value': flow_info.hop_latencies[i]
                    }
                })


        if len(flow_info.switch_ids) > 0 and len(flow_info.queue_ids) > 0:
            for i in range(flow_info.hop_cnt):
                metrics.append({
                    'measurement': 'queue_occupancy',
                    'tags': {
                        'switch_id': flow_info.switch_ids[i],
                        'queue_id': flow_info.queue_ids[i]
                    },
                    'time': flow_info.egress_tstamps[i]*1000,
                    'fields': {
                        'value': flow_info.queue_occups[i]
                    }
                })

        if len(flow_info.switch_ids) > 0 and len(flow_info.l1_egress_ports) > 0 and len(flow_info.l1_ingress_ports) > 0:
            for i in range(flow_info.hop_cnt - 1):
                metrics.append({
                    'measurement': 'link_latency',
                    'tags': {
                        'egress_switch_id': flow_info.switch_ids[i+1],
                        'egress_port_id': flow_info.l1_egress_ports[i+1],
                        'ingress_switch_id': flow_info.switch_ids[i],
                        'ingress_port_id': flow_info.l1_ingress_ports[i]
                    },
                    'time': metric_timestamp,
                    'fields': {
                        'value': abs(flow_info.egress_tstamps[i+1] - flow_info.ingress_tstamps[i])
                    }
                })
        
        self.influx_client.write_points(points=metrics, protocol="json")