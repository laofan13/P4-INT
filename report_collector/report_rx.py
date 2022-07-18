import io, sys, signal, time, socket

from prometheus_client import start_http_server, Gauge

# ethernet(14B) + IP(20B) + UDP(8B)
UDP_OFFSET = 14 + 20 + 8
# ethernet(14B) + IP(20B) + TCP(20B)
TCP_OFFSET = 14 + 20 + 20

SWITCH_ID_BIT =             0b10000000
L1_PORT_IDS_BIT =           0b01000000
HOP_LATENCY_BIT =           0b00100000
QUEUE_BIT =                 0b00010000
INGRESS_TSTAMP_BIT =        0b00001000
EGRESS_TSTAMP_BIT =         0b00000100
L2_PORT_IDS_BIT =           0b00000010
EGRESS_PORT_TX_UTIL_BIT =   0b00000001

# host,port for UDP report receiver
HOST = ''
PORT = 9555

HOP_METADATA = (
    'switch_id',
    'l1_ingress_port_id',
    'l1_egress_port_id',
    'hop_latency',
    'q_id',
    'q_occupancy',
    'ingress_tstamp',
    'egress_tstamp',
    'l2_ingress_port_id',
    'l2_egress_port_id',
    'egress_port_tx_util'
)

# prometheus metric
FLOW_METRICS = Gauge(
    "flow_info", "Flow metrics",
    ['src_ip','dst_ip','src_port','dst_port','protocol','switch_id','metadata']
)

DEBUG = False
TIMER = False

###### CLASSESS ###############################################################

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
        print('received hop metadata:', data)
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
            hop.ingress_tstamp = int.from_bytes(d.read(4), byteorder='big')
        if ins_map & EGRESS_TSTAMP_BIT:
            hop.egress_tstamp = int.from_bytes(d.read(4), byteorder='big')
        if ins_map & L2_PORT_IDS_BIT:
            hop.l2_ingress_port_id = int.from_bytes(d.read(4), byteorder='big')
            hop.l2_egress_port_id = int.from_bytes(d.read(4), byteorder='big')
        if ins_map & EGRESS_PORT_TX_UTIL_BIT:
            hop.egress_port_tx_util = int.from_bytes(d.read(4), byteorder='big')
        return hop

    def __str__(self):
        return str(vars(self))

class Report():
    def __init__(self,  ):
        # report header
        hdr = data[:16]
        self.ver = hdr[0] >> 4
        self.len = hdr[0] & 0x0f
        self.nprot = hdr[1] >> 5
        self.rep_md_bits = (hdr[1] & 0x1f) + (hdr[2] >> 7)
        self.d = hdr[2] & 0x01
        self.q = hdr[3] >> 7
        self.f = (hdr[3] >> 6) & 0x01
        self.hw_id = hdr[3] & 0x3f
        self.switch_id = int.from_bytes(hdr[4:8], byteorder='big')
        self.seq_num = int.from_bytes(hdr[8:12], byteorder='big')
        self.ingress_tstamp = int.from_bytes(hdr[12:16], byteorder='big')

        # flow id
        ip_hdr = data[30:50]
        udp_hdr = data[50:58]
        protocol = ip_hdr[9]
        self.flow_id = (
            ip_hdr[12:16],  # src_ip
            ip_hdr[16:20],  # dst_ip
            udp_hdr[:2],    # src_port
            udp_hdr[2:4],   # dst_port
            ip_hdr[9]       # protocol
        )

        # check next protocol
        # offset: udp/tcp + report header(16B)
        offset = 16
        if protocol == 17:
            offset = offset + UDP_OFFSET
        if protocol == 6:
            offset = offset + TCP_OFFSET

        # int shim
        self.int_shim = data[offset:offset + 4]
        self.int_data_len = int(self.int_shim[2]) - 3

        # int header
        self.int_hdr = data[offset + 4:offset + 12]
        self.hop_data_len = int(self.int_hdr[2] & 0x1f)
        self.ins_map = int.from_bytes(self.int_hdr[4:6], byteorder='big')
        self.hop_count = int(self.int_data_len / self.hop_data_len)

        # int metadata
        self.int_meta = data[offset + 12:]
        print(self.int_meta)
        self.hop_metadata = []
        for i in range(self.hop_count):
            metadata_source = self.int_meta[i*self.hop_data_len*4:(i+1)*self.hop_data_len*4]
            print(metadata_source)
            self.hop_metadata.append(HopMetadata.from_bytes(metadata_source, self.ins_map))

    def __str__(self):
        hop_info = ''
        for hop in self.hop_metadata:
            hop_info += str(hop) + '\n'
        return "sw: {} seq: {} tstamp: {} ins_map: {} \n {}".format(
            self.switch_id,
            self.seq_num,
            self.ingress_tstamp,
            self.ins_map,
            hop_info
        )

class FlowInfo():

    def __init__(self):
        # flow id - 5 tuple: (src_ip, dst_ip, src_port, dst_port, ip_proto)
        self.flow_id = None
        self.hop_cnt = 0
        
        self.switch_ids = []
        self.l1_ingress_port_ids = []
        self.l1_egress_port_ids = []
        self.hop_latencies = []
        self.q_ids = []
        self.q_occups = []
        self.ingress_tstamps = []
        self.egress_tstamps = []
        self.l2_ingress_port_ids = []
        self.l2_egress_port_ids = []
        self.egress_port_tx_utils = []

    @staticmethod
    def from_report(report: Report):
        flow = FlowInfo()
        flow.flow_id = report.flow_id
        flow.hop_cnt = len(report.hop_metadata)
        
        for hop in report.hop_metadata:
            if hop.switch_id is not None:
                flow.switch_ids.append(hop.switch_id)
            if hop.l1_ingress_port_id is not None:
                flow.l1_ingress_port_ids.append(hop.l1_ingress_port_id)
            if hop.l1_egress_port_id is not None:
                flow.l1_egress_port_ids.append(hop.l1_egress_port_id)
            if hop.hop_latency is not None:
                flow.hop_latencies.append(hop.hop_latency)
            if hop.q_id is not None:
                flow.q_ids.append(hop.q_id)
                flow.q_occups.append(hop.q_occupancy)
            if hop.ingress_tstamp is not None:
                flow.ingress_tstamps.append(hop.ingress_tstamp)
            if hop.egress_tstamp is not None:
                flow.egress_tstamps.append(hop.egress_tstamp)
            if hop.l2_ingress_port_id is not None:
                flow.l2_ingress_port_ids.append(hop.l2_ingress_port_id)
                flow.l2_egress_port_ids.append(hop.l2_egress_port_id)
            if hop.egress_port_tx_util is not None:
                flow.egress_port_tx_utils.append(hop.egress_port_tx_util)

        return flow

    def __str__(self):
        return str(vars(self))

class Collector():

    def __init__(self):
        self.flow_table = {}

class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True
        print("Got signal, quitting")

###### FUNCTIONS ##############################################################

def ip2str(ip):
    return "{}.{}.{}.{}".format(ip[0],ip[1],ip[2],ip[3])

def receiver():
    collector = Collector()
    killer = GracefulKiller()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        try:
            while not killer.kill_now:
                data, addr = s.recvfrom(512)
                if TIMER: t1 = time.time()
                rep = Report(data)
                if DEBUG:
                    print("-- Received report from {} --------".format(addr))
                    print(rep)
                
                new_flow = FlowInfo.from_report(rep)
                collector.flow_table[new_flow.flow_id] = new_flow
                if DEBUG: print(new_flow)

                for hop in range(new_flow.hop_cnt):
                    if new_flow.switch_ids:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='hop_num'
                        ).set(str(hop))
                    if new_flow.l1_ingress_port_ids:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='l1_ingress_port_id'
                        ).set(new_flow.l1_ingress_port_ids[hop])
                    if new_flow.l1_egress_port_ids:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='l1_egress_port_id'
                        ).set(new_flow.l1_egress_port_ids[hop])
                    if new_flow.hop_latencies:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='hop_latency'
                        ).set(new_flow.hop_latencies[hop])
                    if new_flow.q_ids:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='q_id'
                        ).set(new_flow.q_ids[hop])
                    if new_flow.q_occups:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='q_occupancy'
                        ).set(new_flow.q_occups[hop])
                    if new_flow.ingress_tstamps:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='ingress_tstamp'
                        ).set(new_flow.ingress_tstamps[hop])
                    if new_flow.egress_tstamps:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='egress_tstamp'
                        ).set(new_flow.egress_tstamps[hop])
                    if new_flow.l2_ingress_port_ids:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='l2_ingress_port_id'
                        ).set(new_flow.l2_ingress_port_ids[hop])
                    if new_flow.l2_egress_port_ids:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='l2_egress_port_id'
                        ).set(new_flow.l2_egress_port_ids[hop])
                    if new_flow.egress_port_tx_utils:
                        FLOW_METRICS.labels(
                                src_ip=ip2str(new_flow.flow_id[0]),
                                dst_ip=ip2str(new_flow.flow_id[1]),
                                src_port=str(int.from_bytes(new_flow.flow_id[2], byteorder='big')),
                                dst_port=str(int.from_bytes(new_flow.flow_id[3], byteorder='big')),
                                protocol=str(int(new_flow.flow_id[4])),
                                switch_id=new_flow.switch_ids[hop],
                                metadata='egress_port_tx_utils'
                        ).set(new_flow.egress_port_tx_utils[hop])
                if TIMER:
                    t2 = time.time()
                    print("\rReports per second: {}".format(1/(t2-t1)), end='')
        
        except KeyboardInterrupt:
            s.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == '--debug': DEBUG = True
        if sys.argv[1] == '--time': TIMER = True

    start_http_server(8000)
    receiver()
