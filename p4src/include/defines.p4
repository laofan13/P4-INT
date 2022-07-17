#ifndef __DEFINES__
#define __DEFINES__

//protocol type
#define ETH_TYPE_IPV4 0x0800
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17
#define IP_VERSION_4 4w4
#define IPV4_IHL_MIN 4w5
#define MAX_PORTS 511

//packet type
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<16> l4_port_t;
typedef bit<9>  port_t;
typedef bit<16> next_hop_id_t;
const port_t CPU_PORT = 255;

/* indicate INT by DSCP value */
const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3F;

typedef bit<48> timestamp_t;
typedef bit<32> switch_id_t;

const bit<8> INT_SHIM_HEADER_WORD = 1;
const bit<8> INT_HEADER_WORD = 3;
const bit<8> INT_TOTAL_HEADER_WORD = 4;

const bit<8> CPU_MIRROR_SESSION_ID = 250;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;
const bit<6> HW_ID = 1;
const bit<8> REPORT_HDR_TTL = 64;

#endif
