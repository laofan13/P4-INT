#include "defines.p4"
#include "headers.p4"

#ifndef __INT_HEADERS__
#define __INT_HEADERS__

// INT shim header for TCP/UDP
header intl4_shim_t {
    bit<4> int_type;                // Type of INT Header
    bit<2> npt;                     // Next protocol type
    bit<2> rsvd;                    // Reserved
    bit<8> len;                     // Length of INT Metadata header and INT stack in 4-byte words, not including the shim header (1 word)
    bit<6> udp_ip_dscp;            // depends on npt field. either original dscp, ip protocol or udp dest port
    bit<10> udp_ip;                // depends on npt field. either original dscp, ip protocol or udp dest port
}

const bit<16> INT_SHIM_HEADER_SIZE = 4;

// INT header
header int_header_t {
    bit<4>   ver;                    // Version
    bit<1>   d;                      // Discard
    bit<27>  rsvd;                   // 12 bits reserved, set to 0                  
    bit<4>   instruction_mask_0003;  /* split the bits for lookup */
    bit<4>   instruction_mask_0407;
    bit<4>   instruction_mask_0811;
    bit<4>   instruction_mask_1215;
    bit<16>  domain_specific_id;     // Unique INT Domain ID
    bit<16>  ds_instruction;         // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
    bit<16>  ds_flags;               // Domain specific flags
    // Optional domain specific 'source only' metadata
}

const bit<16> INT_HEADER_SIZE = 12;

const bit<16> INT_TOTAL_HEADER_SIZE = INT_HEADER_SIZE + INT_SHIM_HEADER_SIZE;


// INT meta-value headers - different header for each value type
header int_switch_id_t {
    bit<32> switch_id;
}
header int_level1_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}
header int_hop_latency_t {
    bit<32> hop_latency;
}
header int_q_occupancy_t {
    bit<8> q_id;
    bit<24> q_occupancy;
}
header int_ingress_tstamp_t {
    bit<64> ingress_tstamp;
}
header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}
header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

// these two not implemented yet
header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}
header int_buffer_t {
    bit<8> buffer_id;
    bit<24> buffer_occupancy;
}

// Report Telemetry Headers
header report_group_header_t {
    bit<4>  ver;
    bit<6>  hw_id;
    bit<22> seq_no;
    bit<32> node_id;
}

const bit<8> REPORT_GROUP_HEADER_LEN = 8;

header report_individual_header_t {
    bit<4>  rep_type;
    bit<4>  in_type;
    bit<8>  len;
    bit<8>  rep_md_len;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<1>  i;
    bit<4>  rsvd;
    // Individual report inner contents for Reptype 1 = INT
    bit<16> rep_md_bits;
    bit<16> domain_specific_id;
    bit<16> domain_specific_md_bits;
    bit<16> domain_specific_md_status;
}
const bit<8> REPORT_INDIVIDUAL_HEADER_LEN = 12;

// Telemetry drop report header
header drop_report_header_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  drop_reason;
    bit<16> pad;
}
const bit<8> DROP_REPORT_HEADER_LEN = 12;

// Switch Local Report Header
header local_report_header_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  pad;
    bit<64> ingress_global_tstamp;
}

const bit<8> LOCAL_REPORT_HEADER_LEN = 16;


struct headers {

    // Original Packet Headers
    ethernet_t                  ethernet;
    ipv4_t			            ipv4;
    udp_t			            udp;
    tcp_t			            tcp;

    // INT Report Encapsulation
    ethernet_t                  report_ethernet;
    ipv4_t                      report_ipv4;
    udp_t                       report_udp;

    // INT Headers
    intl4_shim_t                intl4_shim;
    int_header_t                int_header;
    int_switch_id_t             int_switch_id;
    int_level1_port_ids_t       int_level1_port_ids;
    int_hop_latency_t           int_hop_latency;
    int_q_occupancy_t           int_q_occupancy;
    int_ingress_tstamp_t        int_ingress_tstamp;
    int_egress_tstamp_t         int_egress_tstamp;
    int_level2_port_ids_t       int_level2_port_ids;
    int_egress_port_tx_util_t   int_egress_tx_util;

    // // INT Report Headers
    report_group_header_t       report_group_header;
    report_individual_header_t  report_individual_header;
    local_report_header_t       local_report_header;
}

struct int_metadata_t {
    switch_id_t switch_id;
    bit<16> new_bytes;
    bit<8>  new_words;
    bool  source;
    bool  sink;
    bool  transit;
    bit<8> intl4_shim_len;
    bit<16> int_shim_len;
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    int_metadata_t int_meta;
}

#endif