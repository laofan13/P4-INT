/* -*- P4_16 -*- */

control process_int_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action int_sink() {
        // restore original headers
        hdr.ipv4.dscp = hdr.intl4_shim.udp_ip_dscp;
        // restore length fields of IPv4 header and UDP header
        hdr.ipv4.len = hdr.ipv4.len - INT_TOTAL_HEADER_SIZE;
        if(hdr.udp.isValid()) {
            hdr.udp.length_ = hdr.udp.length_ - INT_TOTAL_HEADER_SIZE;
        }
        // remove all the INT information from the packet
        hdr.intl4_shim.setInvalid();
        hdr.int_header.setInvalid();
    }

    table tb_int_sink {
        actions = {
            int_sink;
        }
        default_action = int_sink();
    }

    apply {
        tb_int_sink.apply();
    }
}

control process_int_report (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    register<bit<22>>(1) seq_number;
    /********************** A C T I O N S **********************/

    action increment_counter() {
        bit<22> tmp;
        seq_number.read(tmp, 0);
        tmp = tmp + 1;
        seq_number.write(0, tmp);
    }

    action do_report_encapsulation(mac_t src_mac, mac_t mon_mac, ip_address_t src_ip,
            ip_address_t mon_ip, l4_port_t mon_port) {
        //Report Ethernet Header
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dst_addr = mon_mac;
        hdr.report_ethernet.src_addr = src_mac;
        hdr.report_ethernet.ether_type = ETH_TYPE_IPV4;

        //Report IPV4 Header
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = IP_VERSION_4;
        hdr.report_ipv4.ihl = IPV4_IHL_MIN;
        hdr.report_ipv4.dscp = 6w0;
        hdr.report_ipv4.ecn = 2w0;

        /* Total Len is report_ipv4_len + report_udp_len + report_fixed_hdr_len + ethernet_len + ipv4_totalLen */
        hdr.report_ipv4.len = (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_GROUP_HEADER_LEN + (bit<16>) REPORT_INDIVIDUAL_HEADER_LEN +
                              (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + 
                              INT_SHIM_HEADER_SIZE + (((bit<16>) hdr.intl4_shim.len)<< 2);

        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = REPORT_HDR_TTL;
        hdr.report_ipv4.protocol = IP_PROTO_UDP;
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;

        //Report UDP Header
        hdr.report_udp.setValid();
        hdr.report_udp.src_port = 1234;
        hdr.report_udp.dst_port = mon_port;
        hdr.report_udp.length_ = (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_GROUP_HEADER_LEN + (bit<16>) REPORT_INDIVIDUAL_HEADER_LEN +
                                 (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN +
                                 INT_SHIM_HEADER_SIZE + (((bit<16>) hdr.intl4_shim.len)<< 2);
        
        hdr.report_group_header.setValid();
        hdr.report_group_header.ver = 1;
        hdr.report_group_header.hw_id = HW_ID;
        seq_number.read(hdr.report_group_header.seq_no, 0);
        increment_counter();
        hdr.report_group_header.node_id = local_metadata.int_meta.switch_id;
        
        
        /* Telemetry Report Individual Header */
        hdr.report_individual_header.setValid();
        hdr.report_individual_header.rep_type = 1;
        hdr.report_individual_header.in_type = 4;
        hdr.report_individual_header.len = 0;
        hdr.report_individual_header.rep_md_len = 0;
        hdr.report_individual_header.d = 0;
        hdr.report_individual_header.q = 0;
        hdr.report_individual_header.f = 1;
        hdr.report_individual_header.i = 1;
        hdr.report_individual_header.rsvd = 0;

        /* Individual report inner contents */

        hdr.report_individual_header.rep_md_bits = 0;
        hdr.report_individual_header.domain_specific_id = 0;
        hdr.report_individual_header.domain_specific_md_bits = 0;
        hdr.report_individual_header.domain_specific_md_status = 0;

        truncate((bit<32>)hdr.report_ipv4.len + (bit<32>) ETH_HEADER_LEN);

    }

    table tb_generate_report {
        actions = {
            do_report_encapsulation;
            NoAction();
        }
        default_action = NoAction();
    }

    apply {
        tb_generate_report.apply();
    }
}

control process_int_header (
    inout headers hdr,
    inout local_metadata_t local_metadata) {
    
    action add_int_header(bit<4> ins_mask0003, bit<4> ins_mask0407) {

        hdr.intl4_shim.setValid();                              // insert INT shim header
        hdr.intl4_shim.int_type = 3;                            // int_type: Hop-by-hop type (1) , destination type (2), MX-type (3)
        hdr.intl4_shim.npt = 0;                                 // next protocol type: 0
        hdr.intl4_shim.len = INT_HEADER_WORD;                   // This is 3 from 0xC (INT_TOTAL_HEADER_SIZE >> 2)
        hdr.intl4_shim.udp_ip_dscp = hdr.ipv4.dscp;             // although should be first 6 bits of the second byte
        hdr.intl4_shim.udp_ip = 0;                              // although should be first 6 bits of the second byte
        
        // insert INT header
        hdr.int_header.setValid();
        hdr.int_header.ver = 2;
        hdr.int_header.d = 0;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0;               // bit 8 is buffer related, rest are reserved
        hdr.int_header.instruction_mask_1215 = 0;               // rsvd

        hdr.int_header.domain_specific_id = 0;                  // Unique INT Domain ID
        hdr.int_header.ds_instruction = 0;                      // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
        hdr.int_header.ds_flags = 0;                            // Domain specific flags

        // add the header len (3 words) to total len
        hdr.ipv4.len = hdr.ipv4.len + INT_TOTAL_HEADER_SIZE;

        if(hdr.udp.isValid()) {
            hdr.udp.length_ = hdr.udp.length_ + INT_TOTAL_HEADER_SIZE;
        }
        
        hdr.ipv4.dscp = DSCP_INT;
    }

    table tb_int_header {
        actions = {
            add_int_header;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    apply {
        tb_int_header.apply();
    }
}