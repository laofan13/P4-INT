control process_int_transit (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action init_metadata(switch_id_t switch_id) {
        local_metadata.int_meta.transit = true;
        local_metadata.int_meta.switch_id = switch_id;
    }

    action int_set_header_0() { //switch_id
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = local_metadata.int_meta.switch_id;
    }
    
    action int_set_header_1() { //level1_port_id
        hdr.int_level1_port_ids.setValid();
        hdr.int_level1_port_ids.ingress_port_id = (bit<16>) standard_metadata.ingress_port;
        hdr.int_level1_port_ids.egress_port_id = (bit<16>) standard_metadata.egress_port;
    }
   
    action int_set_header_2() { //hop_latency
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>) standard_metadata.egress_global_timestamp - (bit<32>) standard_metadata.ingress_global_timestamp;
    }
  
    action int_set_header_3() { //q_occupancy
        // TODO: Support egress queue ID
        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id =0;
        // (bit<8>) standard_metadata.egress_qid;
        hdr.int_q_occupancy.q_occupancy = (bit<24>) standard_metadata.deq_qdepth;
    }
  
    action int_set_header_4() { //ingress_tstamp
        hdr.int_ingress_tstamp.setValid();
        hdr.int_ingress_tstamp.ingress_tstamp = (bit<64>)standard_metadata.ingress_global_timestamp;
    }
   
    action int_set_header_5() { //egress_timestamp
        hdr.int_egress_tstamp.setValid();
        hdr.int_egress_tstamp.egress_tstamp = (bit<64>)standard_metadata.egress_global_timestamp;
    }
   
    action int_set_header_6() { //level2_port_id
        hdr.int_level2_port_ids.setValid();
        // level2_port_id indicates Logical port ID
        hdr.int_level2_port_ids.ingress_port_id = (bit<32>) standard_metadata.ingress_port;
        hdr.int_level2_port_ids.egress_port_id = (bit<32>) standard_metadata.egress_port;
     }
   
    action int_set_header_7() { //egress_port_tx_utilization
        // TODO: implement tx utilization support in BMv2
        hdr.int_egress_tx_util.setValid();
        hdr.int_egress_tx_util.egress_port_tx_util =
        // (bit<32>) queueing_metadata.tx_utilization;
        0;
    }

    // Actions to keep track of the new metadata added.
   
    action add_1() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 1;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 4;
    }

    
    action add_2() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 2;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 8;
    }

    
    action add_3() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 3;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 12;
    }

   
    action add_4() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 4;
       local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 16;
    }

    action add_5() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 5;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 20;
    }

    action add_6() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 6;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 24;
    }

    action add_7() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 7;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 28;
    }
     /* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
     /* Each bit set indicates that corresponding INT header should be added */
    
     action int_set_header_0003_i0() {
     }
    
     action int_set_header_0003_i1() {
        int_set_header_3();
        add_1();
    }
    
    action int_set_header_0003_i2() {
        int_set_header_2();
        add_1();
    }
    
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
        add_2();
    }
    
    action int_set_header_0003_i4() {
        int_set_header_1();
        add_1();
    }
   
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
        add_2();
    }
    
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
        add_2();
    }
    
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        add_3();
    }
    
    action int_set_header_0003_i8() {
        int_set_header_0();
        add_1();
    }
    
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
        add_2();
    }
    
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
        add_2();
    }
    
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
        add_3();
    }
    
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
        add_2();
    }
   
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_4();
    }

     /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    action int_set_header_0407_i0() {
    }
    
    action int_set_header_0407_i1() {
        int_set_header_7();
        add_1();
    }
    
    action int_set_header_0407_i2() {
        int_set_header_6();
        add_2();
    }
    
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
        add_3();
    }
    
    action int_set_header_0407_i4() {
        int_set_header_5();
        add_2();
    }
    
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
        add_3();
    }
    
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
        add_4();
    }
    
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        add_5();
    }
    
    action int_set_header_0407_i8() {
        int_set_header_4();
        add_2();
    }
    
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
        add_3();
    }
    
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
        add_4();
    }
    
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
        add_5();
    }
    
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
        add_4();
    }
   
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
        add_5();
    }
    
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_6();
    }
    
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_7();
    }

    // Default action used to set switch ID.
    table tb_int_insert {
        actions = {
            init_metadata;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    /* Table to process instruction bits 0-3 */
    table tb_int_inst_0003 {
        key = {
            hdr.int_header.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        
        const entries = {
            (0x0) : int_set_header_0003_i0();
            (0x1) : int_set_header_0003_i1();
            (0x2) : int_set_header_0003_i2();
            (0x3) : int_set_header_0003_i3();
            (0x4) : int_set_header_0003_i4();
            (0x5) : int_set_header_0003_i5();
            (0x6) : int_set_header_0003_i6();
            (0x7) : int_set_header_0003_i7();
            (0x8) : int_set_header_0003_i8();
            (0x9) : int_set_header_0003_i9();
            (0xA) : int_set_header_0003_i10();
            (0xB) : int_set_header_0003_i11();
            (0xC) : int_set_header_0003_i12();
            (0xD) : int_set_header_0003_i13();
            (0xE) : int_set_header_0003_i14();
            (0xF) : int_set_header_0003_i15();
        }
    }

    /* Table to process instruction bits 4-7 */
     table tb_int_inst_0407 {
        key = {
            hdr.int_header.instruction_mask_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        
        const entries = {
            (0x0) : int_set_header_0407_i0();
            (0x1) : int_set_header_0407_i1();
            (0x2) : int_set_header_0407_i2();
            (0x3) : int_set_header_0407_i3();
            (0x4) : int_set_header_0407_i4();
            (0x5) : int_set_header_0407_i5();
            (0x6) : int_set_header_0407_i6();
            (0x7) : int_set_header_0407_i7();
            (0x8) : int_set_header_0407_i8();
            (0x9) : int_set_header_0407_i9();
            (0xA) : int_set_header_0407_i10();
            (0xB) : int_set_header_0407_i11();
            (0xC) : int_set_header_0407_i12();
            (0xD) : int_set_header_0407_i13();
            (0xE) : int_set_header_0407_i14();
            (0xF) : int_set_header_0407_i15();
        }
    }

    apply {
        tb_int_insert.apply();
        if (local_metadata.int_meta.transit == false) {
            return;
        }
        tb_int_inst_0003.apply();
        tb_int_inst_0407.apply();

        // Decrement remaining hop cnt
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;

        // Update headers lengths.
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.len = hdr.ipv4.len + local_metadata.int_meta.new_bytes;
        }
        if (hdr.udp.isValid()) {
            hdr.udp.length_ = hdr.udp.length_ + local_metadata.int_meta.new_bytes;
        }
        if (hdr.intl4_shim.isValid()) {
            hdr.intl4_shim.len = hdr.intl4_shim.len + local_metadata.int_meta.new_words;
        }
    }
}