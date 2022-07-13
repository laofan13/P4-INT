#include "defines.p4"
#include "headers.p4"

control l3_forward(inout headers hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action drop(){
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_t dstAddr, port_t port) {
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
            
    }
}

control port_forward(inout headers hdr,
                       inout local_metadata_t local_metadata,
                       inout standard_metadata_t standard_metadata) {

    action send_to_cpu() {
        standard_metadata.egress_port = CPU_PORT;
        standard_metadata.egress_spec = CPU_PORT;
    }

    action set_egress_port(port_t port) {
        standard_metadata.egress_port = port;
        standard_metadata.egress_spec = port;
    }

    action drop(){
        mark_to_drop(standard_metadata);
    }

    table tb_port_forward {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            set_egress_port;
            send_to_cpu;
            drop;
        }
        const default_action = drop();
    }

    apply {
        tb_port_forward.apply();
     }
}