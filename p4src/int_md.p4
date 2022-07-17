/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "include/defines.p4"
#include "include/headers.p4"
#include "include/int_headers.p4"
#include "include/parser.p4"
#include "include/checksum.p4"
#include "include/forward.p4"
#include "include/int_source.p4"
#include "include/int_transit.p4"
#include "include/int_sink.p4"


/*************************************************************************
****************  I N G R E S S   P R O C E S S I N G   ******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
    

    apply {
        if(hdr.ipv4.isValid()) {
            l3_forward.apply(hdr, local_metadata, standard_metadata);
        
            if(hdr.udp.isValid() ) {
                process_int_source_sink.apply(hdr, local_metadata, standard_metadata);
            }
            
            if (local_metadata.int_meta.source == true) {
                process_int_source.apply(hdr, local_metadata);
            } 

            if (local_metadata.int_meta.sink == true && hdr.int_header.isValid()) {
                // clone packet for Telemetry Report
                // clone3(CloneType.I2E, REPORT_MIRROR_SESSION_ID,standard_metadata);
                // clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
                local_metadata.perserv_meta.ingress_port = standard_metadata.ingress_port;
                local_metadata.perserv_meta.egress_port = standard_metadata.egress_port;
                local_metadata.perserv_meta.deq_qdepth = standard_metadata.deq_qdepth;
                local_metadata.perserv_meta.ingress_global_timestamp = standard_metadata.ingress_global_timestamp;
                clone_preserving_field_list(CloneType.I2E, REPORT_MIRROR_SESSION_ID, CLONE_FL_1);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyEgress(inout headers hdr,
                 inout local_metadata_t local_metadata,
                 inout standard_metadata_t standard_metadata) {
    
    apply {
        if(hdr.int_header.isValid()) {
            if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
                standard_metadata.ingress_port = local_metadata.perserv_meta.ingress_port;
                standard_metadata.egress_port = local_metadata.perserv_meta.egress_port;
                standard_metadata.deq_qdepth = local_metadata.perserv_meta.deq_qdepth;
                standard_metadata.ingress_global_timestamp = local_metadata.perserv_meta.ingress_global_timestamp;
            }

            process_int_transit.apply(hdr, local_metadata, standard_metadata);

            if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
                /* send int report */
                process_int_report.apply(hdr, local_metadata, standard_metadata);
            }

            if (local_metadata.int_meta.sink == true && standard_metadata.instance_type != PKT_INSTANCE_TYPE_INGRESS_CLONE) {
                process_int_sink.apply(hdr, local_metadata, standard_metadata);
            }
        }
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;