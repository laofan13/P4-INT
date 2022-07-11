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
        
            if(hdr.tcp.isValid() ||hdr.udp.isValid() ) {
                process_int_source_sink.apply(hdr, local_metadata, standard_metadata);
            }
            
            if (local_metadata.int_meta.source == _TRUE) {
                process_int_source.apply(hdr, local_metadata);
            } 

            if (hdr.int_header.isValid()) {
                // clone packet for Telemetry Report
                // clone3(CloneType.I2E, REPORT_MIRROR_SESSION_ID,standard_metadata);
                clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
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
        // if(hdr.int_header.isValid() ) {

        //     if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
        //         /* send int report */
        //         if (local_metadata.int_meta.source == _TRUE) {
        //             process_int_source.apply(hdr, local_metadata);
        //         } 
        //         process_int_transit.apply(hdr, local_metadata, standard_metadata);
        //         process_int_report.apply(hdr, local_metadata, standard_metadata);
        //     }

        //     if (local_metadata.int_meta.sink == _TRUE && standard_metadata.instance_type != PKT_INSTANCE_TYPE_EGRESS_CLONE) {
        //         process_int_sink.apply(hdr, local_metadata, standard_metadata);
        //     }
        // }
        if(hdr.int_header.isValid() && standard_metadata.instance_type != PKT_INSTANCE_TYPE_INGRESS_CLONE ) {
            if (local_metadata.int_meta.sink == _TRUE ) {
                process_int_sink.apply(hdr, local_metadata, standard_metadata);
            }
        }

        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
                /* send int report */
            if (hdr.int_header.isValid() == _FALSE) {
                process_int_header.apply(hdr, local_metadata);
            } 
            process_int_transit.apply(hdr, local_metadata, standard_metadata);
            process_int_report.apply(hdr, local_metadata, standard_metadata);
        }
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    Int_Parser(),
    SwitchVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    SwitchComputeChecksum(),
    Int_Deparser()
) main;