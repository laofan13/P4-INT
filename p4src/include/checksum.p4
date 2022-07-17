#include "headers.p4"
#include "int_headers.p4"

control MyVerifyChecksum(inout headers hdr, inout local_metadata_t local_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers hdr, inout local_metadata_t local_metadata){
    apply{
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );


        // #ifdef __INT_HEADERS__
        // update_checksum(hdr.report_ipv4.isValid(),
        //     {
        //         hdr.report_ipv4.version,
        //         hdr.report_ipv4.ihl,
        //         hdr.report_ipv4.dscp,
        //         hdr.report_ipv4.ecn,
        //         hdr.report_ipv4.len,
        //         hdr.report_ipv4.identification,
        //         hdr.report_ipv4.flags,
        //         hdr.report_ipv4.frag_offset,
        //         hdr.report_ipv4.ttl,
        //         hdr.report_ipv4.protocol,
        //         hdr.report_ipv4.src_addr,
        //         hdr.report_ipv4.dst_addr
        //     },
        //     hdr.report_ipv4.hdr_checksum,
        //     HashAlgorithm.csum16
        // );
        // #endif // __INT_HEADERS__
    }
}