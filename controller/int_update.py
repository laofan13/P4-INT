#!/usr/bin/env python2

import argparse
import os, sys, json, subprocess, re, argparse
import grpc
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
    'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import p4runtime_lib.simple_controller as p4controller
import yaml

SOURCE = 0
TRANSIT = 1
SINK = 2

def push_rules(table_rules_file, switch, p4info_helper):
    sw_conf_file = open(table_rules_file, 'r')
    sw_conf = p4controller.json_load_byteified(sw_conf_file)
    if 'table_entries' in sw_conf:
        table_entries = sw_conf['table_entries']
        p4controller.info("Inserting table entries...")
        for entry in table_entries:
            p4controller.insertTableEntry(switch, entry, p4info_helper)

def write_int_rules(table_name, action_name, p4info_helper, addr, switch):
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields={
            "hdr.ipv4.dstAddr": (addr, 32)
        },
        action_name=action_name)
    switch.WriteTableEntry(table_entry)

def setup_source_instructions(switch, config, p4info_helper):
    instruction = 0
    for instruct in config['instructions']:
        if instruct == 'node_id':
            instruction |= 0b1
        if instruct == 'lv1_if_id':
            instruction |= 0b10
        if instruct == 'hop_latency':
            instruction |= 0b100
        if instruct == 'queue_id_occupancy':
            instruction |= 0b1000
        if instruct == 'ingress_timestamp':
            instruction |= 0b10000
        if instruct == 'egress_timestamp':
            instruction |= 0b100000
        if instruct == 'lv2_if_id':
            instruction |= 0b1000000
        if instruct == 'eg_if_tx_util':
            instruction |= 0b10000000
        if instruct == 'buffer_id_occupancy':
            instruction |= 0b100000000
    for dest in config['flows']:
        dstAddr = dest['ipv4_dest']
        dstPort = dest['port_dest']
        if dest['l4_proto'] == 'tcp':
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchEgress.add_int_hdr_tcp",
                match_fields={
                "hdr.ipv4.dstAddr": (dstAddr, 32),
                "hdr.tcp.dstPort" : (dstPort)
                },
                action_name="SwitchEgress.setup_int",
                action_params={
                    "instructionBitmap" : instruction
                }
            )
        elif dest['l4_proto'] == 'udp':
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchEgress.add_int_hdr_udp",
                match_fields={
                "hdr.ipv4.dstAddr": (dstAddr, 32),
                "hdr.udp.dstPort" : (dstPort)
                },
                action_name="SwitchEgress.setup_int",
                action_params={
                    "instructionBitmap" : instruction
                }
            )
        switch.WriteTableEntry(table_entry)

#roles : 0 source, 1 transit, 2 sink
def configure_switch(switch_name, switch_addr, device_id, p4file, switch_role, config_file):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper("%s.p4.p4info.txt" % p4file)
    try:
        #Creates a switch connection object
        #backed by a P4Runtime gRPC connection
        switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=switch_name,
            address=switch_addr,
            device_id=device_id,
            proto_dump_file='logs/%s-p4runtime-requests.txt' % switch_name)
        switch.MasterArbitrationUpdate()
        switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path="%s.json" % p4file)
        print "Installed P4 Program using SetForwardingPipelineConfig on %s" % switch_name
        #Basic forwarding rules
        push_rules("topo/%s-runtime.json"% switch_name, switch, p4info_helper)
        if switch_role == SINK:
            addr = config_file['collector']
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchEgress.add_node_id_hdr",
                match_fields={
                    "hdr.ipv4.dstAddr": (addr, 32)
                },
                action_name="SwitchEgress.add_node_id",
                action_params={
                    "switch_id": int(switch_name[1]),
                }
            )
            switch.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="SwitchIngress.report_int",
                match_fields={
                },
                action_name="SwitchIngress.reroute_int",
                action_params={
                    "mon_addr": addr,
                }
            )

        else:
            for dest in config_file['flows']:
                addr = dest['ipv4_dest']
                table_entry = p4info_helper.buildTableEntry(
                    table_name="SwitchEgress.add_node_id_hdr",
                    match_fields={
                        "hdr.ipv4.dstAddr": (addr, 32)
                    },
                    action_name="SwitchEgress.add_node_id",
                    action_params={
                        "switch_id": int(switch_name[1]),
                    }
                ) 
        switch.WriteTableEntry(table_entry)
        write_int_rules("SwitchEgress.add_lv1_if_id_hdr",
                        "SwitchEgress.add_lv1_if_id", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_hop_latency_hdr",
                        "SwitchEgress.add_hop_latency", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_queue_id_occupancy_hdr",
                        "SwitchEgress.add_queue_id_occupancy", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_ingress_timestamp_hdr",
                        "SwitchEgress.add_ingress_timestamp", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_egress_timestamp_hdr",
                        "SwitchEgress.add_egress_timestamp", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_lv2_if_id_hdr",
                        "SwitchEgress.add_lv2_if_id", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_eg_if_tx_util_hdr",
                        "SwitchEgress.add_eg_if_tx_util", 
                        p4info_helper, 
                        addr, 
                        switch)
        write_int_rules("SwitchEgress.add_buffer_id_occupancy_hdr",
                        "SwitchEgress.add_buffer_id_occupancy", 
                        p4info_helper, 
                        addr, 
                        switch)
        if switch_role != SOURCE:
            write_int_rules("SwitchEgress.update_int_hdrs",
                            "SwitchEgress.update_int_headers", 
                            p4info_helper, 
                            addr, 
                            switch)

        if switch_role == SOURCE: 
            #Source rules
            setup_source_instructions(switch, config_file, p4info_helper)
        elif switch_role == SINK:
            #Sink rules
            push_rules("topo/sink_rules.json", switch, p4info_helper)



    except grpc.RpcError as e:
        printGrpcError(e)

    print "Shutting down."

    ShutdownAllSwitchConnections()


def main(config_file):
    print "Opening config file %s" % config_file
    with open(config_file) as file:
        config = yaml.full_load(file)
        for switch in config['source']:
            print "Setting up %s as source" % switch
            configure_switch(switch, "127.0.0.1:5005%s" % switch[1], 
                             int(switch[1])-1, "build/source_switch", SOURCE, config)
        
        for switch in config['transit']:
            print "Setting up %s as transit" % switch
            configure_switch(switch, "127.0.0.1:5005%s" % switch[1],
                             int(switch[1])-1, "build/transit_switch", TRANSIT, config)

        for switch in config['sink']:
            print "Setting up %s as sink" % switch
            configure_switch(switch, "127.0.0.1:5005%s" % switch[1],
                             int(switch[1])-1, "build/sink_switch", SINK, config)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Config file for INT')
    parser.add_argument('--config', help='Configuration file',
                        type=str, action="store", required=False,
                        default='config/config.yaml')
    args = parser.parse_args()
    main(args.config)