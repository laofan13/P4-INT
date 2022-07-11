7. On h1 run :
  - ./send.py --ip 10.0.2.2 --l4 udp --port 8080 --m "INT is nice !" --c 1
  - ./send.py --ip 10.0.3.3 --l4 udp --port 8080 --m "INT is cool !" --c 1

8. connect switch
  simple_switch_CLI --thrift-port 9090
  table_modify process_int_source.tb_int_source int_source 0  => 2 10 0xF 0x5


p4c --p4v 16  --p4runtime-files p4src/int.p4.p4info.txt -o p4src/int.p4 int.json
p4c --target bmv2 --arch v1model p4src/int.p4