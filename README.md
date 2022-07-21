# P4-INT
Implementation In­Band Network Telemetry in P4

<!-- GETTING STARTED -->
# Getting Started
This is an example of how you may give instructions on setting up your project locally. To get a local copy up and running follow these simple example steps.

## Prerequisites
### environment
* win10
* vm-ubuntu20.04

## Installation
1. install Mininet
    ```
      git clone https://github.com/mininet/mininet
      cd mininet

      sudo PYTHON=python3 mininet/util/install.sh -n
    ```
2. install P4
  
    For Ubuntu 20.04 and Ubuntu 21.04 it can be installed as follows:
    ```
      . /etc/os-release
      echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list
      curl -L "http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/Release.key" | sudo apt-key add -
      sudo apt-get update
      sudo apt install p4lang-p4c
    ```
3. python3 Dependency package
    ```
   sudo pip3 install psutil networkx
    ```
4. Influxdb
    ```sh
    sudo apt-get install influxdb
    sudo service influxdb start
    sudo pip3 install influxdb
    ```


## Usage

1. Clone the repo
   ```sh
   git clone https://gitee.com/lifengfan/p4-consisit.git
   ```
2. run
   ```sh
   make run
   ```
3. 在另外一个终端,启动环路检查
   ```sh
   sudo python3 receive_loop_report.py
   ```
4. 在mininet环境中，在h1中运行以下脚本
    ```sh
   python3 ./send.py --ip 10.0.1.1 --l4 udp --port 8080 --m "hello world !" --c 1
5. 在mininet环境中，在h2中运行以下脚本
    ```sh
    python3 ./receive_report.py
    ```

# influxdb operation
```sh
INSERT flow_latency,src_ip="10.0.1.1",dst_ip="10.0.3.2",src_port=1234,dst_port=1234,protocol=17 value=0.64
INSERT switch_latency,switch_id=1 value=0.64
INSERT queue_occupancy,switch_id=1,queue_id=1 value=0.1
INSERT link_latency,ingress_switch_id=2,ingress_port_id=1,egress_switch_id=1,egress_port_id=2 value=

SELECT * FROM flow_latency
drop measurement flow_latency
```