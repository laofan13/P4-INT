# P4-INT

Implementation In­Band Network Telemetry in P4

<!-- GETTING STARTED -->
## Getting Started
### Prerequisites
* Mininet
  ```
    git clone https://github.com/mininet/mininet
    cd mininet

    sudo PYTHON=python3 mininet/util/install.sh -n
  ```
* P4
  
  For Ubuntu 20.04 and Ubuntu 21.04 it can be installed as follows:
  ```
    . /etc/os-release
    echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list
    curl -L "http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/Release.key" | sudo apt-key add -
    sudo apt-get update
    sudo apt install p4lang-p4c
  ```
* python3 Dependency package
  ```
    sudo pip3 install psutil networkx
  ```

### Installation

2. Clone the repo
   ```sh
   git clone https://gitee.com/lifengfan/p4-consisit.git
   ```
3. run
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
   python3 ./receive_check.py