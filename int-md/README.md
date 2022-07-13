
<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
There are many great README templates available on GitHub; however, I didn't find one that really suited my needs so I created this enhanced one. I want to create a README template so amazing that it'll be the last one you ever need -- I think this is it.

Here's why:
* Your time should be focused on creating something amazing. A project that solves a problem and helps others
* You shouldn't be doing the same tasks over and over like creating a README from scratch
* You should implement DRY principles to the rest of your life :smile:

Of course, no one template will serve all projects since your needs may be different. So I'll be adding more in the near future. You may also suggest changes by forking this repo and creating a pull request or opening an issue. Thanks to all the people have contributed to expanding this template!

<p align="right">(<a href="#top">back to top</a>)</p>



### Built With

The main dependencies of this project are as follows

* [Ubuntu 20.04](https://releases.ubuntu.com/20.04/)
* [Mininet](http://mininet.org/)
* [P4 Language](https://p4.org/)
* [P4Utils](https://github.com/nsg-ethz/p4-utils)

<p align="right">(<a href="#top">back to top</a>)</p>



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