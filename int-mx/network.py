from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

#source Dirs
rules = "./rules/"
p4src = "./p4src/"

# Network general options
net.setLogLevel('info')
net.enableCli()

# Network definition
net.addP4Switch('s1', cli_input= rules + 's1-commands.txt')
net.addP4Switch('s2', cli_input= rules + 's2-commands.txt')
net.addP4Switch('s3', cli_input= rules + 's3-commands.txt')

net.setP4SourceAll(p4src + "int_mx.p4")

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')

net.addLink('h1', 's1')
net.addLink('h2', 's3')
net.addLink('h3', 's3')

net.addLink('s1', 's2',addr1="00:01:0a:00:03:04",addr2="00:01:0a:00:03:05")
net.addLink('s2', 's3',addr1="00:01:0a:00:03:06",addr2="00:01:0a:00:03:07")

# Assignment strategy
net.mixed()

# Nodes general options
net.enableCpuPortAll()
net.enablePcapDumpAll()
net.enableLogAll()

# Start the network
net.startNetwork()