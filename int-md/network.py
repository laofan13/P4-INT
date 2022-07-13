import argparse
from p4utils.mininetlib.network_API import NetworkAPI

default_rule = 'rules/default/'

def config_network(p4):
    net = NetworkAPI()

    # Network general options
    net.setLogLevel('info')
    net.enableCli()

    # Network definition
    net.addP4Switch('s1',cli_input= default_rule + 's1-commands.txt')
    net.addP4Switch('s2',cli_input= default_rule + 's2-commands.txt')
    net.addP4Switch('s3',cli_input= default_rule + 's3-commands.txt')

    net.setP4SourceAll(p4)

    net.addHost('h1')
    net.addHost('h2')

    net.addLink('h1', 's1')
    net.addLink('h2', 's3')
    net.addLink('s1', 's2')
    net.addLink('s2', 's3')

    # Assignment strategy
    net.mixed()

    # Nodes general options
    net.enableCpuPortAll()
    net.enablePcapDumpAll()
    net.enableLogAll()

    return net


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--p4', help='p4 src file.',
                        type=str, required=False, default='p4src/int_mri.p4')
                        
    return parser.parse_args()


def main():
    args = get_args()
    net = config_network(args.p4)
    net.startNetwork()


if __name__ == '__main__':
    main()