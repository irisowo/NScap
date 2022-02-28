#! /usr/bin/python

import time

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Switch
from mininet.cli import CLI

class Router(Node):
    "Node with Linux Router Function"
    
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(Router, self).terminate()

def topology():
    net = Mininet(autoStaticArp=False)

    # Initialize objects dicts
    hosts, switches, routers = {}, {}, {}

    # Create Host, from h1 to h4
    h1 = net.addHost('h1',ip='10.0.0.1/8')
    GWr = net.addHost('GWr',ip='10.0.0.2/8')


    # Create Router, from r1 to r6
    r1 = net.addHost('r1', cls=Router)
    r2 = net.addHost('r2', cls=Router)
    BRG1 = net.addHost('BRG1', cls=Router)
    BRGr = net.addHost('BRGr', cls=Router)
    # link pairs
    links = [('h1', 'BRG1'), ('GWr', 'BRGr'),
             ('BRG1', 'r1'),
             ('BRGr', 'r2'),
             ('r1', 'r2')
            ]
    #create link
    for link in links:
        src, dst = link
        net.addLink(src, dst)

    net.start()

    # Configure network manually
    config(r1, r2, BRG1, BRGr, h1, GWr)

    CLI(net)

    net.stop()

def config(r1, r2, BRG1, BRGr, h1, GWr):

    # Hosts, Routers IP configuration
    r1.cmd('ifconfig r1-eth0 140.113.0.2/16')
    r1.cmd('ifconfig r1-eth1 20.0.0.1/8')

    r2.cmd('ifconfig r2-eth0 140.114.0.2/16')
    r2.cmd('ifconfig r2-eth1 20.0.0.2/8')

    BRG1.cmd('ifconfig BRG1-eth1 140.113.0.1/16')

    BRGr.cmd('ifconfig BRGr-eth1 140.114.0.1/16')

    # Host routing table configuration
    h1.cmd('ip route add default via 10.0.0.2 dev h1-eth0')

    # Router routing table configuration
    r1.cmd('route add -net 140.113.0.0/16 gw 140.113.0.1')
    r1.cmd('route add -net 140.114.0.0/16 gw 20.0.0.2')

    r2.cmd('route add -net 140.114.0.0/16 gw 140.114.0.1')
    r2.cmd('route add -net 140.113.0.0/16 gw 20.0.0.1')

    BRG1.cmd('ip route add 140.114.0.0/16 via 140.113.0.2')
    BRGr.cmd('ip route add 140.113.0.0/16 via 140.114.0.2')

    BRG1.cmd('ip link add GRE type gretap remote 140.114.0.1 local 140.113.0.1')
    BRG1.cmd('ip link set GRE up')
    BRG1.cmd('ip link add br0 type bridge')
    BRG1.cmd('brctl addif br0 BRG1-eth0')
    BRG1.cmd('brctl addif br0 GRE')
    BRG1.cmd('ip link set br0 up')

    BRGr.cmd('ip link add GRE type gretap remote 140.113.0.1 local 140.114.0.1')
    BRGr.cmd('ip link set GRE up')
    BRGr.cmd('ip link add br0 type bridge')
    BRGr.cmd('brctl addif br0 BRGr-eth0')
    BRGr.cmd('brctl addif br0 GRE')
    BRGr.cmd('ip link set br0 up')
    



if __name__ == '__main__':
    topology()
