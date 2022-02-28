#! /usr/bin/python
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Switch
from mininet.cli import CLI

def topology():
    net = Mininet()

    #add nodes and links
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    s1 = net.addSwitch('s1',failMode = 'standalone')
    s2 = net.addSwitch('s2',failMode = 'standalone')
    s3 = net.addSwitch('s3',failMode = 'standalone')
    s4 = net.addSwitch('s4',failMode = 'standalone')
    net.addLink('h1','s1')
    net.addLink('h2','s1')
    net.addLink('h3','s3')
    net.addLink('h4','s3')
    net.addLink('s1','s2')
    net.addLink('s3','s2')
    net.addLink('s1','s4')
    net.addLink('s3','s4')

    net.start()
    CLI(net)  #enter mininet CLI
    net.stop()
if __name__ == '__main__':
    topology()
