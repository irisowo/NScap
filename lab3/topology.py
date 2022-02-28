#! /usr/bin/python

import time
import os
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
    net = Mininet(autoStaticArp=True)

    # Initialize objects dicts
    hosts, switches, routers = {}, {}, {}

    # Create Host, from h1 to h3
    h1 = net.addHost('h1',ip='0.0.0.0/0', )
    h2 = net.addHost('h2',ip='192.168.1.65/26', defaultRoute='192.168.1.126/26')
    h3 = net.addHost('h3',ip='192.168.1.66/26', defaultRoute='192.168.1.126/26')
    h4 = net.addHost('h4',ip='140.114.0.1/24', defaultRoute='140.114.0.2/24')

    # Create DHCP server
    DHCPServer = net.addHost('DHCPServer')

    # Create Switch, from s1 to s2
    for i in range(2):
        switch = net.addSwitch('s%d' % (i + 1), failMode='standalone')
        switches['s%d' % (i + 1)] = switch

    # Create Router, from r1 to r4
    for i in range(4):
        router = net.addHost('r%d' % (i + 1), cls=Router)
        routers['r%d' % (i + 1)] = router

    # link pairs
    links = [('r2', 'r3'), ('r2', 'r1'),
             ('r3', 'r4'), ('r1', 's1'),
             ('r1', 's2'), ('r4', 'h4'),
             ('s1', 'h1'), ('s1', 'DHCPServer'),
             ('s2', 'h2'), ('h3', 's2')
            ]
    #create link
    for link in links:
        src, dst = link
        net.addLink(src, dst)

    net.start()
    config(routers, h2, h3, h4, DHCPServer)
    runBGP(routers)
    runDHCP(net) # if your dhcpd.conf is done, uncomment this line
    runNAT(routers['r1'])
    h1.cmd('dhclient h1-eth0')
    CLI(net)
    killDHCP(net) # don't leave dhcp process
    killBGP() #dont leave bgp process
    net.stop()

def config(routers, h2, h3, h4, DHCPServer):
    DHCPServer.cmd('ifconfig DHCPServer-eth0 192.168.1.4/26')
    h2.cmd('route add default gw 192.168.1.126')
    h3.cmd('route add default gw 192.168.1.126')
    h4.cmd('route add default gw 140.114.0.2')
    routers['r1'].cmd('ifconfig r1-eth0 10.0.1.2/24')
    routers['r1'].cmd('ifconfig r1-eth1 192.168.1.62/26')
    routers['r1'].cmd('ifconfig r1-eth2 192.168.1.126/26')
    routers['r2'].cmd('ifconfig r2-eth0 10.0.0.1/24')
    routers['r2'].cmd('ifconfig r2-eth1 10.0.1.1/24')
    routers['r3'].cmd('ifconfig r3-eth0 10.0.0.2/24')
    routers['r3'].cmd('ifconfig r3-eth1 10.0.2.1/24')
    routers['r4'].cmd('ifconfig r4-eth0 10.0.2.3/24')
    routers['r4'].cmd('ifconfig r4-eth1 140.114.0.2/24')


def runBGP(routers):

    routers['r1'].cmd('zebra -f ./configs/zebra.conf -d -i /var/run/quagga/zebrar1.pid')
    routers['r1'].cmd('bgpd -f ./configs/bgp_r1.conf -d -i /var/run/quagga/bgpdr1.pid')
    routers['r2'].cmd('zebra -f ./configs/zebra.conf -d -i /var/run/quagga/zebrar2.pid')
    routers['r2'].cmd('bgpd -f ./configs/bgp_r2.conf -d -i /var/run/quagga/bgpdr2.pid')
    routers['r3'].cmd('zebra -f ./configs/zebra.conf -d -i /var/run/quagga/zebrar3.pid')
    routers['r3'].cmd('bgpd -f ./configs/bgp_r3.conf -d -i /var/run/quagga/bgpdr3.pid')
    routers['r4'].cmd('zebra -f ./configs/zebra.conf -d -i /var/run/quagga/zebrar4.pid')
    routers['r4'].cmd('bgpd -f ./configs/bgp_r4.conf -d -i /var/run/quagga/bgpdr4.pid')

def killBGP():
    print("[-] Killing BGP")
    os.system("sudo kill -9 `cat /var/run/quagga/bgpdr1.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/bgpdr2.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/bgpdr3.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/bgpdr4.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/zebrar1.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/zebrar2.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/zebrar3.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/zebrar4.pid`")

def runDHCP(net):
    #Run DHCP server on node DHCPServer
    print("[+] Run DHCP server")
    dhcp = net.getNodeByName('DHCPServer')
    dhcp.cmdPrint('/usr/sbin/dhcpd 4 -pf /run/dhcp-server-dhcpd.pid -cf ./dhcpd.conf %s' % dhcp.defaultIntf())

def killDHCP(net):
    #Kill DHCP server process
    dhcp = net.getNodeByName('DHCPServer')
    print("[-] Killing DHCP server")
    dhcp.cmdPrint("kill -9 `ps aux | grep DHCPServer-eth0 | grep dhcpd | awk '{print $2}'`")


def runNAT(r1):
    r1.cmd('iptables -X')

    r1.cmd('iptables -t nat -A POSTROUTING -s 192.168.1.0/26 -d 140.114.0.0/24 -j SNAT --to-source 140.113.0.30')

    r1.cmd('iptables -t nat -A POSTROUTING -s 192.168.1.64/26 -d 140.114.0.0/24 -j SNAT --to-source 140.113.0.40')

    r1.cmd('iptables -t nat -A PREROUTING -d 140.113.0.40 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.66:8000')



if __name__ == '__main__':
    topology()


