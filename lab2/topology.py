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
    net = Mininet(autoStaticArp=True)

    # Initialize objects dicts
    hosts, switches, routers = {}, {}, {}

    # Create Host, from h1 to h5
    for i in range(5):
        host = net.addHost('h%d' % (i + 1), ip="0.0.0.0/0")
        hosts['h%d' % (i + 1)] = host

    # Create DHCP server
    DHCPServer = net.addHost('DHCPServer')

    # Create Switch, from s1 to s3
    for i in range(3):
        switch = net.addSwitch('s%d' % (i + 1), failMode='standalone')
        switches['s%d' % (i + 1)] = switch

    # Create Router, from r1 to r4
    for i in range(4):
        router = net.addHost('r%d' % (i + 1), cls=Router)
        routers['r%d' % (i + 1)] = router

    # link pairs
    links = [('r2', 'r3'), ('r2', 'r1'),
             ('r3', 'r4'), ('r1', 's1'),
             ('r1', 's2'), ('r4', 's3'),
             ('s1', 'h1'),('s1', 'DHCPServer'),
             ('s2', 'h2'), ('s2', 'h3'),
             ('s3', 'h4'), ('s3', 'h5')

            ]
    #create link
    for link in links:
        src, dst = link
        net.addLink(src, dst)

    net.start()
    
    # Configure network manually
    config(hosts, switches, routers, DHCPServer)

    # Run DHCP server at node DHCPserver
    runDHCP(net) # if your dhcpd.conf is done, uncomment this line 

    check(hosts)

    # Comment this line if you don't need to debug
    CLI(net)
    
    check(hosts)
    # Kill DHCP server process, don't leave dhcp process on your computer 
    killDHCP(net)

    net.stop()

def config(hosts, switches, routers, DHCPServer):
    # Hosts interface IP and  default gateway configuration
    DHCPServer.cmd('ifconfig DHCPServer-eth0 192.168.1.4/26')
        
    hosts['h2'].cmd('ifconfig h2-eth0 192.168.1.65/26')
    hosts['h2'].cmd('route add default gw 192.168.1.126')
    
    hosts['h3'].cmd('ifconfig h3-eth0 192.168.1.66/26')
    hosts['h3'].cmd('route add default gw 192.168.1.126')

    hosts['h4'].cmd('ifconfig h4-eth0 192.168.3.1/24')
    hosts['h4'].cmd('route add default gw 192.168.3.254')

    hosts['h5'].cmd('ifconfig h5-eth0 192.168.3.2/24')
    hosts['h5'].cmd('route add default gw 192.168.3.254')
   
    #Routers interface IP configuration
    routers['r1'].cmd('ifconfig r1-eth0 10.0.1.2/24')
    routers['r1'].cmd('ifconfig r1-eth1 192.168.1.62/26')
    routers['r1'].cmd('ifconfig r1-eth2 192.168.1.126/26')

    routers['r2'].cmd('ifconfig r2-eth0 10.0.0.1/24')
    routers['r2'].cmd('ifconfig r2-eth1 10.0.1.1/24')
    
    routers['r3'].cmd('ifconfig r3-eth0 10.0.0.2/24')
    routers['r3'].cmd('ifconfig r3-eth1 10.0.2.1/24')

    routers['r4'].cmd('ifconfig r4-eth0 10.0.2.3/24')
    routers['r4'].cmd('ifconfig r4-eth1 192.168.3.254/24')
    
    # Router routing table configuration
    routers['r1'].cmd('route add -net 192.168.3.0/24 gw 10.0.1.1')
    routers['r2'].cmd('route add -net 192.168.3.0/24 gw 10.0.0.2')
    routers['r3'].cmd('route add -net 192.168.3.0/24 gw 10.0.2.3')
    
    routers['r4'].cmd('route add -net 192.168.1.0/26 gw 10.0.2.1')
    routers['r3'].cmd('route add -net 192.168.1.0/26 gw 10.0.0.1')
    routers['r2'].cmd('route add -net 192.168.1.0/26 gw 10.0.1.2')

    routers['r4'].cmd('route add -net 192.168.1.64/26 gw 10.0.2.1')
    routers['r3'].cmd('route add -net 192.168.1.64/26 gw 10.0.0.1')
    routers['r2'].cmd('route add -net 192.168.1.64/26 gw 10.0.1.2')

    # Bonus
    routers['r1'].cmd('route add -net 10.0.0.0/24 gw 10.0.1.1')

    routers['r1'].cmd('route add -net 10.0.2.0/24 gw 10.0.1.1')
    routers['r2'].cmd('route add -net 10.0.2.0/24 gw 10.0.0.2')


def check(hosts):
    ips = {'192.168.1.65', '192.168.1.66', '192.168.3.1', '192.168.3.2'}
    flag = 0
    for h in sorted(hosts):
        for ip in sorted(ips):
            check = hosts[h].cmd('ping %s -c 1 -W 1' % ip)
            if '64 bytes from %s' %ip not in check:
                print('\033[93m%s doesn\'t have connectivity to %s\033[0m' % (h,ip))
                flag = 1
    if flag==0:
        print('\033[92mACCEPT\033[0m')
    if flag==1:
        print('\033[91mWRONG ANSWER\033[0m')

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

if __name__ == '__main__':
    topology()


