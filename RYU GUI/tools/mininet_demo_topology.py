"""
Mininet demo topology — 3 OVS switches, 6 hosts, all pointed at the Ryu
controller running on the same Ubuntu host.

    sudo python3 tools/mininet_demo_topology.py
"""
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


def topology():
    net = Mininet(switch=OVSKernelSwitch, controller=None)
    c0 = net.addController(
        "c0", controller=RemoteController, ip="127.0.0.1", port=6653,
    )
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")
    hosts = [net.addHost(f"h{i+1}") for i in range(6)]

    for h in hosts[0:2]:
        net.addLink(h, s1)
    for h in hosts[2:4]:
        net.addLink(h, s2)
    for h in hosts[4:6]:
        net.addLink(h, s3)
    net.addLink(s1, s2); net.addLink(s2, s3)

    net.build(); c0.start(); s1.start([c0]); s2.start([c0]); s3.start([c0])
    print("Topology started. Try `pingall` then exit.")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    topology()
