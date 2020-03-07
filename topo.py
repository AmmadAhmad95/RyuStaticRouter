from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, DefaultController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

"""
Router Topology | SCC365
 - Will Fantom

Creates 3 subnets. Each subnet has at least 1 port of a router.

Run with python:
e.g. sudo python topo.py
"""

def RouterNetwork(do_test=False):

    net = Mininet( switch=OVSSwitch, build=False, topo=None )

    info( "*** Creating Controllers\n" )
    cs1 = net.addController( 'cs1', controller=DefaultController, port=6634 )
    cr1 = net.addController( 'cr1', controller=RemoteController, port=6653 )

    info( "*** Creating Routers\n" )
    r1 = net.addSwitch( 'r1', cls=OVSKernelSwitch, dpid='0000000000000002' )
    r2 = net.addSwitch( 'r2', cls=OVSKernelSwitch, dpid='0000000000000003' )

    info( "*** Creating Switches\n" )
    s1 = net.addSwitch( 's1', cls=OVSKernelSwitch, dpid='0000000000000001' )
    s2 = net.addSwitch( 's2', cls=OVSKernelSwitch, dpid='0000000000000004' )

    info( "*** Creating Hosts\n" )
    hosts_l = [ net.addHost( 'h%d' % n ) for n in ( 1, 2 ) ]
    hosts_r = [ net.addHost( 'h%d' % n ) for n in ( 3, 4 ) ]

    info( "*** Creating Links\n" )
    for h in hosts_l:
        net.addLink( s1, h )
    for h in hosts_r:
        net.addLink( s2, h )
    net.addLink( s1, r1 )
    net.addLink( r1, r2 )
    net.addLink( r2, s2 )

    info( "*** Starting Network\n" )
    net.build()

    info( "*** Setting Host Interface Values\n" )
    hosts_l[0].intf( 'h1-eth0' ).setIP( '148.88.172.19', 24 )
    hosts_l[0].intf( 'h1-eth0' ).setMAC( 'aa:aa:aa:aa:bb:aa' )
    hosts_l[0].setARP( '148.88.172.1', 'aa:aa:aa:aa:aa:aa' )
    hosts_l[1].intf( 'h2-eth0' ).setIP( '148.88.172.69', 24 )
    hosts_l[1].intf( 'h2-eth0' ).setMAC( 'aa:aa:aa:aa:bb:bb' )
    hosts_l[1].setARP( '148.88.172.1', 'aa:aa:aa:aa:aa:aa' )

    hosts_r[0].intf( 'h3-eth0' ).setIP( '112.98.37.121', 24 )
    hosts_r[0].intf( 'h3-eth0' ).setMAC( 'cc:cc:cc:cc:bb:aa' )
    hosts_r[0].setARP( '112.98.37.1', 'cc:cc:cc:cc:aa:aa' )
    hosts_r[1].intf( 'h4-eth0' ).setIP( '112.98.37.227', 24 )
    hosts_r[1].intf( 'h4-eth0' ).setMAC( 'cc:cc:cc:cc:bb:bb' )
    hosts_r[1].setARP( '112.98.37.1', 'cc:cc:cc:cc:aa:aa' )

    info( "*** Setting Switch Interface Values\n" )
    s1.intf( 's1-eth1' ).setMAC( '00:00:00:00:00:02' )
    s1.intf( 's1-eth2' ).setMAC( '00:00:00:00:00:03' )
    s1.intf( 's1-eth3' ).setMAC( '00:00:00:00:00:04' )
    s2.intf( 's2-eth1' ).setMAC( '00:00:00:00:02:02' )
    s2.intf( 's2-eth2' ).setMAC( '00:00:00:00:02:03' )
    s2.intf( 's2-eth3' ).setMAC( '00:00:00:00:02:04' )

    info( "*** Setting Router Interface Values\n" )
    r1.intf( 'r1-eth1' ).setMAC( 'aa:aa:aa:aa:aa:aa' )
    r1.intf( 'r1-eth2' ).setMAC( '00:bb:bb:bb:aa:aa' )
    r2.intf( 'r2-eth1' ).setMAC( '00:bb:bb:bb:aa:bb' )
    r2.intf( 'r2-eth2' ).setMAC( 'cc:cc:cc:cc:aa:aa' )

    for controller in net.controllers:
        controller.start()
    s1.start( [ cs1 ] )
    s2.start( [ cs1 ] )
    r1.start( [ cr1 ] )
    r2.start( [ cr1 ] )

    info( "*** Setting Default Routes\n" )
    hosts_l[0].cmd( 'route add default gw 148.88.172.1 h1-eth0' )
    hosts_l[1].cmd( 'route add default gw 148.88.172.1 h2-eth0' )
    hosts_r[0].cmd( 'route add default gw 112.98.37.1 h3-eth0' )
    hosts_r[1].cmd( 'route add default gw 112.98.37.1 h4-eth0' )

    if do_test:
        info( "*** Testing Network\n" )
        net.pingAll()

    info( "*** Running CLI\n" )
    CLI( net )

    info( "*** Stopping Network\n" )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )  # for CLI output
    RouterNetwork()
