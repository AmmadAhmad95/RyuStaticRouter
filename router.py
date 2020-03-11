from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, icmp
from ryu.lib.packet import ether_types
from ryu.lib.dpid import dpid_to_str
from ryu.lib import mac as mac_lib
from ryu.utils import hex_array
import ipaddress

from staticdata import StaticRoutingTable, StaticARPTable

"""
Base Router | SCC365
 - Will Fantom

A minimal router template for coursework 2 of SCC365.
You may alter the template code.
"""


class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self.arp_table = StaticARPTable(debug=True)
        self.routing_table = StaticRoutingTable(debug=True)
        self.interface_table = {}

    ## Error Handling
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.error("OpenFlow Error In")
        self.logger.debug("Error Info | Type 0x%02x | Code 0x%02x", msg.type, msg.code)
        self.logger.debug("Error Message | %s", hex_array(msg.data))

    ## Flow Installs
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        proto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(proto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    ## Config
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_features_request(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        port_request = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(port_request)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def handle_port_desc_reply(self, ev):
        self.logger.debug("Port stats response in")
        datapath_id = dpid_to_str(ev.msg.datapath.id)
        current_arp = self.arp_table.getArpTable(datapath_id)
        interface_entry = []
        for p in ev.msg.body:
            port = p.port_no
            mac = p.hw_addr
            ip = ''
            for entry in current_arp:
                if (entry.get('hw') == mac):
                    ip = entry.get('ip')
                    break
            if ip != '' and port != 4294967294:
                interface_entry.append({'port' : port, 'ip' : ip, 'hw' : mac})
        self.interface_table[datapath_id] = interface_entry


    ## ICMP
    def send_icmp(self, datapath, dst_ip, src_mac, icmp_type, icmp_code, ip_ihl, icmp_data):
        self.logger.debug("Sending ICMP")
        proto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid_to_str(datapath.id)

        pkt = packet.Packet()

        out_port, hop_ip = self.get_route(dpid, dst_ip)
        out_mac = self.mac_from_port(dpid, out_port)
        dst_mac = src_mac
        self.logger.debug("Router {} sending ICMP to {} with target MAC {} (from port {} hopping to {})".format(dpid, dst_ip, dst_mac, out_port, hop_ip))

        for interface in self.interface_table.get(dpid):
            if interface.get("port") == out_port:
                src_ip = interface.get("ip")
        
        offset = 14 + 8 + (ip_ihl * 4)
        payload = icmp_data[14:offset]

        if icmp_type == 3:
            self.logger.debug("TYPE 3 ICMP")
            payload = icmp.dest_unreach(data=payload)
        
        if icmp_type == 11:
            self.logger.debug("TYPE 11 ICMP")
            payload = icmp.TimeExceeded(data=payload)

        ## pkt.add_protocol(...)
        ## https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_icmp.html

        pkt.add_protocol(ethernet.ethernet(
            dst=dst_mac,
            src=out_mac,
            ethertype=ethernet.ether.ETH_TYPE_IP
        ))
        pkt.add_protocol(ipv4.ipv4(
            dst=dst_ip,
            src=src_ip,
            ttl=64,
            proto=ipv4.inet.IPPROTO_ICMP
        ))
        pkt.add_protocol(icmp.icmp(
            type_=icmp_type,
            code=icmp_code,
            data=payload
        ))

        pkt.serialize()
        data = pkt.data
        actions = [datapath.ofproto_parser.OFPActionOutput(port=out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=proto.OFP_NO_BUFFER, in_port=proto.OFPP_ANY, actions=actions, data=data)
        datapath.send_msg(out)


    def get_route(self, dpid, dst_ip):
        routing = self.routing_table.getRoutingTable(dpid)
        destination = ipaddress.ip_address(dst_ip)
        for route in routing:
            if destination in ipaddress.ip_network(route.get("destination")):
                return route.get('out_port'), route.get('hop')
        return '', ''

    def mac_from_ip(self, dpid, ip):
        arp = self.arp_table.getArpTable(dpid)
        for addr in arp:
            if addr.get("ip") == ip:
                return addr.get("hw")
        return ''

    def mac_from_port(self, dpid, port):
        interfaces = self.interface_table.get(dpid)
        for interface in interfaces:
            if (interface.get("port") == port):
                return interface.get("hw")
        return ''
    


    ## Routing
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_pkt_in(self, ev):
        self.logger.info("Packet In")
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        reason = ev.msg.reason
        dpid = dpid_to_str(datapath.id)
        in_port = ev.msg.match['in_port']
        data = ev.msg.data
        pkt = packet.Packet(data)
        
        #get packet's ethernet info
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        mac_dst = pkt_eth.dst
        mac_src = pkt_eth.src
        eth_typ = pkt_eth.ethertype

        if eth_typ == 0x0800:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            ip_dst = pkt_ipv4.dst
            ip_src = pkt_ipv4.src
            ip_ihl = pkt_ipv4.header_length
            ip_ttl = pkt_ipv4.ttl
            if pkt_ipv4.proto == 1:
                self.logger.debug("Incoming packet is ICMP")
            #check ttl
            if ip_ttl <= 1:
                self.send_icmp(datapath=datapath, dst_ip=ip_src, src_mac=mac_src, icmp_type=11, icmp_code=0, ip_ihl=ip_ihl, icmp_data=data)
        

        #check packets MAC dest against datapath's interface table for validity
        interfaces = self.interface_table.get(dpid)
        interface_match = False
        for interface in interfaces:
            if interface.get('hw') == mac_dst:
                interface_match = True
                break
        if not interface_match:
            #packet shouldn't have come here!
            self.logger.debug("Packet incorrectly came to router")
            return

        #check packets IP against routing table - including subnets - and get the 
        #hop IP and the output port
        out_port, hop_ip = self.get_route(dpid, ip_dst)
        if hop_ip == None:
            hop_ip = ip_dst
        if out_port == '':
            #destination is not in routing table
            #destination network unreachable (3 / 0)
            #reasoning: https://tools.ietf.org/html/rfc1812#page-81
            self.logger.debug("destination is not in routing table")
            self.send_icmp(datapath=datapath, dst_ip=ip_src, src_mac=mac_src, icmp_type=3, icmp_code=0, ip_ihl=ip_ihl, icmp_data=data)
            return

        #get MAC of next hop from ARP table
        hop_mac = self.mac_from_ip(dpid, hop_ip)
        if hop_mac == '':
            #hop ip isnt in ARP table!
            #destination host unreachable (3 / 1)
            self.logger.debug("hop ip " + hop_ip + " isnt in ARP table")
            self.send_icmp(datapath=datapath, dst_ip=ip_src, src_mac=mac_src, icmp_type=3, icmp_code=1, ip_ihl=ip_ihl, icmp_data=data)
            return

        #change packet's MAC dst to the next hop, and MAC src to the outgoing port's MAC
        out_mac = self.mac_from_port(dpid, out_port)

        if out_mac == '':
            #i dont know how this would happen
            return
        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src = out_mac),
            parser.OFPActionSetField(eth_dst = hop_mac),
            parser.OFPActionOutput(port = out_port)
        ]

        self.add_flow(dpid, 5, ip_dst)

        #send packet!
        self.logger.debug("{}: Routing packet (TTL {}) to {} with target MAC {} (from port {} hopping to {})".format(dpid, ip_ttl, ip_dst, hop_mac, out_port, hop_ip))
        datapath.send_msg(parser.OFPPacketOut(datapath, ev.msg.buffer_id, in_port, actions, data))
        return