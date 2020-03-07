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
    def send_icmp(self, datapath, dst_ip, type, code, data):
        proto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet()
        out_ip = ""
        out_hw = ""
        out_port = 0

        ## pkt.add_protocol(...)
        ## https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_icmp.html

        pkt.serialize()
        data = pkt.data
        actions = [datapath.ofproto_parser.OFPActionOutput(port=out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=proto.OFP_NO_BUFFER, in_port=proto.OFPP_ANY, actions=actions, data=data)
        datapath.send_msg(out)

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

        #check packets MAC dest against datapath's interface table for validity
        interfaces = self.interface_table.get(dpid)


        #check packets IP against routing table - including subnets - and get the 
        #hop IP and the output table


        #get MAC of next hop from ARP table


        #change packet's MAC dst to the next hop, and MAC src to the outgoing port's MAC


        #send packet!
        


        return