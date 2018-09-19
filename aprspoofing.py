from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_ip = {} # contains list of Ip to MAC address in the controller
	self.ip_set = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
	print("add flow")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	msg=ev.msg
        pkt = packet.Packet(msg.data)
	datapath = ev.msg.datapath
        ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	in_port = msg.match['in_port']
	
		#eth = pkt.get_protocols(ethernet.ethernet)[0]


        arp_Ob = pkt.get_protocol(arp.arp)
        ip_Ob = pkt.get_protocol(ipv4.ipv4)
        if arp_Ob:
	    print("arp packet")	
            src_mac = arp_Ob.src_mac
            src_ip = arp_Ob.src_ip
            
        if ip_Ob:
            print("ip Packet") 
            src_mac = eth.src
            src_ip = ip_Ob.src
        
	if arp_Ob:     
	    if src_mac not in self.mac_to_ip.keys() and src_ip not in self.ip_set:
                #mac_to_port.update({src_mac : src_ip})
                self.mac_to_ip[src_mac]=src_ip
            	self.ip_set.add(src_ip)
                print(self.mac_to_ip)
		print(self.ip_set)            
            else:
                print("already there")
		print(arp_Ob)
		print(self.mac_to_ip)
                print(self.mac_to_ip[src_mac])
		print(src_ip) 
    	  	#for i,(key,value) in enumerate(self.mac_to_ip.items()):
		#    ip=list(self.mac_to_ip.keys())[i];
		#    mac=list(self.mac_to_ip.values())[i];
                #ip = self.mac_to_ip[src_mac]    
                if (self.mac_to_ip[src_mac]!=src_ip):
            	    print("dropping")
                    match = parser.OFPMatch(eth_type=0x0806,in_port=in_port,arp_spa=src_ip)
                    drop_actions = []
                    print("dropping the packet")
                    self.add_flow(datapath, 10, match, drop_actions)
                    return 
            
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
	

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
	    print("Alice in Wl")
	    if arp_Ob:
		print("Arp Hit")
            	match = parser.OFPMatch(eth_type=0x0806,in_port=in_port, eth_dst=dst, eth_src=src, arp_spa=src_ip)
	    elif ip_Ob:
		print("IP")
		match = parser.OFPMatch(eth_type=0x0800,in_port=in_port, eth_dst=dst, eth_src=src, ipv4_src=src_ip)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
