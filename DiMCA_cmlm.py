# dmca_cmlm.py - CMLM: Collaborative Mitigation and Localized Management (Ryu)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

# Hardcoded attacker IPs (in production this list should be dynamic from CPIA/MCPA)
BLOCKED_IPS = ['10.0.0.99', '10.0.0.88']

class DMCACMLM(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DMCACMLM, self).__init__(*args, **kwargs)
        self.logger.info("CMLM mitigation controller initialized.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Allow controller visibility of all packets
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                 priority=0,
                                 match=match,
                                 instructions=inst)
        datapath.send_msg(mod)

        self.logger.info("Default flow installed on switch %s", datapath.id)

        # Block all known malicious IPs
        for ip in BLOCKED_IPS:
            self.block_ip(datapath, ip)

    def block_ip(self, datapath, ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        actions = []  # Drop
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info("🚫 Installed drop rule for attacker IP: %s", ip)
