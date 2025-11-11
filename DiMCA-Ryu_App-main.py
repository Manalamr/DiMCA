#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DMCA Main Controller for Ryu
Modules: DPSI Input Receiver -> MCPA Coordination -> CPIA Detection -> CMLM Mitigation
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
from ryu.lib import hub

import json
import time
import pickle
from controller.ryu.cpia_module import CPIAEngine
from controller.ryu.cmlm_module import MitigationEngine
from controller.ryu.mcpa import CoordinationService

class DMCARyuController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(DMCARyuController, self).__init__(*args, **kwargs)
        self.name = "DMCA Controller"
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.cpia = CPIAEngine()
        self.mitigator = MitigationEngine()
        self.coordinator = CoordinationService()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info(f"Switch connected: {datapath.id}")
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default flow: send all to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # Can be used for real-time traffic analysis
        pass

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            # This is where periodic analysis happens
            self.logger.info("Monitoring cycle...")
            context_data = self.coordinator.gather_features_from_peers()

            is_attack, attack_info = self.cpia.run_analysis(context_data)

            if is_attack:
                self.logger.warning(f"Attack Detected: {attack_info['type']} (Confidence: {attack_info['confidence']})")
                self.mitigator.apply_mitigation(attack_info, self.datapaths)
            hub.sleep(5)
