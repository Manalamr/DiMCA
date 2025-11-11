# dmca_cpia.py - CPIA: Classifier-Based Packet Inspection Agent (Ryu)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
import joblib
import numpy as np
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), '../../ml_model/dmca_model.pkl')

class DMCACPIA(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DMCACPIA, self).__init__(*args, **kwargs)
        self.logger.info("CPIA module initialized.")
        self.model = self.load_model()

    def load_model(self):
        try:
            model = joblib.load(MODEL_PATH)
            self.logger.info("ML model loaded from: %s", MODEL_PATH)
            return model
        except Exception as e:
            self.logger.error("Failed to load model: %s", e)
            return None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if ip:
            features = self.extract_features(ip)
            if features is not None:
                prediction = self.model.predict([features])[0]
                if prediction == 1:
                    self.logger.warning("🚨 Malicious IPv4 traffic detected from %s", ip.src)
                    # Could send mitigation signal to CMLM here
                else:
                    self.logger.info("✔️ Benign IPv4 traffic from %s", ip.src)

        elif arp_pkt:
            if arp_pkt.src_mac == "00:00:00:00:00:00" or arp_pkt.src_ip == "0.0.0.0":
                self.logger.warning("🚨 Suspicious ARP detected: %s → %s", arp_pkt.src_ip, arp_pkt.dst_ip)

    def extract_features(self, ip_pkt):
        try:
            # Dummy feature vector (replace with actual logic)
            src = sum([int(x) for x in ip_pkt.src.split('.')])
            dst = sum([int(x) for x in ip_pkt.dst.split('.')])
            proto = ip_pkt.proto
            ttl = ip_pkt.ttl
            return [src, dst, proto, ttl]
        except:
            return None