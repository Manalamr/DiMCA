# dmca_mcp_agent.py - MCPA: Multi-Controller Policy Agent (Ryu)
import json
import os
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

POLICY_FILE = os.path.join(os.path.dirname(__file__), "../../config/block_policy.json")

class DMCAMCPA(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DMCAMCPA, self).__init__(*args, **kwargs)
        self.logger.info("🧠 MCPA policy agent initialized.")
        self.blocklist = set()
        self.load_policy()

    def load_policy(self):
        if os.path.exists(POLICY_FILE):
            with open(POLICY_FILE, "r") as f:
                try:
                    data = json.load(f)
                    self.blocklist = set(data.get("blocked_ips", []))
                    self.logger.info("📥 Loaded blocklist: %s", list(self.blocklist))
                except Exception as e:
                    self.logger.error("Policy load error: %s", e)

    def sync_policy(self):
        with open(POLICY_FILE, "w") as f:
            json.dump({"blocked_ips": list(self.blocklist)}, f, indent=4)
            self.logger.info("📤 Synced policy file with %d entries.", len(self.blocklist))

    def add_to_blocklist(self, ip):
        if ip not in self.blocklist:
            self.logger.warning("🚨 New malicious IP detected: %s", ip)
            self.blocklist.add(ip)
            self.sync_policy()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Optional: future use to dynamically install mitigation on boot
        self.logger.info("Switch features received from datapath %s", ev.msg.datapath.id)

    # Simulated method to receive alert from CPIA
    def external_alert(self, ip):
        self.add_to_blocklist(ip)
