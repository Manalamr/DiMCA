# p4runtime_controller.py – Communicates with BMv2 switches via P4Runtime API
# NOTE: Requires p4runtime_lib from official P4 tutorials

from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
import p4runtime_lib.bmv2
import grpc

def write_forwarding_rules(p4info_helper, switch, rules):
    for rule in rules:
        match = rule["match"]
        action = rule["action"]
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (match["dst_ip"], 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": action["dst_mac"],
                "port": action["port"]
            }
        )
        switch.WriteTableEntry(table_entry)
        print(f"✅ Installed rule for {match['dst_ip']}")

def main():
    p4info_helper = P4InfoHelper("build/dpsi.p4.p4info.txt")

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="s1",
            address="127.0.0.1:50051",
            device_id=0,
            proto_dump_file="logs/s1-p4runtime-requests.txt"
        )

        s1.MasterArbitrationUpdate()
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path="build/dpsi.p4.json")
        print("🎮 P4Runtime pipeline pushed to s1")

        sample_rules = [
            {"match": {"dst_ip": "10.0.0.5"}, "action": {"dst_mac": "00:00:00:00:00:05", "port": 2}},
            {"match": {"dst_ip": "10.0.0.6"}, "action": {"dst_mac": "00:00:00:00:00:06", "port": 3}}
        ]
        write_forwarding_rules(p4info_helper, s1, sample_rules)

    except KeyboardInterrupt:
        print("Interrupted.")
    except grpc.RpcError as e:
        print(f"gRPC Error: {e}")
    finally:
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    main()
