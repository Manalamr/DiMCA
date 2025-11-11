// DMCAOnosApp.java - ONOS Application to enforce mitigation
package org.dmca.app;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.*;
import org.onosproject.net.flow.*;
import org.onosproject.net.*;
import org.osgi.service.component.annotations.*;

@Component(immediate = true)
public class DMCAOnosApp {

    private static final String BLOCKED_IP = "10.0.0.99";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.dmca.app");
        packetService.addProcessor(new InternalPacketProcessor(), PacketProcessor.director(2));
        System.out.println("✅ DMCA ONOS App Started");
    }

    private class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) return;

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                String srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress()).toString();
                if (BLOCKED_IP.equals(srcIp)) {
                    installDropRule(pkt.receivedFrom().deviceId(), ipv4Packet.getSourceAddress());
                }
            }
        }

        private void installDropRule(DeviceId deviceId, int ip) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(ip), 32))
                .build();

            TrafficTreatment drop = DefaultTrafficTreatment.builder()
                .drop()
                .build();

            FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(drop)
                .withPriority(500)
                .fromApp(appId)
                .makePermanent()
                .build();

            flowRuleService.applyFlowRules(flowRule);
            System.out.println("🚫 Drop rule installed for malicious IP in ONOS.");
        }
    }

    @Deactivate
    public void deactivate() {
        System.out.println("❌ DMCA ONOS App Deactivated");
    }
}
