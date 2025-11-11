// DMCAFloodlightApp.java - Floodlight Module for Basic IP-based Mitigation
package net.floodlightcontroller.dmca;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.core.internal.*;
import net.floodlightcontroller.core.IOFSwitch;
import org.projectfloodlight.openflow.protocol.*;
import java.util.*;

public class DMCAFloodlightApp implements IFloodlightModule, IOFMessageListener {

    private static final String BLOCKED_IP = "10.0.0.99";

    @Override
    public String getName() {
        return "DMCAFloodlightApp";
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() == OFType.PACKET_IN) {
            OFPacketIn pin = (OFPacketIn) msg;
            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

            if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4 = (IPv4) eth.getPayload();
                String srcIp = IPv4.fromIPv4Address(ipv4.getSourceAddress());
                if (BLOCKED_IP.equals(srcIp)) {
                    OFActions actions = sw.getOFFactory().actions();
                    OFInstructions instructions = sw.getOFFactory().instructions();

                    OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
                        .setMatch(sw.getOFFactory().buildMatch()
                            .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                            .setExact(MatchField.IPV4_SRC, IPv4Address.of(srcIp))
                            .build())
                        .setInstructions(Collections.singletonList(
                            instructions.applyActions(Collections.emptyList())))
                        .setPriority(500)
                        .setBufferId(OFBufferId.NO_BUFFER)
                        .build();

                    sw.write(flowAdd);
                    System.out.println("🚫 Installed mitigation rule on Floodlight.");
                }
            }
        }
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        return List.of(IFloodlightProviderService.class);
    }

    @Override
    public void init(FloodlightModuleContext context) { }

    @Override
    public void startUp(FloodlightModuleContext context) {
        context.getServiceImpl(IFloodlightProviderService.class).addOFMessageListener(OFType.PACKET_IN, this);
    }
}
