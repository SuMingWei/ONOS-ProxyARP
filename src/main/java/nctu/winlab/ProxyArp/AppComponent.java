/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.ProxyArp;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;

import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.Map;
import java.util.Properties;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;
    private ApplicationId appId;
    private PacketProcessor processor;
    protected Map<Ip4Address, MacAddress> arpTable = Maps.newConcurrentMap();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        log.info("Started==========");
        appId = coreService.getAppId("nctu.winlab.proxyarp");

        processor = new ProxyArpProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));

        packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                                    PacketPriority.REACTIVE,
                                    appId);
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped==========");
        packetService.removeProcessor(processor);

        packetService.cancelPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                                    PacketPriority.REACTIVE,
                                    appId);
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context){
            if (context.isHandled()) {
                return;
            }
            
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            ARP arpPkt = (ARP) ethPkt.getPayload();
            
            short opCode = arpPkt.getOpCode();
            Ip4Address srcIP = Ip4Address.valueOf(arpPkt.getSenderProtocolAddress());
            Ip4Address dstIP = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());
            MacAddress srcMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());

            if(!arpTable.containsKey(srcIP)) {
                arpTable.put(srcIP, srcMac);
            }
            
            if(opCode == ARP.OP_REQUEST) {
                if(!arpTable.containsKey(dstIP)) {
                    log.info("TABLE MISS. Send request tp edge ports");

                    // send to all edge
                    TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
                    for(ConnectPoint p : edgePortService.getEdgePoints()){
                        if(p != pkt.receivedFrom()){
                            treatment.setOutput(p.port());
                            OutboundPacket arp = new DefaultOutboundPacket(p.deviceId(), treatment.build(), pkt.unparsed());
                            packetService.emit(arp);
                        }
                    }
                }else {
                    log.info("TABLE HIT. Requested MAC = {}", arpTable.get(dstIP));

                    // reply arp
                    ConnectPoint cp = pkt.receivedFrom();
                    Ethernet reply = ARP.buildArpReply(dstIP, arpTable.get(dstIP), ethPkt);
                    ByteBuffer data = ByteBuffer.wrap(reply.serialize());

                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(cp.port()).build();
                    OutboundPacket packet = new DefaultOutboundPacket(cp.deviceId(), treatment, data);
                    packetService.emit(packet); 
                }
            }

            if(opCode == ARP.OP_REPLY) {
                log.info("RECV REPLY. Requested MAC = {}", srcMac);
            }

        }
    }
}
