package com.example.demo.service;
import javafx.application.Platform;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import com.example.demo.model.Packet;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.pcap4j.packet.LlcPacket;
import com.example.demo.model.Packet;

import static org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE;

public class PacketCaptureService {
    private final AtomicInteger incomingCount = new AtomicInteger(0);
    private final AtomicInteger outgoingCount = new AtomicInteger(0);
    private final AtomicInteger connectionCount = new AtomicInteger(0);

    private PcapHandle pcapHandle;
    private ExecutorService executor;
    private volatile boolean running = false;

    private Consumer<Packet> packetConsumer;

    public PacketCaptureService() {}

    public void setPacketConsumer(Consumer<Packet> consumer) {
        this.packetConsumer = consumer;
    }

    public int getIncomingCount() {
        return incomingCount.get();
    }

    public int getOutgoingCount() {
        return outgoingCount.get();
    }

    public int getConnectionCount() {
        return connectionCount.get();
    }

    public void startCapture(String deviceName, RuleEngineDetector ruleEngine) throws PcapNativeException, NotOpenException {
        if (running) return;

        List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
        if (devs == null || devs.isEmpty()) {
            throw new PcapNativeException("No network interfaces found");
        }


        for (PcapNetworkInterface nif : devs) {
            System.out.println(nif.getName() + " : " + nif.getDescription());
        }

        PcapNetworkInterface nif = null;

        if (deviceName != null && !deviceName.trim().isEmpty()) {
            try {
                nif = Pcaps.getDevByName(deviceName);
            } catch (PcapNativeException e) {
                System.err.println("Device '" + deviceName + "' not found, falling back to Ethernet.");
            }
        }

        if (nif == null) {
            // Prefer Intel Ethernet adapter if available
            nif = devs.stream()
                    .filter(d -> d.getDescription() != null && d.getDescription().contains("Wireless"))
                    .findFirst()
                    .orElse(devs.get(0)); // fallback to first interface
        }

        System.out.println("Using network interface: " + nif.getName() + " (" + nif.getDescription() + ")");

        String bpfFilter = "ip";
        PcapHandle.Builder handleBuilder = new PcapHandle.Builder(nif.getName())
                .snaplen(65536)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .bufferSize(1 * 1024 * 1024)
                .timeoutMillis(1000);

        pcapHandle = handleBuilder.build();
        pcapHandle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
        running = true;

        executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            try {
                while (running) {
                    org.pcap4j.packet.Packet pcapPacket = pcapHandle.getNextPacket();
                    if (pcapPacket != null) {
                        Packet packet = convertPacket(pcapPacket, pcapHandle);
                        if (packet != null) {
                            updateStats(packet);


                            Platform.runLater(() -> {
                                if (packetConsumer != null) {
                                    packetConsumer.accept(packet);
                                }
                            });

                            if (ruleEngine != null) {
                                ruleEngine.analyze(packet);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (running) {
                    System.err.println("Capture error: " + e.getMessage());
                }
            }
        });
    }

    private void showError(String s) {
        System.err.println(s);
    }

    public void stopCapture() {
        running = false;
        if (pcapHandle != null) {
            try {
                pcapHandle.breakLoop();
            } catch (NotOpenException e) {

            }
            pcapHandle.close();
        }
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private void updateStats(Packet packet) {
        try {
            InetAddress localAddress = InetAddress.getLocalHost();
            String localHostAddress = localAddress.getHostAddress();

            if (packet.getSourceIp().equals(localHostAddress)) {
                outgoingCount.incrementAndGet();
            } else {
                incomingCount.incrementAndGet();
            }
            connectionCount.incrementAndGet();
        } catch (UnknownHostException e) {
            incomingCount.incrementAndGet();
            connectionCount.incrementAndGet();
        }
    }




    private com.example.demo.model.Packet convertPacket(org.pcap4j.packet.Packet pcapPacket, PcapHandle handle) {
        try {

            EthernetPacket ethernet = pcapPacket.get(EthernetPacket.class);
            if (ethernet != null) {
                if (ethernet.getHeader().getType().equals(EtherType.IPV4)) {
                    return parseIpv4(pcapPacket.get(IpV4Packet.class), pcapPacket);
                }
                int size = pcapPacket.length();
                ArpPacket arp = pcapPacket.get(ArpPacket.class);
                if (arp != null) {
                    return new com.example.demo.model.Packet(
                            arp.getHeader().getSrcProtocolAddr().toString(),
                            arp.getHeader().getDstProtocolAddr().toString(),
                            0, 0,
                            "ARP",
                            pcapPacket.toString(),
                            System.currentTimeMillis(), size
                    );
                }
            }

            // Wi-Fi frames
            if (handle.getDlt().equals(DataLinkType.IEEE802_11)) {
                LlcPacket llc = pcapPacket.get(LlcPacket.class);
                if (llc != null) {
                    IpV4Packet ipv4 = llc.getPayload().get(IpV4Packet.class);
                    if (ipv4 != null) {
                        return parseIpv4(ipv4, pcapPacket);
                    }
                    ArpPacket arp = llc.getPayload().get(ArpPacket.class);
                    int size = pcapPacket.length();
                    if (arp != null) {
                        return new com.example.demo.model.Packet(
                                arp.getHeader().getSrcProtocolAddr().toString(),
                                arp.getHeader().getDstProtocolAddr().toString(),
                                0, 0,
                                "ARP",
                                pcapPacket.toString(),
                                System.currentTimeMillis(), size
                        );
                    }
                }
            }

        } catch (Exception e) {
            // Replace with proper logging in production
            e.printStackTrace();
        }
        int size = pcapPacket.length();
        return new com.example.demo.model.Packet(
                "Unknown", "Unknown",
                0, 0,
                "OTHER",
                pcapPacket.toString(),
                System.currentTimeMillis(),size
        );
    }

    // Helper to parse IPv4 +
    private com.example.demo.model.Packet parseIpv4(IpV4Packet ipv4, org.pcap4j.packet.Packet pcapPacket) {
        if (ipv4 == null) return null;

        String srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
        String protocol = ipv4.getHeader().getProtocol().name();

        int srcPort = 0;
        int dstPort = 0;

        TcpPacket tcp = pcapPacket.get(TcpPacket.class);
        if (tcp != null) {
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            protocol = "TCP";
            if (srcPort == 80 || dstPort == 80) protocol = "HTTP";
            else if (srcPort == 443 || dstPort == 443) protocol = "HTTPS";
        }

        UdpPacket udp = pcapPacket.get(UdpPacket.class);
        if (udp != null) {
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
            protocol = "UDP";
            if (srcPort == 53 || dstPort == 53) protocol = "DNS";
            else if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) protocol = "DHCP";
            else if (srcPort == 443 || dstPort == 443) protocol = "QUIC/TLS over UDP";
        }

        IcmpV4CommonPacket icmp = pcapPacket.get(IcmpV4CommonPacket.class);
        if (icmp != null) {
            protocol = "ICMP";
        }
        int size = pcapPacket.length();

        return new com.example.demo.model.Packet(
                srcIp, dstIp,
                srcPort, dstPort,
                protocol,
                pcapPacket.toString(),
                System.currentTimeMillis(), size
        );
    }





}
