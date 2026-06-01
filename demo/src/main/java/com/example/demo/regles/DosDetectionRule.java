package com.example.demo.regles;

import com.example.demo.model.Packet;
import com.example.demo.model.Severite;

import java.util.HashMap;
import java.util.Map;

public class DosDetectionRule implements Regle {

    private static final int DOS_THRESHOLD = 500;
    private static final long WINDOW_MS = 1000;

    private final Map<String, Integer> packetCounter = new HashMap<>();
    private long windowStart = System.currentTimeMillis();

    @Override
    public boolean matches(Packet packet) {

        long now = System.currentTimeMillis();

        if (now - windowStart > WINDOW_MS) {
            packetCounter.clear();
            windowStart = now;
        }

        String srcIp = packet.getSourceIp();

        packetCounter.put(
                srcIp,
                packetCounter.getOrDefault(srcIp, 0) + 1
        );

        return packetCounter.get(srcIp) > DOS_THRESHOLD;
    }

    @Override
    public String getAlertMessage() {
        return "Possible DoS attack or port scan detected";
    }

    @Override
    public Severite getSeverity() {
        return Severite.HIGH;
    }
}