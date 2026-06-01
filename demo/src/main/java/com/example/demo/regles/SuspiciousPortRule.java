package com.example.demo.regles;

import com.example.demo.model.Packet;
import com.example.demo.model.Severite;

public class SuspiciousPortRule implements Regle {
    
    private static final int[] SUSPICIOUS_PORTS = {23, 445, 3389, 4444, 5900};

    @Override
    public boolean matches(Packet packet) {
        int destPort = packet.getDestinationPort();
        for (int port : SUSPICIOUS_PORTS) {
            if (destPort == port) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String getAlertMessage() {
        return "Connection to suspicious port detected";
    }

    @Override
    public Severite getSeverity() {
        return Severite.MEDIUM;
    }
}
