package com.example.demo.service;

import com.example.demo.model.Alerte;
import com.example.demo.model.Packet;
import com.example.demo.model.Severite;
import com.example.demo.regles.Regle;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class RuleEngineDetector {

    private final List<Regle> regles = new ArrayList<>();
    private final AlertManagerDetector alertManager;
    private final AtomicInteger alertIdCounter = new AtomicInteger(0);

    public RuleEngineDetector(AlertManagerDetector alertManager) {
        this.alertManager = alertManager;
    }

    public void addRule(Regle regle) {
        regles.add(regle);
    }

    public void analyze(Packet packet) {
        for (Regle rule : regles) {
            if (rule.matches(packet)) {
                Alerte alerte = new Alerte(
                    alertIdCounter.incrementAndGet(),
                    rule.getAlertMessage(),
                    "Suspicious activity detected from " + packet.getSourceIp(),
                    rule.getSeverity(),
                    packet.getProtocol(),
                    java.time.LocalDateTime.now(),
                    packet.getSourceIp(),
                    packet.getDestinationIp(),
                    packet.getDestinationPort()
                );
                alertManager.raiseAlert(alerte);
            }
        }
    }
}