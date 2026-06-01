package com.example.demo.regles;

import com.example.demo.model.Packet;
import com.example.demo.model.Severite;

public interface Regle {
    boolean matches(Packet packet);
    String getAlertMessage();
    Severite getSeverity();
}
