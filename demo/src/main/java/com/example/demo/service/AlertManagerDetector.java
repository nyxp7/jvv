package com.example.demo.service;

import com.example.demo.model.Alerte;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.util.ArrayList;
import java.util.List;

public class AlertManagerDetector {

    private final ObservableList<Alerte> alerts = FXCollections.observableArrayList();
    private final List<AlertListener> listeners = new ArrayList<>();

    public interface AlertListener {
        void onNewAlert(Alerte alert);
    }

    public void addListener(AlertListener listener) {
        listeners.add(listener);
    }

    public void raiseAlert(Alerte alert) {
        alerts.add(alert);
        for (AlertListener listener : listeners) {
            listener.onNewAlert(alert);
        }
        System.out.println("[ALERT] " + alert.getSeverity() + " - " + alert.getTitle());
    }

    public ObservableList<Alerte> getAllAlerts() {
        return alerts;
    }

    public int getAlertCount() {
        return alerts.size();
    }
}