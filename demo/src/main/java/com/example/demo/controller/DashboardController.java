package com.example.demo.controller;

import com.example.demo.model.Alerte;
import com.example.demo.model.Packet;
import com.example.demo.regles.DosDetectionRule;
import com.example.demo.regles.SuspiciousPortRule;
import com.example.demo.service.AlertManagerDetector;
import com.example.demo.service.PacketCaptureService;
import com.example.demo.service.RuleEngineDetector;
import javafx.application.Platform;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.fxml.FXML;
import javafx.scene.control.*;


import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.time.format.DateTimeFormatter;

public class DashboardController {
    @FXML
    private Label connectionsLabel;

    @FXML
    private Label incomingLabel;

    @FXML
    private Label outgoingLabel;

    @FXML
    private TableView<Alerte> alertTable;

    @FXML
    private TableColumn<Alerte, Integer> idColumn;

    @FXML
    private TableColumn<Alerte, String> titleColumn;

    @FXML
    private TableColumn<Alerte, String> severityColumn;

    @FXML
    private TableColumn<Alerte, String> sourceIpColumn;

    @FXML
    private TableColumn<Alerte, String> protocolColumn;

    @FXML
    private TableColumn<Alerte, String> timestampColumn;

    @FXML
    private TableColumn<Packet, String> packetSourceColumn;

    @FXML
    private TableColumn<Packet, String> packetDestColumn;

    @FXML
    private TableColumn<Packet, String> packetProtocolColumn;

    @FXML
    private TableColumn<Packet, Integer> packetPortColumn;
    @FXML private TableColumn<Packet, Number> packetSizeColumn;
    @FXML private TableColumn<Packet, String> packetTimeColumn;


    @FXML
    private Button startButton;

    @FXML
    private Button stopButton;

    @FXML
    private Label statusLabel;
    @FXML
    private TableView<Packet> packetTable;

    private PacketCaptureService captureService;
    private AlertManagerDetector alertManager;
    private RuleEngineDetector ruleEngine;
    private volatile boolean running = false;

    public void initialize() {
        setupTableColumns();
        initializeServices();
        updateStats();
    }

    private void setupTableColumns() {
        idColumn.setCellValueFactory(data -> data.getValue().idProperty().asObject());
        titleColumn.setCellValueFactory(data -> data.getValue().titleProperty());
        severityColumn.setCellValueFactory(data -> data.getValue().severityProperty().asString());
        sourceIpColumn.setCellValueFactory(data -> data.getValue().sourceIpProperty());
        protocolColumn.setCellValueFactory(data -> data.getValue().protocolProperty());
        timestampColumn.setCellValueFactory(data -> 
            data.getValue().timestampProperty().asString());
        
        severityColumn.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    switch (item) {
                        case "CRITICAL" -> setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
                        case "HIGH" -> setStyle("-fx-text-fill: orange;");
                        case "MEDIUM" -> setStyle("-fx-text-fill: yellow;");
                        case "LOW" -> setStyle("-fx-text-fill: green;");
                    }
                }
            }
        });


        packetSourceColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getSourceIp()));
        packetDestColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getDestinationIp()));
        packetProtocolColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getProtocol()));
        packetPortColumn.setCellValueFactory(data -> new SimpleIntegerProperty(data.getValue().getDestinationPort()).asObject());


        packetSizeColumn.setCellValueFactory(data -> new SimpleIntegerProperty(data.getValue().getSize()));
        packetTimeColumn.setCellValueFactory(data -> {
            long ts = data.getValue().getTimestamp();
            String formatted = java.time.Instant.ofEpochMilli(ts)
                    .atZone(java.time.ZoneId.systemDefault())
                    .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
            return new SimpleStringProperty(formatted);
        });
    }

    private void initializeServices() {
        alertManager = new AlertManagerDetector();
        ruleEngine = new RuleEngineDetector(alertManager);
        captureService = new PacketCaptureService();

        ruleEngine.addRule(new DosDetectionRule());
        ruleEngine.addRule(new SuspiciousPortRule());

        alertManager.addListener(this::onNewAlert);

        captureService.setPacketConsumer(packet -> {
            Platform.runLater(() -> {
                packetTable.getItems().add(0, packet);
            });
        });
    }

    private void onNewAlert(Alerte alert) {
        Platform.runLater(() -> {
            alertTable.getItems().add(0, alert);
            statusLabel.setText("⚠️ New Alert: " + alert.getTitle());
        });
    }

    @FXML
    private void onStartCapture() {
        if (!running) {
            try {
                captureService.startCapture(null, ruleEngine);
                running = true;
                startButton.setDisable(true);
                stopButton.setDisable(false);
                statusLabel.setText("✅ Monitoring active");
                startUpdateTimer();
            } catch (PcapNativeException | NotOpenException e) {
                showError("Failed to start capture: " + e.getMessage());
            }
        }
    }

    @FXML
    private void onStopCapture() {
        if (running) {
            captureService.stopCapture();
            running = false;
            startButton.setDisable(false);
            stopButton.setDisable(true);
            statusLabel.setText("⏹️ Monitoring stopped");
        }
    }

    private void startUpdateTimer() {
        new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(1000);
                    Platform.runLater(this::updateStats);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }).start();
    }

    private void updateStats() {
        if (captureService != null) {
            connectionsLabel.setText("Active Connections: " + captureService.getConnectionCount());
            incomingLabel.setText("Incoming Packets: " + captureService.getIncomingCount());
            outgoingLabel.setText("Outgoing Packets: " + captureService.getOutgoingCount());
        }
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
