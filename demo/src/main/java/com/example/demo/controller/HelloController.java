package com.example.demo.controller;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;

public class HelloController {
    @FXML
    private Label welcomeText;
    @FXML
    private Label connectionsLabel;

    @FXML
    private Label incomingLabel;

    @FXML
    private Label outgoingLabel;

    @FXML
    private TextArea alertArea;

    public void initialize() {
        connectionsLabel.setText("Active connections: 0");
        incomingLabel.setText("Incoming packets: 0");
        outgoingLabel.setText("Outgoing packets: 0");
        alertArea.setText("alert");
    }

    @FXML
    protected void onHelloButtonClick() {
        welcomeText.setText("bonjour");
    }
}
