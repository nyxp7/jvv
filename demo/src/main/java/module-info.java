module com.example.demo {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.web;

    requires org.kordamp.bootstrapfx.core;
    requires eu.hansolo.tilesfx;
    requires org.pcap4j.core;

    opens com.example.demo to javafx.fxml;
    exports com.example.demo;
    exports com.example.demo.service;
    opens com.example.demo.service to javafx.fxml;
    exports com.example.demo.controller;
    opens com.example.demo.controller to javafx.fxml;
}