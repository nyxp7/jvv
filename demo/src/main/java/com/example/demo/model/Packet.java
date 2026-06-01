package com.example.demo.model;

public class Packet {

    private String sourceIp;
    private String destinationIp;
    private int sourcePort;
    private int destinationPort;
    private String protocol;
    private String payload;
    private long timestamp;
    private int size;
    public Packet(String sourceIp, String destinationIp,
                  int sourcePort, int destinationPort,
                  String protocol, String payload,
                  long timestamp, int size) {

        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.payload = payload;
        this.timestamp = timestamp;
        this.size = size;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getPayload() {
        return payload;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public int getSize(){
        return size;
    }

}