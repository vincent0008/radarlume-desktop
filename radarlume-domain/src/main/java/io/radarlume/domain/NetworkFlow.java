package io.radarlume.domain;

/** Directional TCP/UDP flow over the entire imported capture, not an application attribution. */
public record NetworkFlow(String source, String destination, String protocol,
                          String sourcePort, String destinationPort, long packets, long bytes) {}
