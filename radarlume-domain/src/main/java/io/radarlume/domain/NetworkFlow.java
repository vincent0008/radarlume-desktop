package io.radarlume.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * Directional TCP/UDP flow over the entire imported capture.
 *
 * @param bytes      sum of IP packet lengths (falls back to frame length when the IP length is not available)
 * @param app        app declared by the capture tool's own metadata, or {@code null} when the capture carries none.
 *                   Never inferred from addresses or timing.
 * @param serverName TLS server name (SNI) observed in clear text inside this flow, or empty
 */
public record NetworkFlow(String source, String destination, String protocol,
                          String sourcePort, String destinationPort, long packets, long bytes,
                          Instant firstSeen, Instant lastSeen, CaptureApp app, String serverName) {
    public NetworkFlow {
        Objects.requireNonNull(firstSeen);
        Objects.requireNonNull(lastSeen);
        Objects.requireNonNull(serverName);
    }
}
