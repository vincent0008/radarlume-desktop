package io.radarlume.domain;

import java.time.Instant;
import java.util.List;

/**
 * Result of importing one capture file, with the provenance needed to say which file produced it.
 *
 * @param packets     TCP/UDP packets over IPv4/IPv6 that were considered; other traffic is not counted
 * @param firstPacket {@code null} when no packet was considered
 * @param truncated   the file ended in the middle of a packet: only the complete packets were analysed
 * @param warnings    limits that apply to this specific result, to be shown next to it
 * @param tls         what could and could not be read inside TLS
 * @param requests    HTTP requests sent unencrypted or read thanks to the session keys
 */
public record CaptureAnalysis(String fileName, long fileBytes, String sha256, long packets,
                              Instant firstPacket, Instant lastPacket, AppMetadata appMetadata, boolean truncated,
                              List<NetworkFlow> flows, List<DnsName> dnsNames, List<String> warnings,
                              Tls tls, List<HttpRequest> requests) {
    public enum AppMetadata { NONE, PCAPDROID_TRAILER }

    /**
     * @param keylogUsed  a file of TLS session keys was given to the decoder
     * @param connections TCP connections carrying TLS
     * @param decrypted   of those, the ones where HTTP content became readable
     */
    public record Tls(boolean keylogUsed, long connections, long decrypted) {
        public static final Tls NOT_EXAMINED = new Tls(false, 0, 0);
    }

    public CaptureAnalysis {
        flows = List.copyOf(flows);
        dnsNames = List.copyOf(dnsNames);
        warnings = List.copyOf(warnings);
        requests = List.copyOf(requests);
    }
}
