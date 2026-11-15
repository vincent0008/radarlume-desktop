package io.radarlume.domain;

import java.time.Instant;
import java.util.List;

/**
 * A name seen in clear-text DNS traffic inside the capture.
 * Zero responses means "no answer observed", not "the name does not exist".
 */
public record DnsName(String name, long queries, long responses, List<String> addresses,
                      Instant firstSeen, Instant lastSeen) {
    public DnsName { addresses = List.copyOf(addresses); }
}
