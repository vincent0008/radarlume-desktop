package io.radarlume.domain;
import java.time.Instant;
public record Evidence(String key, String value, String source, Instant collectedAt, Status status) {
    public enum Status { AVAILABLE, UNAVAILABLE }
}
