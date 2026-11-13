package io.radarlume.domain;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record Inventory(UUID id, Instant collectedAt, Device device, List<InstalledApp> apps) {
    public Inventory {
        Objects.requireNonNull(id); Objects.requireNonNull(collectedAt); Objects.requireNonNull(device);
        apps = List.copyOf(apps);
    }
}
