package io.radarlume.domain;

import java.util.Objects;

public record Device(String serial, State state, String model) {
    public enum State { AUTHORIZED, UNAUTHORIZED, OFFLINE, NO_PERMISSIONS, OTHER }
    public Device {
        Objects.requireNonNull(serial); Objects.requireNonNull(state); Objects.requireNonNull(model);
        if (serial.isBlank()) throw new IllegalArgumentException("Seriale mancante");
    }
    @Override public String toString() { return model + " · " + serial + " · " + state; }
}
