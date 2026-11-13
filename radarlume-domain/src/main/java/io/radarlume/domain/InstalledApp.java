package io.radarlume.domain;

public record InstalledApp(String packageName, boolean system) {
    public InstalledApp {
        if (packageName == null || !packageName.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*"))
            throw new IllegalArgumentException("Nome pacchetto non valido");
    }
}
