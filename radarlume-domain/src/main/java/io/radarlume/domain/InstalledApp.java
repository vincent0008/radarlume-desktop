package io.radarlume.domain;

public record InstalledApp(String packageName, boolean system, AppMetadata metadata) {
    public InstalledApp {
        if (packageName == null || !packageName.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*"))
            throw new IllegalArgumentException("Nome pacchetto non valido");
        if (metadata == null) metadata = AppMetadata.UNKNOWN;
    }

    /** Pacchetto senza metadati letti (compatibilità con inventario di base e storico). */
    public InstalledApp(String packageName, boolean system) {
        this(packageName, system, AppMetadata.UNKNOWN);
    }
}
