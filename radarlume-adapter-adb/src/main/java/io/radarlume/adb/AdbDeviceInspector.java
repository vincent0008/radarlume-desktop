package io.radarlume.adb;

import io.radarlume.domain.*;
import io.radarlume.process.CommandRunner;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public final class AdbDeviceInspector implements DeviceInspector {
    private final String executable;
    private final CommandRunner runner;
    public AdbDeviceInspector(String executable, CommandRunner runner) { this.executable = executable; this.runner = runner; }
    @Override public List<Device> discover() {
        return AdbParser.devices(runner.run(List.of(executable, "devices", "-l"), Duration.ofSeconds(20)));
    }
    @Override public List<InstalledApp> inventory(String serial) {
        if (serial == null || !serial.matches("[A-Za-z0-9][A-Za-z0-9._:\\[\\]%-]{0,255}"))
            throw new ScanException("Seriale ADB non valido.");
        // Explicit serial and fixed remote arguments: no user-provided shell fragments.
        var all = AdbParser.packages(runner.run(List.of(executable, "-s", serial, "shell", "pm", "list", "packages"), Duration.ofSeconds(30)));
        var system = AdbParser.packages(runner.run(List.of(executable, "-s", serial, "shell", "pm", "list", "packages", "-s"), Duration.ofSeconds(30)));
        if (all.isEmpty()) throw new ScanException("Inventario vuoto: impossibile confermare la raccolta dei pacchetti.");
        if (!all.containsAll(system)) throw new ScanException("Inventario cambiato durante la lettura. Ripeti la scansione.");
        var metadata = metadata(serial);
        return all.stream().map(name -> new InstalledApp(name, system.contains(name), metadata.getOrDefault(name, AppMetadata.UNKNOWN))).toList();
    }

    /** Metadati app best-effort: un errore qui non invalida l'inventario, i pacchetti restano senza metadati. */
    private Map<String, AppMetadata> metadata(String serial) {
        try {
            return AdbParser.appMetadata(runner.run(
                    List.of(executable, "-s", serial, "shell", "dumpsys", "package"), Duration.ofSeconds(60)));
        } catch (RuntimeException e) {
            return Map.of();
        }
    }
}
