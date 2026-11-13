package io.radarlume.adb;

import io.radarlume.domain.*;
import io.radarlume.process.CommandRunner;
import java.time.Duration;
import java.util.List;

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
        return all.stream().map(name -> new InstalledApp(name, system.contains(name))).toList();
    }
}
