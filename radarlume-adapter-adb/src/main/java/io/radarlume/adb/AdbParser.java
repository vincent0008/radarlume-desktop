package io.radarlume.adb;

import io.radarlume.domain.*;
import java.util.*;

public final class AdbParser {
    private AdbParser() {}
    public static List<Device> devices(String output) {
        var result = new ArrayList<Device>();
        boolean header = false;
        for (String line : output.lines().toList()) {
            line = line.trim();
            if (line.startsWith("List of devices attached")) { header = true; continue; }
            if (line.isEmpty() || line.startsWith("* daemon")) continue;
            if (!header) throw new ScanException("Risposta ADB non riconosciuta.");
            String[] parts = line.split("\\s+");
            if (parts.length < 2) throw new ScanException("Elenco dispositivi ADB incompleto.");
            Device.State state = switch (parts[1]) {
                case "device" -> Device.State.AUTHORIZED;
                case "unauthorized" -> Device.State.UNAUTHORIZED;
                case "offline" -> Device.State.OFFLINE;
                case "no" -> Device.State.NO_PERMISSIONS;
                default -> Device.State.OTHER;
            };
            String model = Arrays.stream(parts).filter(p -> p.startsWith("model:"))
                    .map(p -> p.substring(6).replace('_', ' ')).findFirst().orElse("Android / ADB");
            result.add(new Device(parts[0], state, model));
        }
        if (!header) throw new ScanException("Intestazione ADB mancante.");
        return List.copyOf(result);
    }
    public static Set<String> packages(String output) {
        var result = new TreeSet<String>();
        for (String line : output.lines().toList()) {
            if (line.isBlank()) continue;
            if (!line.startsWith("package:")) throw new ScanException("Inventario non disponibile: risposta package manager non riconosciuta.");
            String name = line.substring(8).trim();
            try { new InstalledApp(name, false); }
            catch (IllegalArgumentException e) { throw new ScanException("Nome pacchetto ADB non valido.", e); }
            result.add(name);
        }
        return Collections.unmodifiableSet(result);
    }
}
