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
    /**
     * Estrae i metadati per pacchetto da {@code dumpsys package}. Best-effort: i campi assenti restano
     * vuoti e un blocco malformato non interrompe il resto. La lettura si ferma alle sezioni duplicate
     * ("Hidden system packages:") per non sovrascrivere i pacchetti reali. Non lancia eccezioni: se il
     * formato non è riconosciuto restituisce una mappa vuota, e l'inventario resta valido senza metadati.
     */
    public static Map<String, AppMetadata> appMetadata(String output) {
        var result = new HashMap<String, AppMetadata>();
        String pkg = null, versionName = "", installer = "";
        long versionCode = -1L;
        var requested = new LinkedHashSet<String>();
        var granted = new LinkedHashSet<String>();
        int section = 0; // 0 nessuna, 1 requested permissions, 2 install/runtime permissions
        for (String raw : output.lines().toList()) {
            String line = raw.strip();
            int open = raw.indexOf("Package [");
            if (open >= 0 && open == firstNonSpace(raw)) {
                if (pkg != null) flush(result, pkg, versionName, versionCode, installer, requested, granted);
                int close = raw.indexOf(']', open);
                pkg = close > open ? raw.substring(open + 9, close) : null;
                versionName = ""; installer = ""; versionCode = -1L; requested.clear(); granted.clear(); section = 0;
                continue;
            }
            if (line.equals("Hidden system packages:")) break;
            if (pkg == null) continue;
            if (line.startsWith("versionName=")) { versionName = line.substring(12).strip(); section = 0; continue; }
            if (line.startsWith("versionCode=")) { versionCode = parseVersionCode(line.substring(12)); section = 0; continue; }
            if (line.startsWith("installerPackageName=")) {
                String v = line.substring(21).strip();
                installer = v.equals("null") ? "" : v; section = 0; continue;
            }
            if (line.equals("requested permissions:")) { section = 1; continue; }
            if (line.equals("install permissions:") || line.equals("runtime permissions:")) { section = 2; continue; }
            if (line.endsWith(":")) { section = 0; continue; } // qualsiasi altra intestazione chiude la sezione permessi
            if (section == 1) { String p = permissionToken(line); if (p != null) requested.add(p); }
            else if (section == 2) {
                String p = permissionToken(line);
                if (p != null && line.contains("granted=true")) { granted.add(p); requested.add(p); }
            }
        }
        if (pkg != null) flush(result, pkg, versionName, versionCode, installer, requested, granted);
        return Map.copyOf(result);
    }

    private static int firstNonSpace(String s) { int i = 0; while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; return i; }

    private static long parseVersionCode(String rest) {
        int i = 0; while (i < rest.length() && Character.isDigit(rest.charAt(i))) i++;
        try { return i > 0 ? Long.parseLong(rest.substring(0, i)) : -1L; } catch (NumberFormatException e) { return -1L; }
    }

    private static String permissionToken(String line) {
        int end = 0;
        while (end < line.length() && (Character.isLetterOrDigit(line.charAt(end)) || line.charAt(end) == '.' || line.charAt(end) == '_')) end++;
        if (end == 0) return null;
        String token = line.substring(0, end);
        return token.contains(".") ? token : null; // scarta righe che non sono nomi di permesso
    }

    private static void flush(Map<String, AppMetadata> result, String pkg, String versionName, long versionCode,
                              String installer, Set<String> requested, Set<String> granted) {
        if (pkg.isBlank() || result.containsKey(pkg)) return;
        result.put(pkg, new AppMetadata(versionName, versionCode, installer, List.copyOf(requested), List.copyOf(granted)));
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
