package io.radarlume.domain;

public record ToolSettings(String adb, String tshark) {
    public ToolSettings {
        adb = validate(adb); tshark = validate(tshark);
    }
    private static String validate(String value) {
        if (value == null || value.isBlank() || value.length() > 4096 || value.chars().anyMatch(Character::isISOControl) || value.contains("\""))
            throw new ScanException("Inserisci un percorso o comando valido, senza virgolette o caratteri di controllo.");
        return value.strip();
    }
}
