package io.radarlume.domain;

/**
 * Tecniche gratuite e open source per rendere leggibile il TLS di un'app che rifiuta il certificato
 * di intercettazione. Nessuna è garantita: il pinning nativo, l'offuscamento, gli anti-Frida e i
 * controlli di integrità possono farle fallire. Si applicano a una singola app sospetta, su un
 * dispositivo di test di cui si ha il pieno controllo.
 */
public enum UnpinningTechnique {
    /** Frida aggancia a runtime le API TLS note e le neutralizza. Copre molte app Java/Kotlin; serve frida-server (root) o la gadget. */
    FRIDA("Frida + script di unpinning", true, "Frida (frida-server sul dispositivo o gadget nell'APK)"),
    /** apk-mitm riscrive il network_security_config e ricompila l'APK. Non serve root; fallisce su integrity check o pinning nativo. */
    APK_MITM("Repackaging con apk-mitm", false, "Node.js e apk-mitm sul PC"),
    /** movecert (Magisk) sposta la CA utente tra quelle di sistema. Aggira la sfiducia verso i cert utente, non il pinning esplicito. */
    MOVECERT("CA di sistema con Magisk (movecert)", true, "Dispositivo con Magisk");

    private final String label;
    private final boolean needsRoot;
    private final String mainPrerequisite;

    UnpinningTechnique(String label, boolean needsRoot, String mainPrerequisite) {
        this.label = label; this.needsRoot = needsRoot; this.mainPrerequisite = mainPrerequisite;
    }

    public String label() { return label; }
    public boolean needsRoot() { return needsRoot; }
    public String mainPrerequisite() { return mainPrerequisite; }
}
