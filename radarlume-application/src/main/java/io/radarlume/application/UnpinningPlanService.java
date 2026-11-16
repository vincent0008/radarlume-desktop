package io.radarlume.application;

import io.radarlume.domain.*;
import io.radarlume.domain.UnpinningPlan.Step;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Costruisce un {@link UnpinningPlan} per un'app sospetta: script, comandi, verifica e limiti. Non esegue
 * nulla sul dispositivo e non contatta la rete; l'operatore applica i passi su un dispositivo di test.
 * Tutti gli strumenti citati sono gratuiti e open source. La verifica si chiude in RadarLume: dopo
 * l'intervento si ripete la cattura e si guarda DATA-007 (quante connessioni TLS sono diventate leggibili).
 */
public final class UnpinningPlanService {
    private UnpinningPlanService() {}

    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*");

    private static final List<String> SAFETY = List.of(
            "Usare solo un dispositivo di test di cui si ha il pieno controllo, non il telefono in uso quotidiano.",
            "Modificare, ricompilare o agganciare un'app richiede l'autorizzazione a farlo: è una verifica, non un attacco a sistemi altrui.",
            "Lo scopo è diagnostico: rendere leggibile il traffico per capirlo, non aggirare protezioni di servizi di terzi.");

    private static final List<String> VERIFICATION = List.of(
            "Ripetere la cattura con PCAPdroid (decrittazione TLS attiva) mentre l'app sospetta genera traffico.",
            "Esportare .pcap e .keylog e reimportarli in RadarLume con le chiavi TLS attive.",
            "Guardare DATA-007: se le connessioni dell'app sono passate da cifrate a leggibili, l'unpinning ha funzionato.",
            "Se le connessioni dell'app restano cifrate nonostante le chiavi, la tecnica non ha avuto effetto su questa app: provarne un'altra o prendere atto che non è decifrabile senza più sforzo.");

    public static UnpinningPlan plan(String packageName, UnpinningTechnique technique, String adbExecutable) {
        if (packageName == null || !PACKAGE.matcher(packageName).matches())
            throw new IllegalArgumentException("Nome pacchetto non valido");
        String adb = quote(adbExecutable == null || adbExecutable.isBlank() ? "adb" : adbExecutable.strip());
        return switch (technique) {
            case FRIDA -> frida(packageName, adb);
            case APK_MITM -> apkMitm(packageName, adb);
            case MOVECERT -> moveCert(packageName, adb);
        };
    }

    private static UnpinningPlan frida(String pkg, String adb) {
        var prerequisites = List.of(
                "Dispositivo di test con root e " + UnpinningTechnique.FRIDA.mainPrerequisite() + ".",
                "frida-tools sul PC (pip install frida-tools).",
                "PCAPdroid con decrittazione TLS attiva e CA utente installata.");
        var steps = List.of(
                new Step("Avvia frida-server sul dispositivo",
                        "Da una shell root sul dispositivo. Il binario deve corrispondere all'architettura del telefono.",
                        adb + " shell \"su -c '/data/local/tmp/frida-server &'\""),
                new Step("Verifica che Frida veda il dispositivo",
                        "Deve elencare i processi: se fallisce, frida-server non è in esecuzione o la versione non combacia.",
                        "frida-ps -U"),
                new Step("Avvia l'app con lo script agganciato",
                        "Spawn del pacchetto con lo script di unpinning. Lascia aperta questa finestra durante la cattura.",
                        "frida -U -f " + pkg + " -l " + UnpinningScripts.FRIDA_FILE_NAME + " --no-pause"),
                new Step("Cattura e usa l'app",
                        "Con PCAPdroid in cattura (solo questa app nei filtri), naviga le funzioni che generano traffico."),
                new Step("Esporta e reimporta",
                        "Esporta .pcap e .keylog da PCAPdroid e reimportali in RadarLume per la verifica."));
        var limits = List.of(
                "Il pinning nativo in C/C++ non passa dalle API Java agganciate: lo script non lo tocca.",
                "App con rilevamento di Frida o di root possono chiudersi o cambiare comportamento.",
                "Offuscamento e classi rinominate possono spostare i punti da agganciare.");
        return new UnpinningPlan(pkg, UnpinningTechnique.FRIDA, prerequisites, steps,
                UnpinningScripts.FRIDA_FILE_NAME, UnpinningScripts.frida(pkg), VERIFICATION, limits, SAFETY);
    }

    private static UnpinningPlan apkMitm(String pkg, String adb) {
        var prerequisites = List.of(
                "Node.js sul PC e " + UnpinningTechnique.APK_MITM.mainPrerequisite() + " (npx apk-mitm).",
                "Nessun root richiesto, ma serve poter disinstallare e reinstallare l'app di test.");
        var steps = List.of(
                new Step("Trova il percorso dell'APK sul dispositivo",
                        "Elenca i file APK del pacchetto. Se ne compaiono più d'uno è un'app divisa (split/bundle): apk-mitm può non bastare.",
                        adb + " shell pm path " + pkg),
                new Step("Scarica l'APK sul PC",
                        "Sostituisci il percorso con quello stampato dal comando precedente.",
                        adb + " pull /data/app/.../base.apk " + pkg + ".apk"),
                new Step("Riscrivi e ricompila",
                        "apk-mitm riscrive il network_security_config per fidarsi anche dei certificati utente e rifirma l'APK.",
                        "npx apk-mitm " + pkg + ".apk"),
                new Step("Installa la versione modificata",
                        "Disinstalla l'originale e installa quella patchata sul dispositivo di test.",
                        adb + " uninstall " + pkg + " && " + adb + " install " + pkg + "-patched.apk"),
                new Step("Cattura e reimporta",
                        "Con PCAPdroid in cattura usa l'app, poi esporta .pcap e .keylog e reimportali in RadarLume."));
        var limits = List.of(
                "Non aggira il pinning esplicito (OkHttp CertificatePinner o pin nei TrustManager): riscrive solo la fiducia nei cert utente.",
                "App con controllo di integrità o firma rifiutano l'APK ricompilato.",
                "Le app divise in più APK (bundle) richiedono passaggi aggiuntivi che apk-mitm non copre sempre.");
        return new UnpinningPlan(pkg, UnpinningTechnique.APK_MITM, prerequisites, steps, "", "", VERIFICATION, limits, SAFETY);
    }

    private static UnpinningPlan moveCert(String pkg, String adb) {
        var prerequisites = List.of(
                UnpinningTechnique.MOVECERT.mainPrerequisite() + " e un modulo che sposti le CA utente tra quelle di sistema.",
                "CA di intercettazione già installata come certificato utente.");
        var steps = List.of(
                new Step("Installa il modulo Magisk",
                        "Un modulo come movecert/AlwaysTrustUserCerts copia la CA utente nello store di sistema."),
                new Step("Riavvia il dispositivo",
                        "Dopo il riavvio la CA di intercettazione risulta di sistema."),
                new Step("Verifica la fiducia",
                        "Le app che si fidano degli store di sistema (e non fanno pinning esplicito) ora accettano il certificato."),
                new Step("Cattura e reimporta",
                        "Con PCAPdroid in cattura usa l'app, poi esporta .pcap e .keylog e reimportali in RadarLume."));
        var limits = List.of(
                "Non ha alcun effetto sul pinning esplicito: serve solo contro la sfiducia verso i certificati utente introdotta da Android 7.",
                "Richiede root con Magisk sul dispositivo di test.");
        return new UnpinningPlan(pkg, UnpinningTechnique.MOVECERT, prerequisites, steps, "", "", VERIFICATION, limits, SAFETY);
    }

    private static String quote(String executable) {
        return executable.chars().anyMatch(Character::isWhitespace) ? "\"" + executable + "\"" : executable;
    }
}
