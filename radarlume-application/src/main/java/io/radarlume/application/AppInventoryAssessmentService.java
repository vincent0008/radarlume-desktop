package io.radarlume.application;

import io.radarlume.domain.*;
import java.util.*;

/**
 * Regole euristiche sui metadati delle app installate (versione, origine, permessi), lette da
 * {@code dumpsys package}. Sono osservazioni, non verdetti: un'origine diversa da uno store o un permesso
 * concesso non dimostrano un comportamento abusivo. Riporta nomi e conteggi, mai i valori d'uso. Le soglie
 * sono del progetto, da tarare su dispositivi reali.
 */
public final class AppInventoryAssessmentService {
    private AppInventoryAssessmentService() {}

    /** Store riconosciuti: un'app installata da qui ha un'origine verificabile. */
    private static final Set<String> KNOWN_STORES = Set.of(
            "com.android.vending", "com.google.android.feedback",
            "com.sec.android.app.samsungapps", "com.samsung.android.app.appsstore",
            "org.fdroid.fdroid", "org.fdroid.basic",
            "com.amazon.venezia", "com.huawei.appmarket",
            "com.xiaomi.market", "com.heytap.market", "com.oppo.market");

    /** Permesso (suffisso) → etichetta leggibile. Più suffissi possono condividere la stessa etichetta. */
    private static final Map<String, String> SENSITIVE = new LinkedHashMap<>();
    static {
        SENSITIVE.put("READ_SMS", "SMS");
        SENSITIVE.put("RECEIVE_SMS", "SMS");
        SENSITIVE.put("SEND_SMS", "SMS");
        SENSITIVE.put("READ_CONTACTS", "contatti");
        SENSITIVE.put("ACCESS_FINE_LOCATION", "posizione");
        SENSITIVE.put("ACCESS_BACKGROUND_LOCATION", "posizione in background");
        SENSITIVE.put("RECORD_AUDIO", "microfono");
        SENSITIVE.put("CAMERA", "fotocamera");
        SENSITIVE.put("READ_CALL_LOG", "registro chiamate");
        SENSITIVE.put("READ_PHONE_STATE", "stato telefono");
        SENSITIVE.put("QUERY_ALL_PACKAGES", "elenco di tutte le app");
        SENSITIVE.put("SYSTEM_ALERT_WINDOW", "sovrapposizione schermo");
        SENSITIVE.put("REQUEST_INSTALL_PACKAGES", "installare app");
        SENSITIVE.put("MANAGE_EXTERNAL_STORAGE", "tutti i file");
        SENSITIVE.put("PACKAGE_USAGE_STATS", "statistiche d'uso");
        SENSITIVE.put("BIND_ACCESSIBILITY_SERVICE", "accessibilità");
        SENSITIVE.put("BIND_NOTIFICATION_LISTENER_SERVICE", "lettura notifiche");
        SENSITIVE.put("BIND_DEVICE_ADMIN", "amministrazione dispositivo");
    }

    private static final int MIN_SENSITIVE = 2; // soglia euristica: quante categorie sensibili per segnalare
    private static final int MAX_LISTED = 15;   // pacchetti elencati per non rendere illeggibile il report

    public static List<Finding> evaluate(List<InstalledApp> apps, String evidenceKey) {
        var findings = new ArrayList<Finding>();
        var thirdParty = apps.stream().filter(a -> !a.system()).toList();

        if (!thirdParty.isEmpty() && thirdParty.stream().noneMatch(a -> a.metadata().known())) {
            findings.add(new Finding("DATA-008", "1", Finding.Severity.INFO, Finding.Confidence.HIGH, evidenceKey,
                    "Metadati app non letti: versione, origine di installazione e permessi non disponibili. L'analisi dell'origine (AND-003) e dei permessi (AND-004) non è stata eseguita.",
                    "Verificare che il dispositivo risponda a \"dumpsys package\"; su alcune versioni Android o profili limitati il comando è ridotto. Non dedurre assenza di rischio."));
            return List.copyOf(findings);
        }

        var unknownOrigin = new ArrayList<String>();
        for (var app : thirdParty) {
            if (!app.metadata().known()) continue;
            String installer = app.metadata().installer();
            if (installer.isEmpty() || !KNOWN_STORES.contains(installer)) unknownOrigin.add(app.packageName());
        }
        if (!unknownOrigin.isEmpty())
            findings.add(new Finding("AND-003", "1", Finding.Severity.INFO, Finding.Confidence.LOW, evidenceKey,
                    unknownOrigin.size() + " app non di sistema risultano installate da un'origine diversa dagli store conosciuti (origine non registrata o sideload): "
                            + list(unknownOrigin) + ". Il sideload è legittimo: F-Droid, APK diretti, strumenti di sviluppo. Un'origine non nota non dimostra che l'app sia dannosa.",
                    "Confrontare ogni pacchetto con le app che il proprietario ricorda di aver installato e con la fonte dichiarata."));

        var sensitiveApps = new ArrayList<String>();
        for (var app : thirdParty) {
            if (!app.metadata().known()) continue;
            var labels = sensitiveGranted(app.metadata());
            if (labels.size() >= MIN_SENSITIVE)
                sensitiveApps.add(app.packageName() + " (" + String.join(", ", labels) + ")");
        }
        if (!sensitiveApps.isEmpty())
            findings.add(new Finding("AND-004", "1", Finding.Severity.INFO, Finding.Confidence.LOW, evidenceKey,
                    sensitiveApps.size() + " app non di sistema hanno almeno " + MIN_SENSITIVE + " categorie di permessi sensibili concessi: "
                            + list(sensitiveApps) + ". Avere un permesso non dimostra come viene usato: molte app legittime ne richiedono diversi.",
                    "Per ogni app chiedersi se quei permessi sono coerenti con la funzione dichiarata; revocare quelli non necessari dalle impostazioni."));

        return List.copyOf(findings);
    }

    private static Set<String> sensitiveGranted(AppMetadata metadata) {
        var labels = new LinkedHashSet<String>();
        for (var entry : SENSITIVE.entrySet())
            if (metadata.hasGranted(entry.getKey())) labels.add(entry.getValue());
        return labels;
    }

    private static String list(List<String> names) {
        if (names.size() <= MAX_LISTED) return String.join(", ", names);
        return String.join(", ", names.subList(0, MAX_LISTED)) + " e altre " + (names.size() - MAX_LISTED);
    }
}
