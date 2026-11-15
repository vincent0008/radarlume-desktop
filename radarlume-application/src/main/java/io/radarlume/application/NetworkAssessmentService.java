package io.radarlume.application;

import io.radarlume.domain.*;
import java.util.*;

/**
 * First network rules. Each one points at something worth a closer look and says why;
 * none of them is, or should be read as, a verdict of malware or data theft.
 * Thresholds are project heuristics chosen to be discussed and tuned, not established limits.
 */
public final class NetworkAssessmentService {
    /** NET-002 ignores exchanges where less than this was sent: small uploads are ordinary. */
    public static final long UPLOAD_MIN_BYTES = 512 * 1024;
    /** NET-002 requires the bytes sent to be at least this many times the bytes received. */
    public static final int UPLOAD_RATIO = 2;
    /** NET-003 fires when one app contacts at least this many distinct remote addresses in the capture. */
    public static final int MANY_DESTINATIONS = 20;
    static final int MAX_FINDINGS_PER_RULE = 100;

    private static final String CAPTURE = "cattura";

    private NetworkAssessmentService() {}

    /**
     * Two directional flows seen as one exchange between the capturing device and a remote endpoint.
     * Which side is "remote" is a heuristic (see {@link #conversations}), stated in the explanations.
     */
    record Conversation(String remote, String remotePort, CaptureApp app, long sent, long received,
                        String serverName, String httpHost) {
        String remoteLabel() {
            String name = !serverName.isEmpty() ? serverName : httpHost;
            return name.isEmpty() ? remote : name + " (" + remote + ")";
        }
    }

    public static List<Finding> evaluate(CaptureAnalysis analysis) {
        var findings = new ArrayList<Finding>();
        if (analysis.truncated())
            findings.add(new Finding("DATA-003", "1", Finding.Severity.INFO, Finding.Confidence.HIGH, CAPTURE,
                    "Cattura troncata: le regole hanno visto solo una parte del traffico.",
                    "Ripetere l'esportazione o la copia del file; non dedurre nulla dall'assenza di osservazioni."));
        if (analysis.packets() == 0) {
            findings.add(new Finding("DATA-005", "1", Finding.Severity.INFO, Finding.Confidence.HIGH, CAPTURE,
                    "Nessun pacchetto TCP/UDP analizzabile: nessuna regola applicata.",
                    "Verificare che la cattura sia stata avviata e che il file non sia vuoto."));
            return List.copyOf(findings);
        }
        boolean apps = analysis.appMetadata() != CaptureAnalysis.AppMetadata.NONE;
        if (!apps)
            findings.add(new Finding("DATA-004", "1", Finding.Severity.INFO, Finding.Confidence.HIGH, CAPTURE,
                    "La cattura non indica quale app ha generato il traffico: la regola NET-003 non è applicabile e le altre non distinguono le app.",
                    "In PCAPdroid attivare \"PCAPdroid extensions\" con formato PCAP e ripetere la cattura."));

        var conversations = conversations(analysis.flows());
        clearTextHttp(conversations, findings);
        uploadImbalance(conversations, findings);
        if (apps) manyDestinations(conversations, findings);
        return List.copyOf(findings);
    }

    /** NET-001: an unencrypted HTTP request was decoded. This is an observation of fact, hence high confidence. */
    private static void clearTextHttp(List<Conversation> conversations, List<Finding> findings) {
        var counts = new LinkedHashMap<String, Integer>();
        for (var c : conversations)
            if (!c.httpHost().isEmpty()) counts.merge(label(c.app()) + " → " + c.httpHost(), 1, Integer::sum);
        var rule = new ArrayList<Finding>();
        counts.forEach((key, count) -> rule.add(new Finding("NET-001", "1", Finding.Severity.MEDIUM, Finding.Confidence.HIGH, key,
                "Richiesta HTTP non cifrata (" + count + (count == 1 ? " connessione" : " connessioni")
                        + "). Chi si trova sul percorso di rete può leggerne e modificarne il contenuto. "
                        + "È una debolezza di riservatezza, non la prova di un comportamento malevolo: capita anche con controlli di connettività e vecchie librerie.",
                "Aprire la cattura in Wireshark con il filtro http e leggere quali dati contiene la richiesta (indirizzo, parametri, intestazioni).")));
        addBounded("NET-001", rule, findings);
    }

    /** NET-002: much more data sent than received towards one remote address. */
    private static void uploadImbalance(List<Conversation> conversations, List<Finding> findings) {
        record Total(String label, long[] bytes) {}
        var totals = new LinkedHashMap<String, Total>();
        for (var c : conversations) {
            Total total = totals.computeIfAbsent(label(c.app()) + "|" + c.remote(),
                    ignored -> new Total(label(c.app()) + " → " + c.remoteLabel(), new long[2]));
            total.bytes()[0] += c.sent();
            total.bytes()[1] += c.received();
        }
        var rule = new ArrayList<Finding>();
        totals.values().stream()
                .filter(t -> t.bytes()[0] >= UPLOAD_MIN_BYTES && t.bytes()[0] >= UPLOAD_RATIO * t.bytes()[1])
                .sorted(Comparator.comparingLong((Total t) -> t.bytes()[0]).reversed())
                .forEach(t -> rule.add(new Finding("NET-002", "1", Finding.Severity.MEDIUM, Finding.Confidence.LOW, t.label(),
                        "Inviati " + size(t.bytes()[0]) + ", ricevuti " + size(t.bytes()[1]) + ": il dispositivo ha caricato molto più di quanto ha scaricato. "
                                + "Backup, invio di foto o video, chiamate e sincronizzazioni producono lo stesso schema; la direzione è stimata da porte e ordine dei pacchetti. "
                                + "Soglia euristica: almeno " + size(UPLOAD_MIN_BYTES) + " inviati e almeno " + UPLOAD_RATIO + " volte il ricevuto.",
                        "Chiedersi se in quel momento era in corso un caricamento voluto; in caso contrario identificare la destinazione e ripetere la cattura con la sola app interessata.")));
        addBounded("NET-002", rule, findings);
    }

    /** NET-003: one app talking to many distinct remote addresses. Context only: browsers and ad-supported apps do this routinely. */
    private static void manyDestinations(List<Conversation> conversations, List<Finding> findings) {
        var remotes = new LinkedHashMap<String, Set<String>>();
        for (var c : conversations)
            if (c.app() != null) remotes.computeIfAbsent(c.app().toString(), ignored -> new HashSet<>()).add(c.remote());
        var rule = new ArrayList<Finding>();
        remotes.entrySet().stream()
                .filter(e -> e.getValue().size() >= MANY_DESTINATIONS)
                .sorted(Comparator.comparingInt((Map.Entry<String, Set<String>> e) -> e.getValue().size()).reversed())
                .forEach(e -> rule.add(new Finding("NET-003", "1", Finding.Severity.INFO, Finding.Confidence.LOW, e.getKey(),
                        "L'app ha contattato " + e.getValue().size() + " indirizzi remoti distinti (soglia euristica: " + MANY_DESTINATIONS + "). "
                                + "Per browser, social e app con pubblicità è normale; è insolito per app con una funzione semplice e locale.",
                        "Confrontare il numero con ciò che l'app dichiara di fare e guardare i nomi contattati nelle tabelle Flussi e DNS.")));
        addBounded("NET-003", rule, findings);
    }

    private static void addBounded(String ruleId, List<Finding> rule, List<Finding> findings) {
        findings.addAll(rule.subList(0, Math.min(rule.size(), MAX_FINDINGS_PER_RULE)));
        if (rule.size() > MAX_FINDINGS_PER_RULE)
            findings.add(new Finding("DATA-006", "1", Finding.Severity.INFO, Finding.Confidence.HIGH, ruleId,
                    "Elenco limitato: altre " + (rule.size() - MAX_FINDINGS_PER_RULE) + " osservazioni " + ruleId + " non sono mostrate.",
                    "Ridurre la durata della cattura o filtrare per app in PCAPdroid."));
    }

    /**
     * Pairs each flow with the one in the opposite direction and decides which end is remote:
     * a well-known port (below 1024) against a higher one marks the server; otherwise the side that spoke first
     * is taken as the device. A capture that starts mid-connection can get this wrong.
     */
    static List<Conversation> conversations(List<NetworkFlow> flows) {
        record Key(String a, String aPort, String b, String bPort, String protocol) {}
        var byKey = new HashMap<Key, NetworkFlow>();
        for (var f : flows) byKey.put(new Key(f.source(), f.sourcePort(), f.destination(), f.destinationPort(), f.protocol()), f);
        var done = new HashSet<Key>();
        var result = new ArrayList<Conversation>();
        for (var f : flows) {
            Key key = new Key(f.source(), f.sourcePort(), f.destination(), f.destinationPort(), f.protocol());
            Key reverseKey = new Key(f.destination(), f.destinationPort(), f.source(), f.sourcePort(), f.protocol());
            if (done.contains(key)) continue;
            done.add(key);
            done.add(reverseKey);
            NetworkFlow reverse = byKey.get(reverseKey);
            boolean outbound = isOutbound(f, reverse);
            NetworkFlow out = outbound ? f : reverse, in = outbound ? reverse : f;
            NetworkFlow any = out != null ? out : in;
            result.add(new Conversation(
                    out != null ? out.destination() : in.source(),
                    out != null ? out.destinationPort() : in.sourcePort(),
                    out != null && out.app() != null ? out.app() : in != null ? in.app() : any.app(),
                    out != null ? out.bytes() : 0, in != null ? in.bytes() : 0,
                    first(out, in, true), first(out, in, false)));
        }
        return result;
    }

    private static boolean isOutbound(NetworkFlow flow, NetworkFlow reverse) {
        int source = Integer.parseInt(flow.sourcePort()), destination = Integer.parseInt(flow.destinationPort());
        if (source >= 1024 && destination < 1024) return true;
        if (source < 1024 && destination >= 1024) return false;
        return reverse == null || !reverse.firstSeen().isBefore(flow.firstSeen());
    }

    private static String first(NetworkFlow out, NetworkFlow in, boolean serverName) {
        for (NetworkFlow f : new NetworkFlow[]{out, in}) {
            if (f == null) continue;
            String value = serverName ? f.serverName() : f.httpHost();
            if (!value.isEmpty()) return value;
        }
        return "";
    }

    private static String label(CaptureApp app) { return app == null ? "app non indicata" : app.toString(); }

    static String size(long bytes) {
        if (bytes < 1024) return bytes + " byte";
        if (bytes < 1024 * 1024) return String.format(Locale.ITALY, "%.1f KiB", bytes / 1024.0);
        return String.format(Locale.ITALY, "%.1f MiB", bytes / (1024.0 * 1024));
    }
}
