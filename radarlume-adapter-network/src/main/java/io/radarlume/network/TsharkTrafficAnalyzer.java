package io.radarlume.network;

import io.radarlume.domain.*;
import io.radarlume.process.BoundedProcessRunner;
import io.radarlume.process.CommandRunner;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Offline import of a capture through TShark: one output line per TCP/UDP packet, aggregated here.
 * The capture is untrusted input: every field is validated and every collection is bounded.
 */
public final class TsharkTrafficAnalyzer implements TrafficAnalyzer {
    public static final long MAX_FILE_BYTES = 100L * 1024 * 1024;
    static final int MAX_FLOWS = 50_000;
    static final int MAX_DNS_NAMES = 20_000;
    static final int MAX_ADDRESSES_PER_NAME = 32;
    public static final long MAX_KEYLOG_BYTES = 16L * 1024 * 1024;
    static final int MAX_REQUESTS = 20_000;
    static final int MAX_PATH_CHARS = 2_000;

    /** Order matters: {@link #parse} reads the columns by these positions. */
    private static final List<String> FIELDS = List.of(
            "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
            "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
            "frame.len", "ip.len", "ipv6.plen",
            "dns.qry.name", "dns.flags.response", "dns.a", "dns.aaaa",
            "tls.handshake.extensions_server_name", "eth.trailer", "http.host",
            "frame.protocols", "http.request.method", "http.request.uri",
            "http2.headers.method", "http2.headers.authority", "http2.headers.path");
    /** Repeated fields are joined with a space: unlike a comma it cannot appear inside a request path, a name or an address. */
    private static final String MANY = " ";
    private static final java.util.regex.Pattern KEYLOG_LINE = java.util.regex.Pattern.compile("[A-Z0-9_]+ [0-9a-fA-F]+ [0-9a-fA-F]+");
    /** ICMP errors quote the header of the packet they refer to: without the exclusion they would create fake flows. */
    private static final String FILTER = "(ip or ipv6) and (tcp or udp) and not icmp and not icmpv6";
    /** Magic number that opens the metadata PCAPdroid appends to each packet when its extensions are enabled. */
    private static final String PCAPDROID_MAGIC = "01072021";

    private final String executable;
    private final CommandRunner runner;

    public TsharkTrafficAnalyzer(String executable, CommandRunner runner) {
        this.executable = executable;
        this.runner = runner;
    }

    @Override public CaptureAnalysis analyze(Path capture, Path keylog) {
        long size;
        try {
            if (!Files.isRegularFile(capture) || !Files.isReadable(capture)) throw new ScanException("Cattura non leggibile.");
            size = Files.size(capture);
            if (size > MAX_FILE_BYTES) throw new ScanException("La cattura supera il limite MVP di 100 MiB.");
        } catch (IOException e) {
            throw new ScanException("Impossibile leggere la cattura.", e);
        }
        if (keylog != null) checkKeylog(keylog);
        String sha256 = sha256(capture);
        var command = new ArrayList<>(List.of(executable, "-n", "-r", capture.toAbsolutePath().toString(),
                "-Y", FILTER, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=/s"));
        if (keylog != null) {
            command.add("-o");
            command.add("tls.keylog_file:" + keylog.toAbsolutePath());
        }
        for (String field : FIELDS) {
            command.add("-e");
            command.add(field);
        }
        var result = runner.execute(command, Duration.ofSeconds(90));
        boolean truncated = false;
        if (result.exitCode() != 0) {
            // TShark still prints every complete packet of a file that ends mid-packet (typical of an
            // interrupted export). That is usable as long as the result is clearly marked as partial.
            // Any other failure is rejected.
            if (!result.stderr().contains("cut short"))
                throw new ScanException("TShark non ha potuto leggere la cattura (codice " + result.exitCode() + ")"
                        + BoundedProcessRunner.detail(result.stderr()) + ". Nessun risultato utilizzato.");
            truncated = true;
        }
        return parse(result.stdout(), capture.getFileName().toString(), size, sha256, truncated, keylog != null);
    }

    /** The key file is as untrusted as the capture: bounded size and the expected line format, or nothing is used. */
    private static void checkKeylog(Path keylog) {
        try {
            if (!Files.isRegularFile(keylog) || !Files.isReadable(keylog)) throw new ScanException("File delle chiavi TLS non leggibile.");
            if (Files.size(keylog) > MAX_KEYLOG_BYTES) throw new ScanException("Il file delle chiavi TLS supera il limite di 16 MiB.");
            try (var lines = Files.lines(keylog, StandardCharsets.ISO_8859_1)) {
                boolean valid = lines.map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#")).findFirst()
                        .map(l -> KEYLOG_LINE.matcher(l).matches()).orElse(false);
                if (!valid) throw new ScanException("Il file indicato non ha il formato di un file di chiavi TLS (SSLKEYLOGFILE).");
            }
        } catch (IOException | java.io.UncheckedIOException e) {
            throw new ScanException("Impossibile leggere il file delle chiavi TLS.", e);
        }
    }

    private static String sha256(Path capture) {
        try (InputStream in = Files.newInputStream(capture)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int n;
            while ((n = in.read(buffer)) != -1) {
                if (Thread.currentThread().isInterrupted()) throw new ScanException("Importazione annullata.");
                digest.update(buffer, 0, n);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException e) {
            throw new ScanException("Impossibile leggere la cattura.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Key(String src, String dst, String protocol, String sport, String dport) {}

    private static final class FlowTotals {
        long packets, bytes;
        Instant first, last;
        CaptureApp app;
        String serverName = "", httpHost = "";
    }

    private static final class DnsTotals {
        long queries, responses;
        Instant first, last;
        final Set<String> addresses = new LinkedHashSet<>();
    }

    public static CaptureAnalysis parse(String output, String fileName, long fileBytes, String sha256, boolean truncated) {
        return parse(output, fileName, fileBytes, sha256, truncated, false);
    }

    public static CaptureAnalysis parse(String output, String fileName, long fileBytes, String sha256, boolean truncated, boolean keylogUsed) {
        var requests = new ArrayList<HttpRequest>();
        var tlsConnections = new HashSet<String>();
        var decryptedConnections = new HashSet<String>();
        boolean requestLimitHit = false;
        var flows = new LinkedHashMap<Key, FlowTotals>();
        var dns = new LinkedHashMap<String, DnsTotals>();
        long packets = 0;
        Instant first = null, last = null;
        boolean trailerSeen = false, dnsLimitHit = false;

        for (String line : output.lines().toList()) {
            if (Thread.currentThread().isInterrupted()) throw new ScanException("Importazione annullata.");
            if (line.isBlank()) continue;
            String[] f = line.split("\t", -1);
            if (f.length != FIELDS.size())
                throw new ScanException("Formato TShark inatteso: sono richiesti " + FIELDS.size() + " campi.");
            try {
                // Tunnelled packets repeat a field once per layer; like the previous version we use the outermost one.
                boolean tcp = !f[5].isEmpty();
                String src = first(f[1].isEmpty() ? f[2] : f[1]), dst = first(f[3].isEmpty() ? f[4] : f[3]);
                String sport = first(tcp ? f[5] : f[7]), dport = first(tcp ? f[6] : f[8]);
                if (src.isBlank() || dst.isBlank()) throw new IllegalArgumentException();
                int sp = Integer.parseInt(sport), dp = Integer.parseInt(dport);
                if (sp < 0 || sp > 65535 || dp < 0 || dp > 65535) throw new IllegalArgumentException();
                long bytes = ipBytes(f);
                Instant time = time(f[0]);

                packets++;
                if (first == null || time.isBefore(first)) first = time;
                if (last == null || time.isAfter(last)) last = time;

                FlowTotals flow = flows.computeIfAbsent(new Key(src, dst, tcp ? "TCP" : "UDP", sport, dport), ignored -> new FlowTotals());
                if (flows.size() > MAX_FLOWS) throw new ScanException("Troppe conversazioni: limite MVP di 50.000 flussi.");
                flow.packets = Math.addExact(flow.packets, 1);
                flow.bytes = Math.addExact(flow.bytes, bytes);
                if (flow.first == null || time.isBefore(flow.first)) flow.first = time;
                if (flow.last == null || time.isAfter(flow.last)) flow.last = time;
                if (flow.serverName.isEmpty()) flow.serverName = name(first(f[16]));
                // Layers as decoded by TShark, e.g. "eth:ethertype:ip:tcp:tls:http2": HTTP after TLS means the keys worked.
                String layers = ":" + first(f[19]) + ":";
                boolean tls = tcp && layers.contains(":tls:"), readable = tls && layers.contains(":tls:http");
                if (tls) {
                    String connection = sp < dp || (sp == dp && src.compareTo(dst) < 0)
                            ? src + " " + sport + " " + dst + " " + dport : dst + " " + dport + " " + src + " " + sport;
                    tlsConnections.add(connection);
                    if (readable) decryptedConnections.add(connection);
                }
                // A Host header read thanks to the keys was not sent in clear text: it must not look like one.
                if (!tls && flow.httpHost.isEmpty()) flow.httpHost = name(hostOnly(first(f[18])));

                CaptureApp app = pcapdroidApp(f[17]);
                if (app != null || f[17].replace(":", "").contains(PCAPDROID_MAGIC)) trailerSeen = true;
                if (flow.app == null) flow.app = app;

                // HTTP/1 carries one request per packet; HTTP/2 can carry several, listed in the same order in the three fields.
                boolean http1 = !f[20].isEmpty();
                String[] methods = many(http1 ? f[20] : f[22]), hosts = many(http1 ? f[18] : f[23]), paths = many(http1 ? f[21] : f[24]);
                for (int i = 0; i < methods.length; i++) {
                    if (requests.size() >= MAX_REQUESTS) { requestLimitHit = true; break; }
                    requests.add(new HttpRequest(time, dst, flow.app, token(methods[i]),
                            name(hostOnly(i < hosts.length ? hosts[i] : "")), path(i < paths.length ? paths[i] : ""), tls));
                }

                String query = name(first(f[12]));
                if (!query.isEmpty()) {
                    DnsTotals total = dns.get(query);
                    if (total == null) {
                        if (dns.size() >= MAX_DNS_NAMES) { dnsLimitHit = true; continue; }
                        dns.put(query, total = new DnsTotals());
                    }
                    if (total.first == null || time.isBefore(total.first)) total.first = time;
                    if (total.last == null || time.isAfter(total.last)) total.last = time;
                    if (isTrue(first(f[13]))) {
                        total.responses++;
                        for (String address : (f[14] + MANY + f[15]).split(MANY))
                            if (!address.isBlank() && address.length() <= 45 && total.addresses.size() < MAX_ADDRESSES_PER_NAME)
                                total.addresses.add(address);
                    } else {
                        total.queries++;
                    }
                }
            } catch (IllegalArgumentException | ArithmeticException e) {
                throw new ScanException("Campi TShark non validi.", e);
            }
        }

        var warnings = new ArrayList<String>();
        if (truncated)
            warnings.add("File troncato: sono stati analizzati solo i pacchetti completi. Il risultato è parziale.");
        if (trailerSeen)
            warnings.add("App indicate dai metadati PCAPdroid, non dedotte da RadarLume. È il nome visualizzato dell'app, troncato a 19 byte: per distinguere due app usare l'UID.");
        else
            warnings.add("La cattura non contiene metadati sulle app leggibili da RadarLume: nessuna attribuzione.");
        if (requestLimitHit)
            warnings.add("Elenco delle richieste HTTP incompleto: superato il limite di " + MAX_REQUESTS + ".");
        if (keylogUsed && decryptedConnections.isEmpty())
            warnings.add("Il file delle chiavi TLS non ha permesso di leggere alcuna connessione: potrebbe appartenere a un'altra cattura.");
        if (dnsLimitHit)
            warnings.add("Elenco DNS incompleto: superato il limite di " + MAX_DNS_NAMES + " nomi.");
        warnings.add("Nomi DNS e TLS sono visibili solo se trasmessi in chiaro: DNS cifrato (DoH/DoT) ed ECH li nascondono. L'assenza di un nome non prova l'assenza di una connessione.");

        return new CaptureAnalysis(fileName, fileBytes, sha256, packets, first, last,
                trailerSeen ? CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER : CaptureAnalysis.AppMetadata.NONE, truncated,
                flows.entrySet().stream().map(e -> new NetworkFlow(e.getKey().src(), e.getKey().dst(), e.getKey().protocol(),
                        e.getKey().sport(), e.getKey().dport(), e.getValue().packets, e.getValue().bytes,
                        e.getValue().first, e.getValue().last, e.getValue().app, e.getValue().serverName, e.getValue().httpHost)).toList(),
                dns.entrySet().stream().map(e -> new DnsName(e.getKey(), e.getValue().queries, e.getValue().responses,
                        List.copyOf(e.getValue().addresses), e.getValue().first, e.getValue().last)).toList(),
                warnings, new CaptureAnalysis.Tls(keylogUsed, tlsConnections.size(), decryptedConnections.size()), requests);
    }

    private static String first(String aggregated) {
        int end = aggregated.indexOf(MANY);
        return end < 0 ? aggregated : aggregated.substring(0, end);
    }

    private static String[] many(String aggregated) { return aggregated.isEmpty() ? new String[0] : aggregated.split(MANY); }

    private static String token(String method) { return method.matches("[A-Za-z]{1,16}") ? method.toUpperCase(Locale.ROOT) : "(non valido)"; }

    /** Request paths are shown to the user: keep printable ASCII only and bound the length. */
    private static String path(String raw) {
        String clean = raw.replaceAll("[^\\x21-\\x7e]", "?");
        return clean.length() <= MAX_PATH_CHARS ? clean : clean.substring(0, MAX_PATH_CHARS) + "…";
    }

    /** The Host header may carry a port ("example.test:8080"); bracketed IPv6 literals are left to the name check. */
    private static String hostOnly(String host) {
        int colon = host.lastIndexOf(':');
        return colon > 0 && !host.startsWith("[") ? host.substring(0, colon) : host;
    }

    private static boolean isTrue(String value) { return value.equalsIgnoreCase("true") || value.equals("1"); }

    /** IP packet length, so that link-layer framing (including the PCAPdroid trailer) does not inflate the totals. */
    private static long ipBytes(String[] f) {
        long frame = Long.parseLong(first(f[9]));
        if (frame < 0) throw new IllegalArgumentException();
        String v4 = first(f[10]), v6 = first(f[11]);
        long ip = !v4.isEmpty() ? Long.parseLong(v4) : !v6.isEmpty() ? Long.parseLong(v6) + 40 : 0;
        if (ip < 0) throw new IllegalArgumentException();
        // Offloaded packets in some captures declare an IP length of zero: the frame length is the best figure left.
        return ip > 0 ? ip : frame;
    }

    private static Instant time(String epoch) {
        BigDecimal value = new BigDecimal(first(epoch));
        if (value.signum() < 0 || value.precision() - value.scale() > 11) throw new IllegalArgumentException();
        long seconds = value.longValue();
        return Instant.ofEpochSecond(seconds, value.subtract(BigDecimal.valueOf(seconds)).movePointRight(9).longValue());
    }

    /** Names come from the capture: keep them only if they look like host names, otherwise show a neutral marker. */
    private static String name(String raw) {
        if (raw.isEmpty()) return "";
        String value = raw.endsWith(".") ? raw.substring(0, raw.length() - 1) : raw;
        if (value.isEmpty()) return "";
        if (value.length() > 253 || !value.matches("[A-Za-z0-9_.*-]+")) return "(nome non valido)";
        return value.toLowerCase(Locale.ROOT);
    }

    /**
     * PCAPdroid trailer: magic (4 bytes), UID (int32, -1 if unknown), package name (20 bytes, NUL padded).
     * Returns {@code null} when the packet has no trailer or the app is unknown.
     */
    static CaptureApp pcapdroidApp(String ethTrailer) {
        String hex = ethTrailer.replace(":", "").replace(MANY, "").toLowerCase(Locale.ROOT);
        int start = hex.indexOf(PCAPDROID_MAGIC);
        while (start >= 0 && start % 2 != 0) start = hex.indexOf(PCAPDROID_MAGIC, start + 1);
        if (start < 0 || hex.length() < start + 56 || !hex.matches("[0-9a-f]+")) return null;
        int uid = (int) Long.parseLong(hex.substring(start + 8, start + 16), 16);
        if (uid < 0) return null;
        byte[] raw = HexFormat.of().parseHex(hex.substring(start + 16, start + 56));
        int length = 0;
        while (length < raw.length && raw[length] != 0) length++;
        // Real captures carry the display name ("AVG AntiVirus"), possibly cut in the middle of a UTF-8 character.
        String name = new String(raw, 0, length, StandardCharsets.UTF_8).replace("�", "").strip();
        return new CaptureApp(uid, name.chars().anyMatch(Character::isISOControl) ? "" : name);
    }
}
