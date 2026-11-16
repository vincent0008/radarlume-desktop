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

    public static final int MAX_BODY_BYTES = 64 * 1024;
    static final int MAX_BODY_CHARS = 8_000;
    static final long MAX_TOTAL_BODY_BYTES = 8L * 1024 * 1024;

    /** Order matters: {@link #parse} reads the columns by these positions. */
    private static final List<String> FIELDS = List.of(
            "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
            "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
            "frame.len", "ip.len", "ipv6.plen",
            "dns.qry.name", "dns.flags.response", "dns.a", "dns.aaaa",
            "tls.handshake.extensions_server_name", "eth.trailer", "http.host",
            "frame.protocols");
    /**
     * Second pass, only over HTTP packets: request headers and bodies, which the first pass cannot carry safely.
     * All of these are tab-free (tokens, URLs or colon-hex), so the field-count invariant still holds; bodies are
     * read as hex so that spaces, tabs and arbitrary bytes inside them never break the columns.
     */
    // Request definitions always; bodies only in the request direction (client port above the server port), so that
    // large response bodies never enter the output. parseRequests still checks the direction exactly, per stream.
    private static final String HTTP_FILTER = "http.request.method or http2.headers.method"
            + " or ((http2.data.data or http.file_data) and tcp.dstport < tcp.srcport)";
    private static final List<String> HTTP_FIELDS = List.of(
            "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
            "eth.trailer", "tcp.stream", "http2.streamid",
            "http2.headers.method", "http2.headers.authority", "http2.headers.path", "http2.header.name",
            "http2.headers.referer", "http2.headers.content_type",
            "http.request.method", "http.host", "http.request.uri", "http.referer", "http.content_type",
            "http2.data.data", "http2.body.reassembled.data", "http.file_data");
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
        var flowResult = runTshark(capture, keylog, FILTER, FIELDS);
        boolean truncated = flowResult.exitCode() != 0;
        var base = parse(flowResult.stdout(), capture.getFileName().toString(), size, sha256, truncated, keylog != null);

        // Second pass over HTTP packets only: headers and bodies. A failure here must not lose the flow analysis.
        var http = parseRequests(runTshark(capture, keylog, HTTP_FILTER, HTTP_FIELDS).stdout());
        var warnings = new ArrayList<>(base.warnings());
        if (http.limitHit())
            warnings.add("Elenco delle richieste HTTP incompleto: superato il limite di " + MAX_REQUESTS + ".");
        return new CaptureAnalysis(base.fileName(), base.fileBytes(), base.sha256(), base.packets(), base.firstPacket(),
                base.lastPacket(), base.appMetadata(), base.truncated(), base.flows(), base.dnsNames(), warnings,
                base.tls(), http.requests());
    }

    /** Runs one TShark field extraction. A file cut short mid-packet is accepted (exit code kept); anything else throws. */
    private CommandRunner.CommandResult runTshark(Path capture, Path keylog, String filter, List<String> fields) {
        var command = new ArrayList<>(List.of(executable, "-n", "-r", capture.toAbsolutePath().toString(),
                "-Y", filter, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=/s"));
        if (keylog != null) {
            command.add("-o");
            command.add("tls.keylog_file:" + keylog.toAbsolutePath());
        }
        for (String field : fields) {
            command.add("-e");
            command.add(field);
        }
        var result = runner.execute(command, Duration.ofSeconds(90));
        // TShark still prints every complete packet of a file that ends mid-packet (typical of an interrupted
        // export). That is usable as long as the result is clearly marked as partial. Any other failure is rejected.
        if (result.exitCode() != 0 && !result.stderr().contains("cut short"))
            throw new ScanException("TShark non ha potuto leggere la cattura (codice " + result.exitCode() + ")"
                    + BoundedProcessRunner.detail(result.stderr()) + ". Nessun risultato utilizzato.");
        return result;
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
        var tlsConnections = new HashSet<String>();
        var decryptedConnections = new HashSet<String>();
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
                warnings, new CaptureAnalysis.Tls(keylogUsed, tlsConnections.size(), decryptedConnections.size()), List.of());
    }

    /** A request under construction, built from several packets of one HTTP/2 stream (or one HTTP/1 request). */
    private static final class Req {
        Instant time; String dst, clientSrc, clientSport;
        CaptureApp app;
        String method = "", host = "", path = "", referer = "", origin = "", contentType = "";
        List<String> headerNames = List.of();
        final java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        boolean complete, truncated;
    }

    /** Result of the HTTP pass: the requests and whether the request limit cut the list short. */
    public record Requests(List<HttpRequest> requests, boolean limitHit) {
        public Requests { requests = List.copyOf(requests); }
    }

    /**
     * Parses the HTTP-only second pass. Request definitions (HTTP/2 HEADERS, HTTP/1 request lines) and request
     * bodies (HTTP/2 DATA, HTTP/1 file data) arrive on different packets, joined here by TCP stream and HTTP/2
     * stream id. Only request-direction bodies are kept; responses are ignored.
     */
    public static Requests parseRequests(String output) {
        var byKey = new LinkedHashMap<String, Req>();
        var lastH1ByStream = new HashMap<String, Req>();
        boolean limitHit = false;
        long totalBody = 0;
        int h1Counter = 0;

        for (String line : output.lines().toList()) {
            if (Thread.currentThread().isInterrupted()) throw new ScanException("Importazione annullata.");
            if (line.isBlank()) continue;
            String[] f = line.split("\t", -1);
            if (f.length != HTTP_FIELDS.size())
                throw new ScanException("Formato TShark inatteso (HTTP): sono richiesti " + HTTP_FIELDS.size() + " campi.");
            try {
                String src = first(f[1].isEmpty() ? f[2] : f[1]), dst = first(f[3].isEmpty() ? f[4] : f[3]);
                String sport = first(f[5]), dport = first(f[6]);
                if (src.isBlank() || dst.isBlank() || sport.isBlank()) continue;
                Instant time = time(f[0]);
                CaptureApp app = pcapdroidApp(f[7]);
                String stream = first(f[8]);

                // HTTP/2 request definitions: one per HEADERS frame. Trust the stream id only when its count matches.
                String[] methods = many(f[10]);
                if (methods.length > 0) {
                    String[] sids = many(f[9]), auths = many(f[11]), paths = many(f[12]);
                    boolean aligned = sids.length == methods.length;
                    for (int i = 0; i < methods.length; i++) {
                        if (byKey.size() >= MAX_REQUESTS) { limitHit = true; break; }
                        String sid = aligned ? sids[i] : "?" + (byKey.size());
                        Req r = byKey.computeIfAbsent(stream + "#" + sid, k -> new Req());
                        fillRequest(r, time, dst, app, src, sport, token(methods[i]),
                                name(hostOnly(i < auths.length ? auths[i] : "")), path(i < paths.length ? paths[i] : ""));
                        if (methods.length == 1) {              // headers align with the request only when the packet holds one
                            r.headerNames = headerNames(f[13]);
                            r.referer = url(f[14]); r.contentType = headerValue(f[15]);
                        }
                    }
                }

                // HTTP/1 request: one per packet. No stream id, so key by stream and a counter.
                if (!f[16].isEmpty()) {
                    if (byKey.size() >= MAX_REQUESTS) limitHit = true;
                    else {
                        Req r = new Req();
                        fillRequest(r, time, dst, app, src, sport, token(first(f[16])),
                                name(hostOnly(first(f[17]))), path(first(f[18])));
                        r.referer = url(f[19]); r.contentType = headerValue(f[20]);
                        byKey.put(stream + "#h1#" + h1Counter++, r);
                        lastH1ByStream.put(stream, r);
                    }
                }

                // Bodies. HTTP/2 DATA frames are matched to their request by stream id and direction; HTTP/1 file
                // data is attached to the most recent HTTP/1 request on the same TCP stream.
                if (!f[21].isEmpty() || !f[22].isEmpty()) {
                    boolean reassembled = !f[22].isEmpty();
                    String[] sids = many(f[9]), chunks = many(reassembled ? f[22] : f[21]);
                    for (int i = 0; i < chunks.length; i++) {
                        String sid = sids.length == chunks.length ? sids[i] : (sids.length == 1 ? sids[0] : "");
                        Req r = byKey.get(stream + "#" + sid);
                        // Only the request side (client → server) is a request body.
                        if (r == null || !src.equals(r.clientSrc) || !sport.equals(r.clientSport)) continue;
                        totalBody = appendBody(r, hex(chunks[i]), reassembled, totalBody);
                    }
                }
                if (!f[23].isEmpty()) {
                    Req r = lastH1ByStream.get(stream);
                    if (r != null) totalBody = appendBody(r, hex(f[23]), false, totalBody);
                }
            } catch (IllegalArgumentException | ArithmeticException e) {
                throw new ScanException("Campi TShark non validi (HTTP).", e);
            }
        }
        var requests = byKey.values().stream().map(TsharkTrafficAnalyzer::toRequest).toList();
        return new Requests(requests, limitHit);
    }

    private static void fillRequest(Req r, Instant time, String dst, CaptureApp app, String clientSrc, String clientSport,
                                    String method, String host, String path) {
        if (r.time == null) { r.time = time; r.dst = dst; r.app = app; r.clientSrc = clientSrc; r.clientSport = clientSport; }
        if (r.method.isEmpty()) { r.method = method; r.host = host; r.path = path; }
    }

    /** Appends body bytes within the per-request and overall limits. A reassembled chunk is the complete body. */
    private static long appendBody(Req r, byte[] bytes, boolean complete, long total) {
        if (r.complete) return total;                       // the full body is already known
        if (complete) { r.body.reset(); r.complete = true; }
        int room = (int) Math.min(MAX_BODY_BYTES - r.body.size(), MAX_TOTAL_BODY_BYTES - total);
        if (room <= 0) { if (bytes.length > 0) r.truncated = true; return total; }
        int take = Math.min(room, bytes.length);
        r.body.write(bytes, 0, take);
        if (take < bytes.length) r.truncated = true;
        return total + take;
    }

    private static HttpRequest toRequest(Req r) {
        byte[] raw = r.body.toByteArray();
        boolean binary = looksBinary(raw);
        String body = binary || raw.length == 0 ? "" : bodyText(new String(raw, StandardCharsets.UTF_8));
        return new HttpRequest(r.time, r.dst, r.app, r.method, r.host, r.path, r.clientSport != null,
                r.headerNames, r.referer, r.origin, r.contentType, body, raw.length, binary && raw.length > 0, r.truncated);
    }

    private static byte[] hex(String colonHex) {
        String h = colonHex.replace(":", "").replace(MANY, "");
        if (h.isEmpty() || (h.length() & 1) != 0 || !h.matches("[0-9a-fA-F]+")) return new byte[0];
        return HexFormat.of().parseHex(h);
    }

    /** More than a tenth non-text bytes, or any NUL, means we treat the body as binary and do not show it. */
    private static boolean looksBinary(byte[] raw) {
        if (raw.length == 0) return false;
        int bad = 0;
        for (byte b : raw) {
            int c = b & 0xff;
            if (c == 0) return true;
            if (c < 0x09 || (c > 0x0d && c < 0x20)) bad++;
        }
        return bad * 10 > raw.length;
    }

    private static String bodyText(String decoded) {
        String clean = decoded.replaceAll("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]", "·");
        return clean.length() <= MAX_BODY_CHARS ? clean : clean.substring(0, MAX_BODY_CHARS) + "…";
    }

    /** Header names are lower-case tokens; keep only well-formed ones, de-duplicated and bounded. */
    private static List<String> headerNames(String aggregated) {
        var names = new java.util.LinkedHashSet<String>();
        for (String n : many(aggregated))
            if (n.matches("[a-z0-9:_-]{1,40}") && names.size() < 60) names.add(n);
        return List.copyOf(names);
    }

    /** A Referer/Origin URL is shown as-is but sanitised and bounded. */
    private static String url(String raw) { return bodyText(first(raw)); }

    /** A Content-Type is a single header value with no tab; keep it printable and bounded. */
    private static String headerValue(String raw) {
        String clean = raw.replaceAll("[^\\x20-\\x7e]", "?");
        return clean.length() <= 200 ? clean : clean.substring(0, 200);
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
