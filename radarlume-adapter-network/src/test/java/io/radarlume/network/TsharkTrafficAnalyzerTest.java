package io.radarlume.network;

import io.radarlume.domain.*;
import io.radarlume.process.CommandRunner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TsharkTrafficAnalyzerTest {
    @TempDir Path temp;

    /** One line of the first pass (flows, DNS, SNI, app). Columns 0..19; extra sets columns by index. */
    private static String line(String time, String src, String dst, String protocol, int sport, int dport, int bytes, String... extra) {
        boolean v6 = src.contains(":"), tcp = protocol.equals("TCP");
        String[] f = new String[20];
        Arrays.fill(f, "");
        f[0] = time; f[v6 ? 2 : 1] = src; f[v6 ? 4 : 3] = dst;
        f[tcp ? 5 : 7] = Integer.toString(sport); f[tcp ? 6 : 8] = Integer.toString(dport);
        f[9] = Integer.toString(bytes); f[v6 ? 11 : 10] = Integer.toString(v6 ? bytes - 40 : bytes);
        for (int i = 0; i < extra.length; i += 2) f[Integer.parseInt(extra[i])] = extra[i + 1];
        return String.join("\t", f) + "\n";
    }
    /** One line of the HTTP pass. Columns 0..24 (see HTTP_FIELDS); extra sets columns by index. */
    private static String httpLine(String time, String src, String dst, int sport, int dport, int stream, String... extra) {
        String[] f = new String[24];
        Arrays.fill(f, "");
        f[0] = time; f[1] = src; f[3] = dst; f[5] = Integer.toString(sport); f[6] = Integer.toString(dport); f[8] = Integer.toString(stream);
        for (int i = 0; i < extra.length; i += 2) f[Integer.parseInt(extra[i])] = extra[i + 1];
        return String.join("\t", f) + "\n";
    }
    private static String hex(String text) {
        StringBuilder b = new StringBuilder();
        for (byte x : text.getBytes(StandardCharsets.UTF_8)) b.append(String.format("%02x:", x));
        return b.length() == 0 ? "" : b.substring(0, b.length() - 1);
    }
    private static CaptureAnalysis parse(String output) { return TsharkTrafficAnalyzer.parse(output, "test.pcap", 1, "hash", false); }

    @Test void aggregatesIpv4AndIpv6WithoutMergingDirections() {
        var analysis = parse(line("100.5", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 60)
                + line("103.25", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100)
                + line("101", "10.0.0.2", "10.0.0.1", "TCP", 443, 1234, 80)
                + line("102", "2001:db8::1", "2001:db8::2", "UDP", 53000, 53, 70));
        var flows = analysis.flows();
        assertEquals(3, flows.size()); assertEquals(2, flows.getFirst().packets()); assertEquals(160, flows.getFirst().bytes());
        assertEquals("UDP", flows.getLast().protocol()); assertEquals("2001:db8::1", flows.getLast().source());
        assertEquals(Instant.ofEpochSecond(100, 500_000_000), flows.getFirst().firstSeen());
        assertEquals(Instant.ofEpochSecond(103, 250_000_000), flows.getFirst().lastSeen());
        assertEquals(4, analysis.packets());
        assertEquals(Instant.ofEpochSecond(100, 500_000_000), analysis.firstPacket());
        assertEquals(Instant.ofEpochSecond(103, 250_000_000), analysis.lastPacket());
    }
    @Test void rejectsMalformedAndNegativeCounters() {
        assertThrows(ScanException.class, () -> parse("invalid"));
        assertThrows(ScanException.class, () -> parse(line("1", "a", "b", "TCP", 1, 2, -10)));
        assertThrows(ScanException.class, () -> parse(line("1", "a", "b", "TCP", 65536, 2, 10)));
        assertThrows(ScanException.class, () -> parse(line("not-a-time", "a", "b", "TCP", 1, 2, 10)));
        var empty = parse("");
        assertTrue(empty.flows().isEmpty()); assertNull(empty.firstPacket()); assertEquals(0, empty.packets());
    }
    @Test void collectsDnsNamesSeparatingQueriesFromAnswers() {
        var analysis = parse(line("1", "10.0.0.1", "10.0.0.2", "UDP", 40000, 53, 60, "12", "Example.TEST", "13", "False")
                + line("2", "10.0.0.2", "10.0.0.1", "UDP", 53, 40000, 90, "12", "example.test", "13", "True", "14", "192.0.2.10 192.0.2.11", "15", "2001:db8::10")
                + line("3", "10.0.0.1", "10.0.0.2", "UDP", 40001, 53, 60, "12", "unanswered.test", "13", "False"));
        assertEquals(2, analysis.dnsNames().size());
        var answered = analysis.dnsNames().getFirst();
        assertEquals("example.test", answered.name()); assertEquals(1, answered.queries()); assertEquals(1, answered.responses());
        assertEquals(List.of("192.0.2.10", "192.0.2.11", "2001:db8::10"), answered.addresses());
        var unanswered = analysis.dnsNames().getLast();
        assertEquals(0, unanswered.responses()); assertTrue(unanswered.addresses().isEmpty());
    }
    @Test void keepsTlsServerNamePerFlowAndNeutralisesHostileNames() {
        var analysis = parse(line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 40)
                + line("2", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 200, "16", "example.test")
                + line("3", "10.0.0.1", "192.0.2.11", "TCP", 50001, 443, 200, "16", "<b>evil</b> name"));
        assertEquals("example.test", analysis.flows().getFirst().serverName());
        assertEquals("(nome non valido)", analysis.flows().getLast().serverName());
    }
    @Test void readsAppOnlyFromPcapdroidTrailer() {
        String trailer = "010720210000278b636f6d2e6578616d706c652e62726f7773657200";
        assertEquals(new CaptureApp(10123, "com.example.browser"), TsharkTrafficAnalyzer.pcapdroidApp(trailer));
        assertEquals(new CaptureApp(10123, "com.example.browser"), TsharkTrafficAnalyzer.pcapdroidApp("00:00:01:07:20:21:00:00:27:8b:63:6f:6d:2e:65:78:61:6d:70:6c:65:2e:62:72:6f:77:73:65:72:00"));
        // Taken from a real PCAPdroid capture: display names with spaces, zero padding before the magic, name cut at 19 bytes.
        assertEquals(new CaptureApp(10320, "AVG AntiVirus"), TsharkTrafficAnalyzer.pcapdroidApp("0000010720210000285041564720416e7469566972757300000000000000"));
        assertEquals(new CaptureApp(10167, "Google Play Service"), TsharkTrafficAnalyzer.pcapdroidApp("01072021000027b7476f6f676c6520506c6179205365727669636500"));
        assertEquals(new CaptureApp(10001, "Caff"), TsharkTrafficAnalyzer.pcapdroidApp("010720210000271143616666c3" + "00".repeat(15)), "Half a UTF-8 character is dropped");
        assertEquals(new CaptureApp(10001, ""), TsharkTrafficAnalyzer.pcapdroidApp("0107202100002711410a42" + "00".repeat(17)), "Control characters are not shown");
        assertNull(TsharkTrafficAnalyzer.pcapdroidApp("01072021ffffffff" + "00".repeat(20)), "UID -1 means unknown app");
        assertNull(TsharkTrafficAnalyzer.pcapdroidApp("0000000000000000"));
        assertNull(TsharkTrafficAnalyzer.pcapdroidApp(""));

        var with = parse(line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 40, "17", trailer));
        assertEquals(CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, with.appMetadata());
        assertEquals(10123, with.flows().getFirst().app().uid());
        var without = parse(line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 40));
        assertEquals(CaptureAnalysis.AppMetadata.NONE, without.appMetadata());
        assertNull(without.flows().getFirst().app());
    }
    @Test void countsTlsConnectionsAndTheOnesThatBecameReadable() {
        String tcp = "eth:ethertype:ip:tcp";
        var analysis = parse(line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 300, "19", tcp + ":tls:http2")
                + line("2", "192.0.2.10", "10.0.0.1", "TCP", 443, 50000, 300, "19", tcp + ":tls:http2:json")
                + line("3", "10.0.0.1", "192.0.2.11", "TCP", 50001, 443, 300, "19", tcp + ":tls:x509sat")
                + line("4", "10.0.0.1", "192.0.2.13", "TCP", 50003, 80, 300, "19", tcp + ":http", "18", "plain.test"));
        assertEquals(new CaptureAnalysis.Tls(true, 2, 1), TsharkTrafficAnalyzer.parse(
                line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 300, "19", tcp + ":tls:http2")
                + line("3", "10.0.0.1", "192.0.2.11", "TCP", 50001, 443, 300, "19", tcp + ":tls:x509sat"),
                "t", 1, "h", false, true).tls(), "Certificates in a TLS 1.2 handshake are not decrypted content");
        assertEquals("plain.test", analysis.flows().getLast().httpHost());
    }
    @Test void parseRequestsJoinsHeadersAndBodyByStreamAndKeepsOnlyRequestDirection() {
        String tr = "010720210000278b636f6d2e6578616d706c652e62726f7773657200";
        var result = TsharkTrafficAnalyzer.parseRequests(
                // HTTP/2 POST on stream 5, id 1: headers in one packet, body (client->server) in the next.
                httpLine("1", "10.0.0.1", "192.0.2.10", 50000, 443, 5, "7", tr, "9", "1", "10", "POST", "11", "shop.test",
                        "12", "/cart?lat=45.1", "13", "cookie referer content-type", "14", "https://ref.test/p", "15", "application/x-www-form-urlencoded")
                + httpLine("2", "10.0.0.1", "192.0.2.10", 50000, 443, 5, "9", "1", "21", hex("qty=2&email=a@b.test"))
                // Response DATA on the same stream must be ignored.
                + httpLine("3", "192.0.2.10", "10.0.0.1", 443, 50000, 5, "9", "1", "21", hex("you cannot read this as a request"))
                // HTTP/1 GET on stream 9 with a binary body.
                + httpLine("4", "10.0.0.1", "192.0.2.20", 50001, 443, 9, "16", "GET", "17", "old.test", "18", "/h1?x=1",
                        "23", "00:01:02:ff:fe:00:01:02:ff:fe"));
        var requests = result.requests();
        assertEquals(2, requests.size());
        HttpRequest post = requests.getFirst();
        assertEquals("POST", post.method()); assertEquals("shop.test", post.host()); assertEquals("/cart?lat=45.1", post.path());
        assertTrue(post.decrypted()); assertEquals(10123, post.app().uid());
        assertEquals("qty=2&email=a@b.test", post.body()); assertEquals(20, post.bodyBytes()); assertFalse(post.bodyBinary());
        assertEquals(List.of("cookie", "referer", "content-type"), post.headerNames());
        assertTrue(post.hasHeader("cookie")); assertEquals("https://ref.test/p", post.referer());
        assertEquals("application/x-www-form-urlencoded", post.contentType());
        HttpRequest h1 = requests.getLast();
        assertEquals("old.test", h1.host()); assertEquals("/h1?x=1", h1.path());
        assertTrue(h1.bodyBinary()); assertEquals("", h1.body()); assertEquals(10, h1.bodyBytes());
    }
    @Test void boundsBodyLengthPerRequest() {
        String big = "a".repeat(TsharkTrafficAnalyzer.MAX_BODY_BYTES + 500);
        var requests = TsharkTrafficAnalyzer.parseRequests(
                httpLine("1", "10.0.0.1", "192.0.2.10", 50000, 443, 5, "9", "1", "10", "POST", "12", "/x")
                + httpLine("2", "10.0.0.1", "192.0.2.10", 50000, 443, 5, "9", "1", "21", hex(big))).requests();
        HttpRequest r = requests.getFirst();
        assertEquals(TsharkTrafficAnalyzer.MAX_BODY_BYTES, r.bodyBytes()); assertTrue(r.bodyTruncated());
    }
    @Test void passesCaptureAsSingleArgumentAndDisablesNameResolution() throws Exception {
        Path capture = Files.write(temp.resolve("capture with spaces.pcap"), new byte[]{1});
        List<List<String>> seen = new ArrayList<>();
        var analyzer = new TsharkTrafficAnalyzer("tshark", (args, timeout) -> { seen.add(args); return ""; });
        var analysis = analyzer.analyze(capture);
        assertEquals(capture.toAbsolutePath().toString(), seen.getFirst().get(3));
        assertEquals("-n", seen.getFirst().get(1)); assertFalse(seen.getFirst().contains("-i"));
        assertEquals("capture with spaces.pcap", analysis.fileName()); assertEquals(1, analysis.fileBytes());
        assertEquals("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a", analysis.sha256());
        assertThrows(ScanException.class, () -> analyzer.analyze(temp.resolve("missing.pcap")));
        assertEquals(2, seen.size(), "One pass for flows, one for HTTP");
    }
    @Test void acceptsOnlyTruncationAsPartialResult() throws Exception {
        Path capture = Files.write(temp.resolve("capture.pcap"), new byte[]{1});
        String packet = line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 40);
        var truncated = new TsharkTrafficAnalyzer("tshark", flowOnly(2, packet, "tshark: The file \"x\" appears to have been cut short in the middle of a packet.")).analyze(capture);
        assertTrue(truncated.truncated()); assertEquals(1, truncated.flows().size());
        assertTrue(truncated.warnings().stream().anyMatch(w -> w.contains("parziale")));
        var error = assertThrows(ScanException.class,
                () -> new TsharkTrafficAnalyzer("tshark", flowOnly(2, packet, "tshark: The file \"x\" is not a capture file in a format TShark understands.")).analyze(capture));
        assertTrue(error.getMessage().contains("is not a capture file"), "The reason given by TShark must reach the user");
    }
    @Test void passesAValidatedKeylogToTheDecoder() throws Exception {
        Path capture = Files.write(temp.resolve("capture.pcap"), new byte[]{1});
        Path keylog = Files.writeString(temp.resolve("keys with spaces.keylog"), "# comment\n\nCLIENT_RANDOM 00ff 11ee\n");
        List<List<String>> seen = new ArrayList<>();
        var analyzer = new TsharkTrafficAnalyzer("tshark", (args, timeout) -> { seen.add(args); return ""; });
        assertTrue(analyzer.analyze(capture, keylog).tls().keylogUsed());
        int option = seen.getFirst().indexOf("-o");
        assertEquals("tls.keylog_file:" + keylog.toAbsolutePath(), seen.getFirst().get(option + 1));
        assertFalse(analyzer.analyze(capture).tls().keylogUsed());
        assertFalse(seen.getLast().contains("-o"));

        Path notKeys = Files.writeString(temp.resolve("notes.txt"), "these are not keys\n");
        assertThrows(ScanException.class, () -> analyzer.analyze(capture, notKeys));
        assertThrows(ScanException.class, () -> analyzer.analyze(capture, temp.resolve("missing.keylog")));
        assertEquals(4, seen.size(), "Two analyses of two passes each; a rejected key file starts nothing");
    }
    /** Returns the flow-pass output (and its exit code) only; the HTTP pass gets empty output. */
    private static CommandRunner flowOnly(int exit, String flowStdout, String stderr) {
        return new CommandRunner() {
            @Override public String run(List<String> arguments, Duration timeout) { throw new AssertionError("execute expected"); }
            @Override public CommandResult execute(List<String> arguments, Duration timeout) {
                boolean http = arguments.contains("tcp.stream");
                return new CommandResult(exit, http ? "" : flowStdout, stderr);
            }
        };
    }
}
