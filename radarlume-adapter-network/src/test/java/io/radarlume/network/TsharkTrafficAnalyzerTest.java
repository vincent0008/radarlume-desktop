package io.radarlume.network;

import io.radarlume.domain.*;
import io.radarlume.process.CommandRunner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TsharkTrafficAnalyzerTest {
    @TempDir Path temp;

    /** One TShark output line. Columns: time, addresses, ports, lengths, DNS, SNI, Ethernet trailer. */
    private static String line(String time, String src, String dst, String protocol, int sport, int dport, int bytes, String... extra) {
        boolean v6 = src.contains(":"), tcp = protocol.equals("TCP");
        String[] f = new String[18];
        Arrays.fill(f, "");
        f[0] = time; f[v6 ? 2 : 1] = src; f[v6 ? 4 : 3] = dst;
        f[tcp ? 5 : 7] = Integer.toString(sport); f[tcp ? 6 : 8] = Integer.toString(dport);
        f[9] = Integer.toString(bytes); f[v6 ? 11 : 10] = Integer.toString(v6 ? bytes - 40 : bytes);
        for (int i = 0; i < extra.length; i += 2) f[Integer.parseInt(extra[i])] = extra[i + 1];
        return String.join("\t", f) + "\n";
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
                + line("2", "10.0.0.2", "10.0.0.1", "UDP", 53, 40000, 90, "12", "example.test", "13", "True", "14", "192.0.2.10,192.0.2.11", "15", "2001:db8::10")
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
        assertEquals(1, seen.size());
    }
    @Test void acceptsOnlyTruncationAsPartialResult() throws Exception {
        Path capture = Files.write(temp.resolve("capture.pcap"), new byte[]{1});
        String packet = line("1", "10.0.0.1", "192.0.2.10", "TCP", 50000, 443, 40);
        var truncated = new TsharkTrafficAnalyzer("tshark", runner(2, packet, "tshark: The file \"x\" appears to have been cut short in the middle of a packet.")).analyze(capture);
        assertTrue(truncated.truncated()); assertEquals(1, truncated.flows().size());
        assertTrue(truncated.warnings().stream().anyMatch(w -> w.contains("parziale")));
        var error = assertThrows(ScanException.class,
                () -> new TsharkTrafficAnalyzer("tshark", runner(2, packet, "tshark: The file \"x\" is not a capture file in a format TShark understands.")).analyze(capture));
        assertTrue(error.getMessage().contains("is not a capture file"), "The reason given by TShark must reach the user");
    }
    private static CommandRunner runner(int exit, String stdout, String stderr) {
        return new CommandRunner() {
            @Override public String run(List<String> arguments, Duration timeout) { throw new AssertionError("execute expected"); }
            @Override public CommandResult execute(List<String> arguments, Duration timeout) { return new CommandResult(exit, stdout, stderr); }
        };
    }
}
