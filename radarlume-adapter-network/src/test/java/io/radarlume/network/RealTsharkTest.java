package io.radarlume.network;

import io.radarlume.domain.*;
import io.radarlume.process.BoundedProcessRunner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the real TShark on synthetic captures in the formats PCAPdroid exports.
 * Skipped when TShark is not installed; set {@code -Dradarlume.tshark=...} or RADARLUME_TSHARK to point at it.
 * This proves our command line and parser agree with TShark, not that a real PCAPdroid export behaves the same.
 */
class RealTsharkTest {
    private static String tshark;
    @TempDir Path temp;

    @BeforeAll static void locate() {
        tshark = Stream.of(System.getProperty("radarlume.tshark"), System.getenv("RADARLUME_TSHARK"),
                        "tshark", "C:\\Program Files\\Wireshark\\tshark.exe")
                .filter(Objects::nonNull).filter(RealTsharkTest::runs).findFirst().orElse(null);
        assumeTrue(tshark != null, "TShark not installed: real-tool tests skipped");
    }
    private static boolean runs(String candidate) {
        try { new BoundedProcessRunner(64 * 1024).run(List.of(candidate, "--version"), Duration.ofSeconds(20)); return true; }
        catch (ScanException e) { return false; }
    }
    private TsharkTrafficAnalyzer analyzer() { return new TsharkTrafficAnalyzer(tshark, new BoundedProcessRunner(1024 * 1024)); }

    @Test void importsRawIpCaptureWithDnsTlsNameAndTimes() throws Exception {
        var analysis = analyzer().analyze(SyntheticCapture.rawIp(temp.resolve("raw.pcap")));
        assertEquals(5, analysis.packets()); assertFalse(analysis.truncated());
        assertEquals(Instant.ofEpochSecond(SyntheticCapture.START_EPOCH, 250_000_000), analysis.firstPacket());
        assertEquals(Instant.ofEpochSecond(SyntheticCapture.START_EPOCH + 4, 250_000_000), analysis.lastPacket());
        assertEquals(CaptureAnalysis.AppMetadata.NONE, analysis.appMetadata());
        assertEquals(64, analysis.sha256().length());

        assertEquals(4, analysis.flows().size());
        var http = analysis.flows().get(2);
        assertEquals(SyntheticCapture.PLAIN_SERVER, http.destination()); assertEquals("80", http.destinationPort());
        assertEquals(SyntheticCapture.PLAIN_NAME, http.httpHost()); assertEquals("", http.serverName());
        var tls = analysis.flows().getLast();
        assertEquals(SyntheticCapture.SERVER, tls.destination()); assertEquals("443", tls.destinationPort());
        assertEquals(2, tls.packets()); assertEquals(SyntheticCapture.NAME, tls.serverName()); assertEquals("", tls.httpHost()); assertNull(tls.app());

        assertEquals(1, analysis.dnsNames().size());
        var dns = analysis.dnsNames().getFirst();
        assertEquals(SyntheticCapture.NAME, dns.name()); assertEquals(1, dns.queries()); assertEquals(1, dns.responses());
        assertEquals(List.of(SyntheticCapture.SERVER), dns.addresses());
    }
    @Test void readsAppFromPcapdroidExtensionsWithoutCountingTheTrailerAsTraffic() throws Exception {
        var raw = analyzer().analyze(SyntheticCapture.rawIp(temp.resolve("raw.pcap")));
        var extended = analyzer().analyze(SyntheticCapture.pcapdroidExtensions(temp.resolve("extended.pcap")));
        assertEquals(CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, extended.appMetadata());
        assertEquals(raw.flows().size(), extended.flows().size());
        for (int i = 0; i < raw.flows().size(); i++) {
            assertEquals(new CaptureApp(SyntheticCapture.UID, SyntheticCapture.APP), extended.flows().get(i).app(), "flow " + i);
            assertEquals(raw.flows().get(i).bytes(), extended.flows().get(i).bytes(), "same IP bytes with or without trailer");
        }
        assertEquals(raw.dnsNames(), extended.dnsNames());
    }
    @Test void truncatedFileGivesPartialResultMarkedAsSuch() throws Exception {
        var analysis = analyzer().analyze(SyntheticCapture.truncated(temp.resolve("cut.pcap")));
        assertTrue(analysis.truncated()); assertEquals(4, analysis.packets());
    }
    @Test void fileThatIsNotACaptureIsRejectedWithTsharkReason() throws Exception {
        Path file = Files.writeString(temp.resolve("notes.pcap"), "this is not a capture");
        var error = assertThrows(ScanException.class, () -> analyzer().analyze(file));
        assertTrue(error.getMessage().contains("TShark"));
    }
}
