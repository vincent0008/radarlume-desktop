package io.radarlume.network;

import io.radarlume.domain.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TsharkTrafficAnalyzerTest {
    @TempDir Path temp;
    @Test void aggregatesIpv4AndIpv6WithoutMergingDirections() {
        var flows = TsharkTrafficAnalyzer.parse("10.0.0.1\t\t10.0.0.2\t\t1234\t443\t\t\t60\n"
                + "10.0.0.1\t\t10.0.0.2\t\t1234\t443\t\t\t100\n"
                + "10.0.0.2\t\t10.0.0.1\t\t443\t1234\t\t\t80\n"
                + "\t2001:db8::1\t\t2001:db8::2\t\t\t53000\t53\t70\n");
        assertEquals(3, flows.size()); assertEquals(2, flows.getFirst().packets()); assertEquals(160, flows.getFirst().bytes());
        assertEquals("UDP", flows.getLast().protocol()); assertEquals("2001:db8::1", flows.getLast().source());
    }
    @Test void rejectsMalformedAndNegativeCounters() {
        assertThrows(ScanException.class, () -> TsharkTrafficAnalyzer.parse("invalid"));
        assertThrows(ScanException.class, () -> TsharkTrafficAnalyzer.parse("a\t\tb\t\t1\t2\t\t\t-10"));
        assertThrows(ScanException.class, () -> TsharkTrafficAnalyzer.parse("a\t\tb\t\t65536\t2\t\t\t10"));
        assertTrue(TsharkTrafficAnalyzer.parse("").isEmpty());
    }
    @Test void passesCaptureAsSingleArgumentAndDisablesNameResolution() throws Exception {
        Path capture = Files.write(temp.resolve("capture with spaces.pcap"), new byte[]{1});
        List<List<String>> seen = new ArrayList<>();
        var analyzer = new TsharkTrafficAnalyzer("tshark", (args, timeout) -> { seen.add(args); return ""; });
        analyzer.analyze(capture);
        assertEquals(capture.toAbsolutePath().toString(), seen.getFirst().get(3));
        assertEquals("-n", seen.getFirst().get(1)); assertFalse(seen.getFirst().contains("-i"));
        assertThrows(ScanException.class, () -> analyzer.analyze(temp.resolve("missing.pcap")));
        assertEquals(1, seen.size());
    }
}
