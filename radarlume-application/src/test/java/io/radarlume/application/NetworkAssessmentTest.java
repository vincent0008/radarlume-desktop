package io.radarlume.application;

import io.radarlume.domain.*;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class NetworkAssessmentTest {
    private static final String PHONE = "10.215.173.1";
    private static final CaptureApp APP = new CaptureApp(10123, "com.example.app");
    private int port = 40000;

    private static NetworkFlow flow(String src, int sport, String dst, int dport, long bytes, long second, CaptureApp app, String sni, String http) {
        return new NetworkFlow(src, dst, "TCP", Integer.toString(sport), Integer.toString(dport), 1, bytes,
                Instant.ofEpochSecond(second), Instant.ofEpochSecond(second + 1), app, sni, http);
    }
    /** Both directions of one exchange started by the phone. */
    private List<NetworkFlow> exchange(String remote, int remotePort, long sent, long received, CaptureApp app, String sni, String http) {
        int local = port++;
        return List.of(flow(PHONE, local, remote, remotePort, sent, 10, app, sni, http), flow(remote, remotePort, PHONE, local, received, 11, app, "", ""));
    }
    private static CaptureAnalysis capture(List<NetworkFlow> flows, CaptureAnalysis.AppMetadata metadata, boolean truncated) {
        return new CaptureAnalysis("test.pcap", 1, "hash", flows.size(), Instant.EPOCH, Instant.EPOCH, metadata, truncated, flows, List.of(), List.of());
    }
    private static List<String> rules(List<Finding> findings) { return findings.stream().map(Finding::ruleId).toList(); }

    @Test void ordinaryEncryptedBrowsingRaisesNothing() {
        var flows = exchange("192.0.2.10", 443, 4_000, 900_000, APP, "example.test", "");
        assertTrue(NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false)).isEmpty());
    }
    @Test void clearTextHttpIsReportedOncePerAppAndHost() {
        var flows = new ArrayList<NetworkFlow>();
        flows.addAll(exchange("192.0.2.20", 80, 500, 2_000, APP, "", "plain.test"));
        flows.addAll(exchange("192.0.2.20", 80, 500, 2_000, APP, "", "plain.test"));
        flows.addAll(exchange("192.0.2.30", 80, 500, 2_000, APP, "", ""));
        var findings = NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false));
        assertEquals(List.of("NET-001"), rules(findings), "Port 80 alone, without a decoded request, is not reported");
        assertEquals("com.example.app (UID 10123) → plain.test", findings.getFirst().evidenceKey());
        assertTrue(findings.getFirst().explanation().contains("2 connessioni"));
        assertEquals(Finding.Confidence.HIGH, findings.getFirst().confidence());
    }
    @Test void uploadImbalanceNeedsBothVolumeAndRatioAndStaysLowConfidence() {
        long min = NetworkAssessmentService.UPLOAD_MIN_BYTES;
        var big = exchange("192.0.2.40", 443, min, min / 2, APP, "upload.test", "");
        var findings = NetworkAssessmentService.evaluate(capture(big, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false));
        assertEquals(List.of("NET-002"), rules(findings));
        assertEquals(Finding.Confidence.LOW, findings.getFirst().confidence());
        assertEquals("com.example.app (UID 10123) → upload.test (192.0.2.40)", findings.getFirst().evidenceKey());

        var small = exchange("192.0.2.40", 443, min - 1, 0, APP, "", "");
        var balanced = exchange("192.0.2.41", 443, min, min / 2 + 1, APP, "", "");
        assertTrue(NetworkAssessmentService.evaluate(capture(small, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false)).isEmpty());
        assertTrue(NetworkAssessmentService.evaluate(capture(balanced, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false)).isEmpty());
    }
    @Test void uploadIsSummedAcrossConnectionsToTheSameAddress() {
        long half = NetworkAssessmentService.UPLOAD_MIN_BYTES / 2;
        var flows = new ArrayList<NetworkFlow>();
        flows.addAll(exchange("192.0.2.40", 443, half, 100, APP, "", ""));
        flows.addAll(exchange("192.0.2.40", 443, half, 100, APP, "", ""));
        assertEquals(List.of("NET-002"), rules(NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false))));
    }
    @Test void downloadIsNotMistakenForUploadWhenTheServerSpeaksFirstInTheCapture() {
        // Capture started mid-connection: the first packet seen comes from the server. The well-known port decides.
        long big = NetworkAssessmentService.UPLOAD_MIN_BYTES * 4;
        var flows = List.of(flow("192.0.2.50", 443, PHONE, 45000, big, 5, APP, "", ""), flow(PHONE, 45000, "192.0.2.50", 443, 1_000, 6, APP, "", ""));
        assertTrue(NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false)).isEmpty());
        var conversation = NetworkAssessmentService.conversations(flows).getFirst();
        assertEquals("192.0.2.50", conversation.remote()); assertEquals(1_000, conversation.sent()); assertEquals(big, conversation.received());
    }
    @Test void manyDestinationsCountsDistinctAddressesPerApp() {
        var flows = new ArrayList<NetworkFlow>();
        for (int i = 0; i < NetworkAssessmentService.MANY_DESTINATIONS; i++) flows.addAll(exchange("198.51.100." + i, 443, 500, 2_000, APP, "", ""));
        for (int i = 0; i < 5; i++) flows.addAll(exchange("198.51.100.1", 443, 500, 2_000, APP, "", ""));
        var findings = NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false));
        assertEquals(List.of("NET-003"), rules(findings));
        assertTrue(findings.getFirst().explanation().contains(NetworkAssessmentService.MANY_DESTINATIONS + " indirizzi"));
        assertEquals(Finding.Severity.INFO, findings.getFirst().severity());

        flows.subList(0, 2).clear();
        assertTrue(NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false)).isEmpty());
    }
    @Test void missingDataIsStatedInsteadOfLookingLikeACleanResult() {
        var flows = new ArrayList<NetworkFlow>();
        for (int i = 0; i < NetworkAssessmentService.MANY_DESTINATIONS; i++) flows.addAll(exchange("198.51.100." + i, 443, 500, 2_000, null, "", ""));
        assertEquals(List.of("DATA-003", "DATA-004"), rules(NetworkAssessmentService.evaluate(capture(flows, CaptureAnalysis.AppMetadata.NONE, true))),
                "Truncated and without app metadata: both limits reported, per-app rule not applied");
        assertEquals(List.of("DATA-005"), rules(NetworkAssessmentService.evaluate(capture(List.of(), CaptureAnalysis.AppMetadata.NONE, false))));
    }
}
