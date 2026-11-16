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
        return new CaptureAnalysis("test.pcap", 1, "hash", flows.size(), Instant.EPOCH, Instant.EPOCH, metadata, truncated, flows, List.of(), List.of(),
                CaptureAnalysis.Tls.NOT_EXAMINED, List.of());
    }
    private static CaptureAnalysis withRequests(CaptureAnalysis.Tls tls, HttpRequest... requests) {
        var flows = List.of(flow(PHONE, 40000, "192.0.2.10", 443, 100, 10, APP, "", ""));
        return new CaptureAnalysis("test.pcap", 1, "hash", 1, Instant.EPOCH, Instant.EPOCH, CaptureAnalysis.AppMetadata.PCAPDROID_TRAILER, false,
                flows, List.of(), List.of(), tls, List.of(requests));
    }
    private static HttpRequest request(String host, String path, boolean decrypted) {
        return req(host, "GET", path, decrypted, "", "", List.of());
    }
    private static HttpRequest req(String host, String method, String path, boolean decrypted, String body, String referer, List<String> headers) {
        return new HttpRequest(Instant.EPOCH, "192.0.2.10", APP, method, host, path, decrypted, headers, referer, "",
                body.isEmpty() ? "" : "application/x-www-form-urlencoded", body, body.length(), false, false);
    }

    @Test void parameterNamesSuggestingPersonalDataAreReportedWithoutTheirValues() {
        var findings = NetworkAssessmentService.evaluate(withRequests(new CaptureAnalysis.Tls(true, 4, 3),
                request("ads.test", "/sync?gdpr=1&Lat=45.4642&lon=9.19&device_id=abc123", true),
                request("ads.test", "/sync?lat=45.4642", true),
                request("mail.test", "/open?u=mario.rossi%40example.test", false),
                request("plain.test", "/page?lat=&id=7&latency=30", true),
                request("plain.test", "/no-query", true)));
        assertEquals(List.of("DATA-007", "NET-004", "NET-004"), rules(findings));
        assertTrue(findings.getFirst().explanation().contains("3 connessioni TLS su 4"));
        Finding ads = findings.get(1), mail = findings.get(2);
        assertEquals("com.example.app (UID 10123) → ads.test", ads.evidenceKey());
        assertTrue(ads.explanation().startsWith("2 richieste"));
        assertTrue(ads.explanation().contains("posizione: Lat, lat, lon") && ads.explanation().contains("device_id"));
        assertTrue(ads.explanation().contains("in rete erano cifrate"));
        assertFalse(ads.explanation().contains("45.4642") || ads.explanation().contains("abc123"), "Values must stay out of the findings");
        assertTrue(mail.explanation().contains("forma di indirizzo email") && mail.explanation().contains("senza cifratura"));
        assertFalse(mail.explanation().contains("mario"));
        assertEquals(Finding.Confidence.LOW, ads.confidence());
    }
    @Test void scansBodyRefererAndAuthorizationHeaderToo() {
        var findings = NetworkAssessmentService.evaluate(withRequests(new CaptureAnalysis.Tls(true, 3, 3),
                req("api.test", "POST", "/login", true, "user=mario&password=hunter2&lat=45.1", "", List.of("content-type")),
                req("api.test", "GET", "/me", true, "", "", List.of("authorization", "cookie")),
                req("track.test", "GET", "/p", true, "", "https://track.test/x?email=a%40b.test", List.of())));
        var byRule = findings.stream().collect(java.util.stream.Collectors.groupingBy(Finding::ruleId));
        assertEquals(2, byRule.get("NET-004").size());
        Finding api = byRule.get("NET-004").stream().filter(x -> x.evidenceKey().contains("api.test")).findFirst().orElseThrow();
        assertTrue(api.explanation().contains("credenziale:") && api.explanation().contains("password")
                && api.explanation().contains("(intestazione Authorization)"), api.explanation());
        assertTrue(api.explanation().contains("posizione: lat"));
        assertFalse(api.explanation().contains("hunter2"), "Body values must not appear");
        Finding track = byRule.get("NET-004").stream().filter(x -> x.evidenceKey().contains("track.test")).findFirst().orElseThrow();
        assertTrue(track.explanation().contains("forma di indirizzo email"));
    }
    @Test void jsonBodyIsNotMisreadAsFormParameters() {
        var request = new HttpRequest(Instant.EPOCH, "192.0.2.10", APP, "POST", "api.test", "/e", true, List.of(),
                "", "", "application/json", "{\"note\":\"password=x should not count\"}", 36, false, false);
        assertTrue(NetworkAssessmentService.evaluate(withRequests(new CaptureAnalysis.Tls(true, 1, 1), request)).stream()
                .noneMatch(f -> f.ruleId().equals("NET-004")));
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
