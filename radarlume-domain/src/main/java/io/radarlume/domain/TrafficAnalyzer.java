package io.radarlume.domain;

import java.nio.file.Path;

public interface TrafficAnalyzer {
    /**
     * @param keylog file of TLS session keys (SSLKEYLOGFILE format) exported together with the capture,
     *               or {@code null} to leave encrypted content unread
     */
    CaptureAnalysis analyze(Path capture, Path keylog);

    default CaptureAnalysis analyze(Path capture) { return analyze(capture, null); }
}
