package io.radarlume.domain;

/**
 * App attribution exactly as written by the capture tool (for example the PCAPdroid trailer).
 *
 * @param packageName may be truncated by the capture format, or empty when only the UID is known
 */
public record CaptureApp(int uid, String packageName) {
    @Override public String toString() {
        return packageName.isEmpty() ? "UID " + uid : packageName + " (UID " + uid + ")";
    }
}
