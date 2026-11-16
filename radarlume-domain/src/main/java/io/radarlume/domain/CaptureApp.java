package io.radarlume.domain;

/**
 * App attribution exactly as written by the capture tool (for example the PCAPdroid trailer).
 *
 * @param name what the capture tool wrote: on real PCAPdroid captures it is the app's display name
 *             ("Facebook", "AVG AntiVirus"), not the package identifier. It may be truncated by the
 *             capture format, is not unique, and is empty when only the UID is known.
 */
public record CaptureApp(int uid, String name) {
    @Override public String toString() {
        return name.isEmpty() ? "UID " + uid : name + " (UID " + uid + ")";
    }
}
