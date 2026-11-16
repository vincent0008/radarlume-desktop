package io.radarlume.domain;

import java.time.Instant;

/**
 * One HTTP request line read from a capture. Bodies and headers other than the host are not kept.
 *
 * @param destination remote address the packet was sent to
 * @param app         {@code null} when the capture does not say which app sent it
 * @param path        request target with its query string, as sent; it can contain personal data
 * @param decrypted   {@code true} when the request travelled inside TLS and was read with the session keys
 *                    supplied by the user; {@code false} when it was sent unencrypted
 */
public record HttpRequest(Instant time, String destination, CaptureApp app, String method, String host, String path,
                          boolean decrypted) {}
