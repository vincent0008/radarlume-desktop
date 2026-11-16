package io.radarlume.domain;

import java.time.Instant;
import java.util.List;

/**
 * One HTTP request read from a capture, with the request-side headers and body. Responses are not kept.
 *
 * @param app          {@code null} when the capture does not say which app sent it
 * @param path         request target with its query string, as sent; it can contain personal data
 * @param decrypted    {@code true} when the request travelled inside TLS and was read with the session keys
 *                     supplied by the user; {@code false} when it was sent unencrypted
 * @param headerNames  lower-case names of the request headers that were present (values are not all kept)
 * @param referer      value of the Referer header, or empty
 * @param origin       value of the Origin header, or empty
 * @param contentType  value of the Content-Type header, or empty
 * @param body         request body decoded as text, sanitised and length-bounded; empty when there is no body
 *                     or when it is binary (see {@link #bodyBinary})
 * @param bodyBytes    size of the body actually read, in bytes
 * @param bodyBinary   the body is not printable text and is not shown
 * @param bodyTruncated the body was longer than the per-request limit and was cut
 */
public record HttpRequest(Instant time, String destination, CaptureApp app, String method, String host, String path,
                          boolean decrypted, List<String> headerNames, String referer, String origin, String contentType,
                          String body, long bodyBytes, boolean bodyBinary, boolean bodyTruncated) {
    public HttpRequest { headerNames = List.copyOf(headerNames); }

    /** Whether a request header with this (lower-case) name was present. */
    public boolean hasHeader(String name) { return headerNames.contains(name); }
}
