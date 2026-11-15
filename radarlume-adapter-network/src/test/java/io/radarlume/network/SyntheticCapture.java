package io.radarlume.network;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * Builds small capture files in code, so that no real (personal) traffic is ever committed.
 * Addresses are documentation ranges and the name is under the reserved {@code .test} domain.
 * The scenario: one DNS query and its answer, one unencrypted HTTP request, then a TCP SYN and a TLS
 * ClientHello towards the resolved address.
 */
final class SyntheticCapture {
    static final String NAME = "example.test";
    static final String PHONE = "10.215.173.1", RESOLVER = "10.215.173.2", SERVER = "192.0.2.10";
    static final String PLAIN_NAME = "plain.test", PLAIN_SERVER = "192.0.2.20";
    static final int UID = 10123;
    static final String APP = "com.example.browser";
    /** 2026-01-01T00:00:00Z; packets are one second apart, each at .25 s. */
    static final int START_EPOCH = 1_767_225_600;

    private static final int LINKTYPE_ETHERNET = 1, LINKTYPE_RAW_IP = 101;
    private static final int[] PHONE_IP = {10, 215, 173, 1}, RESOLVER_IP = {10, 215, 173, 2}, SERVER_IP = {192, 0, 2, 10}, PLAIN_IP = {192, 0, 2, 20};

    private SyntheticCapture() {}

    /** What PCAPdroid writes by default: bare IP packets, no app information. */
    static Path rawIp(Path file) throws IOException { return write(file, LINKTYPE_RAW_IP, packets()); }

    /** What PCAPdroid writes with "PCAPdroid extensions" enabled: fake Ethernet header plus a trailer naming the app. */
    static Path pcapdroidExtensions(Path file) throws IOException {
        return write(file, LINKTYPE_ETHERNET, packets().stream().map(p -> withTrailer(p, UID, APP)).toList());
    }

    /** A capture whose last packet is incomplete, as after an interrupted export or copy. */
    static Path truncated(Path file) throws IOException {
        byte[] whole = Files.readAllBytes(rawIp(file));
        return Files.write(file, Arrays.copyOf(whole, whole.length - 30));
    }

    private static List<byte[]> packets() {
        return List.of(
                ip4(17, PHONE_IP, RESOLVER_IP, udp(40000, 53, dnsQuery(NAME))),
                ip4(17, RESOLVER_IP, PHONE_IP, udp(53, 40000, dnsAnswer(NAME, SERVER_IP))),
                ip4(6, PHONE_IP, PLAIN_IP, tcp(50001, 80, 101, 0x18, ("GET /track?id=1 HTTP/1.1\r\nHost: " + PLAIN_NAME + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII))),
                ip4(6, PHONE_IP, SERVER_IP, tcp(50000, 443, 100, 0x02, new byte[0])),
                ip4(6, PHONE_IP, SERVER_IP, tcp(50000, 443, 101, 0x18, clientHello(NAME))));
    }
    private static byte[] ip4(int proto, int[] src, int[] dst, byte[] payload) {
        ByteBuffer b = ByteBuffer.allocate(20 + payload.length);
        b.put((byte) 0x45).put((byte) 0).putShort((short) (20 + payload.length)).putShort((short) 1).putShort((short) 0x4000)
         .put((byte) 64).put((byte) proto).putShort((short) 0);
        for (int x : src) b.put((byte) x); for (int x : dst) b.put((byte) x);
        b.put(payload);
        byte[] a = b.array(); int sum = 0;
        for (int i = 0; i < 20; i += 2) sum += ((a[i] & 0xff) << 8) | (a[i + 1] & 0xff);
        while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
        a[10] = (byte) (~sum >> 8); a[11] = (byte) ~sum;
        return a;
    }
    private static byte[] udp(int sp, int dp, byte[] data) {
        return ByteBuffer.allocate(8 + data.length).putShort((short) sp).putShort((short) dp).putShort((short) (8 + data.length)).putShort((short) 0).put(data).array();
    }
    private static byte[] tcp(int sp, int dp, int seq, int flags, byte[] data) {
        return ByteBuffer.allocate(20 + data.length).putShort((short) sp).putShort((short) dp).putInt(seq).putInt(flags == 2 ? 0 : 1)
            .put((byte) 0x50).put((byte) flags).putShort((short) 65535).putShort((short) 0).putShort((short) 0).put(data).array();
    }
    private static byte[] qname(String name) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (String l : name.split("\\.")) { o.write(l.length()); o.writeBytes(l.getBytes(StandardCharsets.US_ASCII)); }
        o.write(0); return o.toByteArray();
    }
    private static byte[] dnsQuery(String name) {
        byte[] q = qname(name);
        return ByteBuffer.allocate(12 + q.length + 4).putShort((short) 0x1234).putShort((short) 0x0100).putShort((short) 1).putShort((short) 0).putShort((short) 0).putShort((short) 0)
            .put(q).putShort((short) 1).putShort((short) 1).array();
    }
    private static byte[] dnsAnswer(String name, int[] addr) {
        byte[] q = qname(name);
        ByteBuffer b = ByteBuffer.allocate(12 + q.length + 4 + 16).putShort((short) 0x1234).putShort((short) 0x8180).putShort((short) 1).putShort((short) 1).putShort((short) 0).putShort((short) 0)
            .put(q).putShort((short) 1).putShort((short) 1)
            .putShort((short) 0xc00c).putShort((short) 1).putShort((short) 1).putInt(60).putShort((short) 4);
        for (int x : addr) b.put((byte) x); return b.array();
    }
    private static byte[] clientHello(String sni) {
        byte[] host = sni.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer ext = ByteBuffer.allocate(9 + host.length).putShort((short) 0).putShort((short) (5 + host.length)).putShort((short) (3 + host.length)).put((byte) 0).putShort((short) host.length).put(host);
        int bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext.capacity();
        ByteBuffer b = ByteBuffer.allocate(5 + 4 + bodyLen);
        b.put((byte) 22).putShort((short) 0x0301).putShort((short) (4 + bodyLen));
        b.put((byte) 1).put((byte) 0).putShort((short) bodyLen);
        b.putShort((short) 0x0303).put(new byte[32]).put((byte) 0).putShort((short) 2).putShort((short) 0x1301).put((byte) 1).put((byte) 0)
         .putShort((short) ext.capacity()).put(ext.array());
        return b.array();
    }
    private static byte[] withTrailer(byte[] ip, int uid, String app) {
        int pad = (4 - ((14 + ip.length) % 4)) % 4;
        ByteBuffer b = ByteBuffer.allocate(14 + ip.length + pad + 28 + 4);
        b.put(new byte[12]).putShort((short) 0x0800).put(ip).put(new byte[pad]);
        b.putInt(0x01072021).putInt(uid);
        byte[] name = Arrays.copyOf(app.getBytes(StandardCharsets.US_ASCII), 20); name[19] = 0; b.put(name);
        b.putInt(0);
        return b.array();
    }
    private static Path write(Path file, int linktype, List<byte[]> packets) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(24 + packets.stream().mapToInt(p -> 16 + p.length).sum()).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0xa1b2c3d4).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0).putInt(65535).putInt(linktype);
        int t = START_EPOCH;
        for (byte[] p : packets) { b.putInt(t++).putInt(250_000).putInt(p.length).putInt(p.length); b.put(p); }
        return Files.write(file, b.array());
    }
}
