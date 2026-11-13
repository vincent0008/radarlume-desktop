package io.radarlume.network;

import io.radarlume.domain.*;
import io.radarlume.process.CommandRunner;
import java.nio.file.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;

public final class TsharkTrafficAnalyzer implements TrafficAnalyzer {
    public static final long MAX_FILE_BYTES = 100L * 1024 * 1024;
    private final String executable;
    private final CommandRunner runner;
    public TsharkTrafficAnalyzer(String executable, CommandRunner runner) { this.executable = executable; this.runner = runner; }
    @Override public List<NetworkFlow> analyze(Path capture) {
        try {
            if (!Files.isRegularFile(capture) || !Files.isReadable(capture)) throw new ScanException("Cattura non leggibile.");
            if (Files.size(capture) > MAX_FILE_BYTES) throw new ScanException("La cattura supera il limite MVP di 100 MiB.");
        } catch (IOException e) { throw new ScanException("Impossibile leggere la cattura.", e); }
        var command = new ArrayList<>(List.of(executable, "-n", "-r", capture.toAbsolutePath().toString(),
                "-Y", "(ip or ipv6) and (tcp or udp)", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"));
        for (String field : List.of("ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len")) {
            command.add("-e"); command.add(field);
        }
        return parse(runner.run(command, Duration.ofSeconds(90)));
    }
    public static List<NetworkFlow> parse(String output) {
        record Key(String src, String dst, String protocol, String sport, String dport) {}
        var totals = new LinkedHashMap<Key, long[]>();
        for (String line : output.lines().toList()) {
            if (Thread.currentThread().isInterrupted()) throw new ScanException("Importazione annullata.");
            if (line.isBlank()) continue;
            String[] f = line.split("\t", -1);
            if (f.length != 9) throw new ScanException("Formato TShark inatteso: sono richiesti nove campi.");
            boolean tcp = !f[4].isEmpty();
            String src = f[0].isEmpty() ? f[1] : f[0], dst = f[2].isEmpty() ? f[3] : f[2];
            String sport = tcp ? f[4] : f[6], dport = tcp ? f[5] : f[7];
            try {
                if (src.isBlank() || dst.isBlank()) throw new IllegalArgumentException();
                int sp = Integer.parseInt(sport), dp = Integer.parseInt(dport);
                long bytes = Long.parseLong(f[8]);
                if (sp < 0 || sp > 65535 || dp < 0 || dp > 65535 || bytes < 0) throw new IllegalArgumentException();
                var key = new Key(src, dst, tcp ? "TCP" : "UDP", sport, dport);
                long[] count = totals.computeIfAbsent(key, ignored -> new long[2]);
                count[0] = Math.addExact(count[0], 1); count[1] = Math.addExact(count[1], bytes);
                if (totals.size() > 50_000) throw new ScanException("Troppe conversazioni: limite MVP di 50.000 flussi.");
            } catch (IllegalArgumentException | ArithmeticException e) { throw new ScanException("Campi TShark non validi.", e); }
        }
        return totals.entrySet().stream().map(e -> new NetworkFlow(e.getKey().src(), e.getKey().dst(), e.getKey().protocol(),
                e.getKey().sport(), e.getKey().dport(), e.getValue()[0], e.getValue()[1])).toList();
    }
}
