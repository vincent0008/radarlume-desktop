package io.radarlume.process;

import io.radarlume.domain.ScanException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;

/** No host shell. Concurrent draining prevents pipe deadlock; output and total runtime are bounded. */
public final class BoundedProcessRunner implements CommandRunner {
    private final int maxBytes;
    public BoundedProcessRunner(int maxBytes) {
        if (maxBytes < 1) throw new IllegalArgumentException("maxBytes");
        this.maxBytes = maxBytes;
    }
    @Override public String run(List<String> arguments, Duration timeout) {
        if (arguments.isEmpty() || timeout.isNegative() || timeout.isZero()) throw new IllegalArgumentException();
        Process process;
        try { process = new ProcessBuilder(List.copyOf(arguments)).start(); }
        catch (IOException e) { throw new ScanException("Impossibile avviare lo strumento. Verifica percorso e installazione.", e); }
        ExecutorService readers = Executors.newVirtualThreadPerTaskExecutor();
        long deadline = System.nanoTime() + timeout.toNanos();
        Future<byte[]> out = readers.submit(() -> read(process.getInputStream(), process));
        Future<byte[]> err = readers.submit(() -> read(process.getErrorStream(), process));
        try {
            process.getOutputStream().close();
            if (!process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS))
                throw new TimeoutException();
            byte[] stdout = out.get(remaining(deadline), TimeUnit.NANOSECONDS);
            err.get(remaining(deadline), TimeUnit.NANOSECONDS);
            if (process.exitValue() != 0)
                throw new ScanException("Lo strumento ha restituito errore (codice " + process.exitValue()
                        + "). Verifica autorizzazione ADB o validità della cattura. Nessun risultato parziale utilizzato.");
            return new String(stdout, StandardCharsets.UTF_8);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanException("Operazione annullata.", e);
        } catch (TimeoutException e) {
            throw new ScanException("Tempo massimo superato. Operazione interrotta.", e);
        } catch (ExecutionException e) {
            throw new ScanException("Output non leggibile o superiore al limite di " + maxBytes + " byte.", e.getCause());
        } catch (IOException e) {
            throw new ScanException("Errore di comunicazione con lo strumento.", e);
        } finally {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            try { process.getInputStream().close(); } catch (IOException ignored) { }
            try { process.getErrorStream().close(); } catch (IOException ignored) { }
            out.cancel(true); err.cancel(true); readers.shutdownNow();
        }
    }
    private static long remaining(long deadline) { return Math.max(1, deadline - System.nanoTime()); }
    private byte[] read(InputStream input, Process process) throws IOException {
        try (input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = input.read(buffer)) != -1) {
                if (output.size() > maxBytes - n) {
                    process.destroyForcibly();
                    throw new IOException("Limite output superato");
                }
                output.write(buffer, 0, n);
            }
            return output.toByteArray();
        }
    }
}
