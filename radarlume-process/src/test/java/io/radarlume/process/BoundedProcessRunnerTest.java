package io.radarlume.process;

import io.radarlume.domain.ScanException;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class BoundedProcessRunnerTest {
    private List<String> command(String... args) {
        String java = Path.of(System.getProperty("java.home"), "bin", System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java").toString();
        var command = new ArrayList<>(List.of(java, "-cp", Path.of("target/test-classes").toAbsolutePath().toString(), ProcessFixture.class.getName()));
        command.addAll(List.of(args)); return command;
    }
    @Test void preservesArgumentsWithoutShellEvaluation() {
        String text = "hello world; $(whoami) & echo surprise";
        assertEquals(text, new BoundedProcessRunner(4096).run(command("echo", text), Duration.ofSeconds(10)));
    }
    @Test void rejectsFailureInsteadOfReturningPartialStdout() {
        assertThrows(ScanException.class, () -> new BoundedProcessRunner(4096).run(command("fail"), Duration.ofSeconds(10)));
    }
    @Test void drainsAndBoundsStderr() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertThrows(ScanException.class,
                () -> new BoundedProcessRunner(4096).run(command("flood"), Duration.ofSeconds(5))));
    }
    @Test void enforcesTimeout() {
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> assertThrows(ScanException.class,
                () -> new BoundedProcessRunner(4096).run(command("sleep"), Duration.ofMillis(200))));
    }
    @Test void interruptionTerminatesWorker() throws Exception {
        var executor = Executors.newSingleThreadExecutor();
        var future = executor.submit(() -> new BoundedProcessRunner(4096).run(command("sleep"), Duration.ofSeconds(30)));
        Thread.sleep(300); future.cancel(true); executor.shutdownNow();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }
    @Test void missingExecutableProducesActionableError() {
        assertThrows(ScanException.class, () -> new BoundedProcessRunner(4096).run(List.of("radarlume-nonexistent-executable"), Duration.ofSeconds(2)));
    }
}
