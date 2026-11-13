package io.radarlume.process;

import java.time.Duration;
import java.util.List;

@FunctionalInterface
public interface CommandRunner {
    String run(List<String> arguments, Duration timeout);
}
