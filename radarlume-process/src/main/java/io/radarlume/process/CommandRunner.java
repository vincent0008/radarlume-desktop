package io.radarlume.process;

import java.time.Duration;
import java.util.List;

@FunctionalInterface
public interface CommandRunner {
    /** Returns stdout; fails on any non-zero exit code. */
    String run(List<String> arguments, Duration timeout);

    /**
     * Like {@link #run} but hands the exit code and stderr to the caller, for tools that
     * report a recoverable condition (for example a truncated capture) with a non-zero exit.
     */
    default CommandResult execute(List<String> arguments, Duration timeout) {
        return new CommandResult(0, run(arguments, timeout), "");
    }

    record CommandResult(int exitCode, String stdout, String stderr) {}
}
