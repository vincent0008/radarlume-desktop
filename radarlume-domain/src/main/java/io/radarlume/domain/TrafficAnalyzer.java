package io.radarlume.domain;

import java.nio.file.Path;

public interface TrafficAnalyzer { CaptureAnalysis analyze(Path capture); }
