package io.radarlume.domain;

import java.nio.file.Path;
import java.util.List;

public interface TrafficAnalyzer { List<NetworkFlow> analyze(Path capture); }
