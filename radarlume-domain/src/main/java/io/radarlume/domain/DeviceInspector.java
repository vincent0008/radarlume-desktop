package io.radarlume.domain;

import java.util.List;

public interface DeviceInspector {
    List<Device> discover();
    List<InstalledApp> inventory(String serial);
}
