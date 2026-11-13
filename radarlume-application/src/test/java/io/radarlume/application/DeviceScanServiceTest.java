package io.radarlume.application;

import io.radarlume.domain.*;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DeviceScanServiceTest {
    private static final class Inspector implements DeviceInspector {
        int discoveries, inventories;
        List<Device> devices = List.of(new Device("abc", Device.State.AUTHORIZED, "Pixel"));
        public List<Device> discover() { discoveries++; return devices; }
        public List<InstalledApp> inventory(String serial) { inventories++; return List.of(new InstalledApp("android", true)); }
    }
    @Test void noDeviceAccessWithoutConsent() {
        var inspector = new Inspector();
        assertThrows(ScanException.class, () -> new DeviceScanService(inspector, Clock.systemUTC()).scan("abc", false));
        assertEquals(0, inspector.discoveries); assertEquals(0, inspector.inventories);
    }
    @Test void rechecksAuthorizationAndConnectionBeforeReading() {
        var inspector = new Inspector(); var service = new DeviceScanService(inspector, Clock.systemUTC());
        for (Device.State state : List.of(Device.State.UNAUTHORIZED, Device.State.OFFLINE, Device.State.OTHER, Device.State.NO_PERMISSIONS)) {
            inspector.devices = List.of(new Device("abc", state, "Pixel"));
            assertThrows(ScanException.class, () -> service.scan("abc", true));
        }
        inspector.devices = List.of(); assertThrows(ScanException.class, () -> service.scan("abc", true));
        assertEquals(0, inspector.inventories);
    }
    @Test void createsTimestampedImmutableSnapshot() {
        var inspector = new Inspector(); Instant now = Instant.parse("2026-01-01T00:00:00Z");
        var snapshot = new DeviceScanService(inspector, Clock.fixed(now, ZoneOffset.UTC)).scan("abc", true);
        assertEquals(now, snapshot.collectedAt()); assertEquals(1, snapshot.apps().size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.apps().clear());
    }
}
