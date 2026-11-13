package io.radarlume.application;

import io.radarlume.domain.*;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class DeviceScanService {
    private final DeviceInspector inspector;
    private final Clock clock;
    public DeviceScanService(DeviceInspector inspector, Clock clock) { this.inspector = inspector; this.clock = clock; }
    public List<Device> discover() { return inspector.discover(); }
    public Inventory scan(String serial, boolean consent) {
        if (!consent) throw new ScanException("Conferma di essere autorizzato ad analizzare questo dispositivo.");
        Device device = inspector.discover().stream().filter(d -> d.serial().equals(serial)).findFirst()
                .orElseThrow(() -> new ScanException("Dispositivo scollegato. Aggiorna l'elenco."));
        if (device.state() != Device.State.AUTHORIZED)
            throw new ScanException("ADB non autorizzato o dispositivo offline. Sblocca il telefono e autorizza questo PC.");
        var apps = inspector.inventory(serial);
        return new Inventory(UUID.randomUUID(), Instant.now(clock), device, apps);
    }
}
