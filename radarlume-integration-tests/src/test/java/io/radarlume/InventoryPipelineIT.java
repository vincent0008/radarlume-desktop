package io.radarlume;

import io.radarlume.adb.AdbDeviceInspector;
import io.radarlume.application.DeviceScanService;
import io.radarlume.domain.*;
import io.radarlume.storage.SqliteInventoryRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class InventoryPipelineIT {
    @TempDir Path temp;
    @Test void adbApplicationSqliteRoundTripAndDeletion() {
        var adapter = new AdbDeviceInspector("adb", (args, timeout) -> {
            if (args.contains("devices")) return "List of devices attached\nabc device model:Test_Device\n";
            return args.getLast().equals("-s") ? "package:android\n" : "package:android\npackage:com.example.app\n";
        });
        var service = new DeviceScanService(adapter, Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        var repository = new SqliteInventoryRepository(temp.resolve("data/inventory.db"));
        assertTrue(repository.recent(10).isEmpty());
        assertFalse(Files.exists(temp.resolve("data")), "Reading absent history must not create storage");
        var inventory = service.scan("abc", true); repository.save(inventory);
        var reopened = new SqliteInventoryRepository(temp.resolve("data/inventory.db"));
        assertEquals(List.of(inventory), reopened.recent(10));
        reopened.deleteAll(); assertTrue(reopened.recent(10).isEmpty());
    }
    @Test void failedAppInsertRollsBackEntireSnapshot() {
        var repository = new SqliteInventoryRepository(temp.resolve("inventory.db"));
        var duplicate = new InstalledApp("com.example.app", false);
        var inventory = new Inventory(UUID.randomUUID(), Instant.now(), new Device("abc", Device.State.AUTHORIZED, "Test"), List.of(duplicate, duplicate));
        assertThrows(ScanException.class, () -> repository.save(inventory));
        assertTrue(repository.recent(10).isEmpty(), "No orphan scan after rollback");
    }
    @Test void storesTextAsDataRatherThanSqlAndOrdersSnapshots() {
        var repository = new SqliteInventoryRepository(temp.resolve("inventory.db"));
        var device = new Device("abc", Device.State.AUTHORIZED, "Model'); DROP TABLE apps; --");
        var first = new Inventory(UUID.randomUUID(), Instant.parse("2026-01-01T00:00:00Z"), device, List.of(new InstalledApp("android", true)));
        var second = new Inventory(UUID.randomUUID(), Instant.parse("2026-02-01T00:00:00Z"), device, List.of());
        repository.save(first); repository.save(second);
        assertEquals(List.of(second, first), repository.recent(10));
        assertEquals(List.of(second), repository.recent(1));
    }
}
