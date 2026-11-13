package io.radarlume.adb;

import io.radarlume.domain.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class AdbTest {
    @Test void parsesStatesWithoutTreatingUnauthorizedAsAuthorized() {
        var devices = AdbParser.devices("List of devices attached\r\nabc device product:p model:Pixel_8 transport_id:1\r\ndef unauthorized\r\nghi offline\r\njkl no permissions (udev rules)\r\n");
        assertEquals(List.of(Device.State.AUTHORIZED, Device.State.UNAUTHORIZED, Device.State.OFFLINE, Device.State.NO_PERMISSIONS), devices.stream().map(Device::state).toList());
        assertEquals("Pixel 8", devices.getFirst().model());
        assertTrue(AdbParser.devices("List of devices attached\n\n").isEmpty());
    }
    @Test void rejectsMalformedOutputAndRemoteErrorEvenWithSuccessfulExit() {
        assertThrows(ScanException.class, () -> AdbParser.devices("connection refused"));
        assertThrows(ScanException.class, () -> AdbParser.packages("Error: SecurityException"));
        assertThrows(ScanException.class, () -> AdbParser.packages("package:com.test;reboot"));
    }
    @Test void deduplicatesPackagesAndAllowsAndroidPackage() {
        assertEquals(Set.of("android", "com.example.app"), AdbParser.packages("package:android\npackage:com.example.app\npackage:android\n"));
    }
    @Test void selectsSerialAndClassifiesSystemPackages() {
        List<List<String>> commands = new ArrayList<>();
        var adapter = new AdbDeviceInspector("C:\\Android SDK\\adb.exe", (args, timeout) -> {
            commands.add(args);
            return args.getLast().equals("-s") ? "package:android\n" : "package:android\npackage:com.example.app\n";
        });
        var apps = adapter.inventory("ABC123");
        assertEquals(List.of(new InstalledApp("android", true), new InstalledApp("com.example.app", false)), apps);
        assertEquals(List.of("C:\\Android SDK\\adb.exe", "-s", "ABC123", "shell", "pm", "list", "packages"), commands.getFirst());
        assertThrows(ScanException.class, () -> adapter.inventory("abc;reboot"));
        assertEquals(2, commands.size());
    }
    @Test void emptyInventoryIsNotReportedAsSuccess() {
        var adapter = new AdbDeviceInspector("adb", (args, timeout) -> "");
        assertThrows(ScanException.class, () -> adapter.inventory("ABC123"));
    }
}
