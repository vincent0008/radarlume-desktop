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
        assertEquals(List.of("C:\\Android SDK\\adb.exe", "-s", "ABC123", "shell", "dumpsys", "package"), commands.getLast());
        assertThrows(ScanException.class, () -> adapter.inventory("abc;reboot"));
        assertEquals(3, commands.size());
    }
    @Test void inventoryStaysValidWhenMetadataCollectionFails() {
        var adapter = new AdbDeviceInspector("adb", (args, timeout) -> {
            if (args.getLast().equals("package")) throw new ScanException("dumpsys non disponibile");
            return args.getLast().equals("-s") ? "" : "package:com.example.app\n";
        });
        var apps = adapter.inventory("ABC123");
        assertEquals(List.of(new InstalledApp("com.example.app", false)), apps);
        assertEquals(AppMetadata.UNKNOWN, apps.getFirst().metadata());
    }
    @Test void parsesVersionOriginAndPermissionsAndStopsAtHiddenPackages() {
        String dumpsys = """
            Packages:
              Package [com.example.app] (abc123):
                userId=10194
                versionCode=45 minSdk=23 targetSdk=33
                versionName=4.5.0
                installerPackageName=com.android.vending
                requested permissions:
                  android.permission.INTERNET
                  android.permission.ACCESS_FINE_LOCATION
                  android.permission.CAMERA
                install permissions:
                  android.permission.INTERNET: granted=true
                User 0:
                  gids=[3003]
                  runtime permissions:
                    android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET ]
                    android.permission.CAMERA: granted=false
              Package [com.side.loaded] (def456):
                versionName=1.0
                installerPackageName=null
                requested permissions:
                  android.permission.READ_SMS
                install permissions:
                  android.permission.READ_SMS: granted=true
            Hidden system packages:
              Package [com.example.app] (ghost):
                versionName=0.0.0
            """;
        var map = AdbParser.appMetadata(dumpsys);
        assertEquals(2, map.size());
        var app = map.get("com.example.app");
        assertEquals("4.5.0", app.versionName());
        assertEquals(45L, app.versionCode());
        assertEquals("com.android.vending", app.installer());
        assertTrue(app.requestedPermissions().contains("android.permission.CAMERA"));
        assertTrue(app.hasGranted("ACCESS_FINE_LOCATION"));
        assertFalse(app.hasGranted("CAMERA"));
        assertEquals("", map.get("com.side.loaded").installer());
        assertTrue(map.get("com.side.loaded").hasGranted("READ_SMS"));
    }
    @Test void unrecognizedDumpsysYieldsEmptyMetadataWithoutThrowing() {
        assertTrue(AdbParser.appMetadata("error: device offline").isEmpty());
    }
    @Test void emptyInventoryIsNotReportedAsSuccess() {
        var adapter = new AdbDeviceInspector("adb", (args, timeout) -> "");
        assertThrows(ScanException.class, () -> adapter.inventory("ABC123"));
    }
}
