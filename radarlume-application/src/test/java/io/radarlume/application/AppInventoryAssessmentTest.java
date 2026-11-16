package io.radarlume.application;

import io.radarlume.domain.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AppInventoryAssessmentTest {

    private static InstalledApp app(String pkg, boolean system, String installer, List<String> granted) {
        return new InstalledApp(pkg, system, new AppMetadata("1.0", 1L, installer, granted, granted));
    }

    private static List<String> rules(List<Finding> findings) { return findings.stream().map(Finding::ruleId).toList(); }

    @Test void flagsUnknownOriginAndSensitivePermissionsButNotSystemOrStoreApps() {
        var findings = AppInventoryAssessmentService.evaluate(List.of(
                app("com.store.app", false, "com.android.vending", List.of("android.permission.CAMERA")),
                app("com.side.app", false, "", List.of("android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION")),
                app("com.android.system", true, "", List.of("android.permission.READ_SMS", "android.permission.RECORD_AUDIO"))),
                "SERIAL1");
        assertEquals(List.of("AND-003", "AND-004"), rules(findings));
        Finding origin = findings.get(0), perms = findings.get(1);
        assertTrue(origin.explanation().contains("com.side.app"));
        assertFalse(origin.explanation().contains("com.store.app"), "app da store noto non va segnalata");
        assertFalse(origin.explanation().contains("com.android.system"), "app di sistema non va segnalata");
        assertTrue(perms.explanation().contains("com.side.app"));
        assertFalse(perms.explanation().contains("com.store.app"), "una sola categoria sensibile è sotto soglia");
        assertEquals(Finding.Severity.INFO, perms.severity());
        assertEquals(Finding.Confidence.LOW, perms.confidence());
    }

    @Test void reportsMissingMetadataAndSkipsOtherRules() {
        var findings = AppInventoryAssessmentService.evaluate(List.of(
                new InstalledApp("com.side.app", false),
                new InstalledApp("com.android.system", true)),
                "SERIAL1");
        assertEquals(List.of("DATA-008"), rules(findings));
    }

    @Test void noFindingsWhenEverythingIsFromAStoreWithFewPermissions() {
        var findings = AppInventoryAssessmentService.evaluate(List.of(
                app("com.a", false, "com.android.vending", List.of("android.permission.CAMERA")),
                app("com.b", false, "org.fdroid.fdroid", List.of())),
                "SERIAL1");
        assertTrue(findings.isEmpty());
    }
}
