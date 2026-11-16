package io.radarlume.application;

import io.radarlume.domain.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UnpinningPlanServiceTest {

    @Test void fridaPlanCarriesAParameterizedScriptAndSpawnCommand() {
        var plan = UnpinningPlanService.plan("com.example.app", UnpinningTechnique.FRIDA, "adb");
        assertTrue(plan.hasScript());
        assertTrue(plan.scriptContent().contains("com.example.app"), "lo script deve citare il pacchetto");
        assertTrue(plan.scriptContent().contains("CertificatePinner"));
        assertTrue(plan.steps().stream().anyMatch(s ->
                s.command().contains("frida -U -f com.example.app") && s.command().contains(plan.scriptFileName())));
    }

    @Test void repackagingPlanHasNoScriptAndPullsTheApk() {
        var plan = UnpinningPlanService.plan("com.suspect.pkg", UnpinningTechnique.APK_MITM, "adb");
        assertFalse(plan.hasScript());
        assertTrue(plan.steps().stream().anyMatch(s -> s.command().contains("pm path com.suspect.pkg")));
    }

    @Test void everyPlanStatesVerificationViaData007AndSafety() {
        for (var technique : UnpinningTechnique.values()) {
            var plan = UnpinningPlanService.plan("com.example.app", technique, "adb");
            assertFalse(plan.safety().isEmpty());
            assertTrue(plan.verification().stream().anyMatch(v -> v.contains("DATA-007")), technique + " deve rimandare a DATA-007");
            assertFalse(plan.limits().isEmpty(), technique + " deve dichiarare i limiti");
        }
    }

    @Test void adbPathWithSpacesIsQuotedInCommands() {
        var plan = UnpinningPlanService.plan("com.example.app", UnpinningTechnique.APK_MITM, "C:\\Android SDK\\adb.exe");
        assertTrue(plan.steps().stream().anyMatch(s -> s.command().contains("\"C:\\Android SDK\\adb.exe\"")));
    }

    @Test void rejectsInvalidPackageName() {
        assertThrows(IllegalArgumentException.class, () -> UnpinningPlanService.plan("com.evil; rm -rf /", UnpinningTechnique.FRIDA, "adb"));
        assertThrows(IllegalArgumentException.class, () -> UnpinningPlanService.plan("", UnpinningTechnique.FRIDA, "adb"));
        assertThrows(IllegalArgumentException.class, () -> UnpinningPlanService.plan(null, UnpinningTechnique.FRIDA, "adb"));
    }
}
