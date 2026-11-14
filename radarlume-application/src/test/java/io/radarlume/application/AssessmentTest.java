package io.radarlume.application;
import io.radarlume.domain.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AssessmentTest {
    private Evidence evidence(String key,String value,Evidence.Status status) { return new Evidence(key,value,"fixture",Instant.EPOCH,status); }
    @Test void distinguishesMissingOldAndFuturePatch() {
        LocalDate today=LocalDate.of(2026,11,14);
        for(String date:List.of("invalid","2027-01-01"))
            assertEquals("DATA-002",AndroidAssessmentService.evaluate(List.of(evidence("security_patch",date,Evidence.Status.AVAILABLE)),today).getFirst().ruleId());
        assertEquals("AND-001",AndroidAssessmentService.evaluate(List.of(evidence("security_patch","2020-01-01",Evidence.Status.AVAILABLE)),today).getFirst().ruleId());
        assertEquals("DATA-001",AndroidAssessmentService.evaluate(List.of(evidence("security_patch","",Evidence.Status.UNAVAILABLE)),today).getFirst().ruleId());
        assertTrue(AndroidAssessmentService.evaluate(List.of(evidence("security_patch",today.minusDays(180).toString(),Evidence.Status.AVAILABLE)),today).isEmpty());
    }
    @Test void accessibilityIsContextNotMalwareVerdict() {
        var findings=AndroidAssessmentService.evaluate(List.of(evidence("accessibility","com.example/.Reader",Evidence.Status.AVAILABLE)),LocalDate.now());
        assertEquals(Finding.Severity.INFO,findings.getFirst().severity());
        assertEquals(Finding.Confidence.LOW,findings.getFirst().confidence());
        assertTrue(AndroidAssessmentService.evaluate(List.of(evidence("accessibility","null",Evidence.Status.AVAILABLE)),LocalDate.now()).isEmpty());
    }
    @Test void deniesAccessWithoutConsent() {
        var service=new AndroidAssessmentService(null,null,Clock.systemUTC());
        assertThrows(ScanException.class,()->service.assess("test",false));
    }
}
