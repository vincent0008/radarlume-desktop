package io.radarlume.adb;
import io.radarlume.domain.*;
import java.time.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class EvidenceCollectorTest {
    @Test void preservesUnavailableFieldsAndUsesExplicitSerial() {
        var collector=new AdbSecurityEvidenceCollector("adb",(args,timeout)->{
            assertEquals("serial",args.get(2));
            return switch(args.getLast()) {
                case "ro.build.version.release" -> "14\n";
                case "ro.build.version.sdk" -> "34\n";
                case "ro.build.version.security_patch" -> throw new ScanException("unsupported");
                default -> "SecurityException: denied";
            };
        },Clock.systemUTC());
        var evidence=collector.collect("serial");
        assertEquals(4,evidence.size());assertEquals("14",evidence.getFirst().value());
        assertEquals(Evidence.Status.UNAVAILABLE,evidence.get(2).status());
        assertEquals(Evidence.Status.UNAVAILABLE,evidence.get(3).status());
        assertThrows(ScanException.class,()->collector.collect("x;reboot"));
    }
}
