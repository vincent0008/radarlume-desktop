package io.radarlume.adb;
import io.radarlume.domain.*;
import io.radarlume.process.CommandRunner;
import java.time.*;
import java.util.*;
public final class AdbSecurityEvidenceCollector implements SecurityEvidenceCollector {
    private final String executable;
    private final CommandRunner runner;
    private final Clock clock;
    public AdbSecurityEvidenceCollector(String executable, CommandRunner runner, Clock clock) {
        this.executable=executable; this.runner=runner; this.clock=clock;
    }
    public List<Evidence> collect(String serial) {
        if(serial==null || !serial.matches("[A-Za-z0-9][A-Za-z0-9._:\\[\\]%-]{0,255}")) throw new ScanException("Seriale non valido.");
        var result=new ArrayList<Evidence>();
        read(result,serial,"android_version",List.of("getprop","ro.build.version.release"));
        read(result,serial,"sdk",List.of("getprop","ro.build.version.sdk"));
        read(result,serial,"security_patch",List.of("getprop","ro.build.version.security_patch"));
        read(result,serial,"accessibility",List.of("settings","get","secure","enabled_accessibility_services"));
        return List.copyOf(result);
    }
    private void read(List<Evidence> result,String serial,String key,List<String> remote) {
        if(Thread.currentThread().isInterrupted()) throw new ScanException("Analisi annullata.");
        var args=new ArrayList<>(List.of(executable,"-s",serial,"shell")); args.addAll(remote);
        String value=""; Evidence.Status state=Evidence.Status.UNAVAILABLE;
        try {
            value=runner.run(args,Duration.ofSeconds(15)).strip();
            boolean valid = !value.isBlank() && !value.contains("\n") && !value.toLowerCase(Locale.ROOT).contains("exception")
                && !value.toLowerCase(Locale.ROOT).startsWith("error") && value.length()<8192;
            if(key.equals("sdk")) valid &= value.matches("[0-9]+");
            if(key.equals("accessibility")) valid &= value.equals("null") || value.matches("[A-Za-z0-9_.$/:-]+") && value.contains("/");
            if(valid) state=Evidence.Status.AVAILABLE; else value="";
        } catch(ScanException ex) {
            if(Thread.currentThread().isInterrupted()) throw ex;
        }
        result.add(new Evidence(key,value,"adb shell "+String.join(" ",remote),Instant.now(clock),state));
    }
}
