package io.radarlume.application;
import io.radarlume.domain.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
public final class AndroidAssessmentService {
    public record Assessment(String serial, List<Evidence> evidence, List<Finding> findings) {
        public Assessment { evidence = List.copyOf(evidence); findings = List.copyOf(findings); }
    }
    private final DeviceInspector inspector;
    private final SecurityEvidenceCollector collector;
    private final Clock clock;
    public AndroidAssessmentService(DeviceInspector inspector, SecurityEvidenceCollector collector, Clock clock) {
        this.inspector=inspector; this.collector=collector; this.clock=clock;
    }
    public Assessment assess(String serial, boolean consent) {
        if (!consent) throw new ScanException("Autorizzazione richiesta.");
        if (inspector.discover().stream().noneMatch(d -> d.serial().equals(serial) && d.state()==Device.State.AUTHORIZED))
            throw new ScanException("Dispositivo non disponibile o non autorizzato.");
        var evidence=collector.collect(serial);
        return new Assessment(serial, evidence, evaluate(evidence, LocalDate.now(clock)));
    }
    public static List<Finding> evaluate(List<Evidence> evidence, LocalDate today) {
        var findings=new ArrayList<Finding>();
        for (var e:evidence) {
            if(e.status()!=Evidence.Status.AVAILABLE) {
                findings.add(new Finding("DATA-001","1",Finding.Severity.INFO,Finding.Confidence.HIGH,e.key(),
                    "Dato non acquisito: valutazione incompleta.", "Verificare accesso e compatibilità Android; non dedurre assenza di rischio."));
                continue;
            }
            if(e.key().equals("security_patch")) {
                try {
                    LocalDate patch=LocalDate.parse(e.value());
                    if(patch.isAfter(today)) throw new IllegalArgumentException();
                    if(ChronoUnit.DAYS.between(patch,today)>180)
                        findings.add(new Finding("AND-001","1",Finding.Severity.MEDIUM,Finding.Confidence.HIGH,e.key(),
                            "Livello patch dichiarato più vecchio di 180 giorni. Soglia euristica, non prova di infezione.",
                            "Verificare aggiornamenti e supporto del produttore."));
                } catch (RuntimeException ex) {
                    findings.add(new Finding("DATA-002","1",Finding.Severity.INFO,Finding.Confidence.HIGH,e.key(),
                        "Data patch non interpretabile o futura.", "Controllare data del PC e valore restituito dal dispositivo."));
                }
            }
            if(e.key().equals("accessibility") && !e.value().equals("null") && !e.value().isBlank())
                findings.add(new Finding("AND-002","1",Finding.Severity.INFO,Finding.Confidence.LOW,e.key(),
                    "Servizi di accessibilità configurati. Possono essere legittimi; non dimostrano controllo abusivo.",
                    "Confrontare i componenti con le app e con le funzioni consapevolmente abilitate dal proprietario."));
        }
        return List.copyOf(findings);
    }
}
