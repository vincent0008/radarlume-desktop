package io.radarlume.domain;

import java.util.List;

/**
 * Piano guidato per rendere leggibile il traffico TLS di un'app sospetta. RadarLume non esegue nulla sul
 * dispositivo: genera lo script, i comandi, la verifica e i limiti, che l'operatore applica su un dispositivo
 * di test. La verifica si chiude in RadarLume stesso: dopo l'intervento si ripete la cattura e si guarda
 * DATA-007, che conta quante connessioni TLS sono diventate leggibili.
 */
public record UnpinningPlan(String packageName, UnpinningTechnique technique, List<String> prerequisites,
                            List<Step> steps, String scriptFileName, String scriptContent,
                            List<String> verification, List<String> limits, List<String> safety) {

    /** Un passo del piano: cosa fare e, quando c'è, il comando da copiare. */
    public record Step(String title, String detail, String command) {
        public Step(String title, String detail) { this(title, detail, ""); }
        public boolean hasCommand() { return command != null && !command.isBlank(); }
    }

    public UnpinningPlan {
        prerequisites = List.copyOf(prerequisites);
        steps = List.copyOf(steps);
        verification = List.copyOf(verification);
        limits = List.copyOf(limits);
        safety = List.copyOf(safety);
        scriptContent = scriptContent == null ? "" : scriptContent;
        scriptFileName = scriptFileName == null ? "" : scriptFileName;
    }

    public boolean hasScript() { return !scriptFileName.isBlank() && !scriptContent.isBlank(); }
}
