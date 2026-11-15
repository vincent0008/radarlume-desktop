package io.radarlume.domain;
public record Finding(String ruleId, String ruleVersion, Severity severity, Confidence confidence,
                      String evidenceKey, String explanation, String nextStep) {
    public enum Severity { INFO, MEDIUM }
    public enum Confidence { LOW, HIGH }
}
