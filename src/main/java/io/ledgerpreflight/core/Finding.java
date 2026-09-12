package io.ledgerpreflight.core;

import java.util.List;

public record Finding(String id, String title, String severity, String category,
        String status, String confidence, String source, String affectedArtifact,
        List<String> technicalEvidence, String impact, String explanation,
        String recommendedNextAction, String documentationReference) implements Comparable<Finding> {
    public Finding { technicalEvidence = List.copyOf(technicalEvidence); }
    public static Finding of(String id, String title, String severity, String category,
            String confidence, String source, String artifact, List<String> evidence, String impact, String next) {
        return new Finding(id,title,severity,category,severity,confidence,source,artifact,evidence,impact,title,next,"");
    }
    @Override public int compareTo(Finding other) {
        int a = rank(severity)-rank(other.severity);
        if(a!=0) return a;
        a=id.compareTo(other.id); if(a!=0)return a;
        a=affectedArtifact.compareTo(other.affectedArtifact); if(a!=0)return a;
        return technicalEvidence.toString().compareTo(other.technicalEvidence.toString());
    }
    private static int rank(String s) { return switch(s) {case "BLOCKED","ERROR"->0;case "UNKNOWN"->1;case "WARNING"->2;default->3;}; }
}
