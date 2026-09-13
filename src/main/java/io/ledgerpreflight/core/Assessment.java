package io.ledgerpreflight.core;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.*;
import java.security.*;
import java.nio.charset.StandardCharsets;
public record Assessment(String schemaVersion, String productVersion, String status,
    String sourceVersion, String targetVersion, List<Finding> findings, Map<String,Object> evidence,
    String assessmentId,String timestamp) {
    public Assessment(String schemaVersion,String productVersion,String status,String sourceVersion,String targetVersion,List<Finding> findings,Map<String,Object> evidence){this(schemaVersion,productVersion,status,sourceVersion,targetVersion,findings,evidence,id(findings,sourceVersion,targetVersion,evidence),Instant.now().toString());}
    public Assessment { findings=findings.stream().sorted().toList(); evidence=Collections.unmodifiableMap(new TreeMap<>(evidence)); }
    @JsonProperty public String ledgerPreflightVersion(){return productVersion;}
    @JsonProperty public Object currentNode(){return evidence.getOrDefault("environment",Map.of());}
    @JsonProperty public Object upgradeKit(){return evidence.getOrDefault("upgrade-kit",List.of());}
    @JsonProperty public Object artifacts(){return Map.of("current",currentNode(),"target",upgradeKit());}
    @JsonProperty public Map<String,String> hashes(){return inventoryHashes(evidence);}
    private static Map<String,String> inventoryHashes(Map<String,Object> evidence){Map<String,String> hashes=new TreeMap<>();Object target=evidence.get("upgrade-kit");if(target instanceof List<?> jars)for(Object jar:jars)if(jar instanceof Discovery.Artifact a)hashes.put("target/"+a.path(),a.sha256());Object env=evidence.get("environment");if(env instanceof Map<?,?> m && m.get("current") instanceof List<?> jars)for(Object jar:jars)if(jar instanceof Discovery.Artifact a)hashes.put("current/"+a.path(),a.sha256());return Collections.unmodifiableMap(hashes);}
    @JsonProperty public Object gates(){return Map.of("static",findings.stream().filter(f->!f.category().equals("TVU")&&!f.id().equals("LP-DB-003")).noneMatch(f->Set.of("BLOCKED","UNKNOWN","WARNING","ERROR").contains(f.severity()))?"PASS":"REVIEW_REQUIRED","tvu",evidence.get("tvu-summary") instanceof io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence t && t.completeSuccess() && completedGuidedRun()?"PASS":"REQUIRED_OR_UNRESOLVED");}
    private boolean completedGuidedRun() {
        Object value=evidence.get("tvu-run");
        if(value==null)return true;
        if(!(value instanceof Map<?,?> run))return false;
        return "NONE".equals(run.get("failureKind"))
            && run.get("exitCode") instanceof Number code && code.intValue()==0
            && !Boolean.TRUE.equals(run.get("cancelled"))
            && Boolean.TRUE.equals(run.get("workspaceCleaned"))
            && !Boolean.TRUE.equals(run.get("manifestWriteFailure"));
    }
    private static String id(List<Finding> findings,String source,String target,Map<String,Object> evidence){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((source+"|"+target+"|"+inventoryHashes(evidence)+"|"+findings.stream().sorted().toList()).getBytes(StandardCharsets.UTF_8))).substring(0,24);}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
    public static String readiness(List<Finding> findings, boolean tvuSuccess, boolean tvuSupplied) {
        if(findings.stream().anyMatch(f->f.severity().equals("BLOCKED") || f.severity().equals("ERROR")))return "BLOCKED";
        if(findings.stream().anyMatch(f->f.severity().equals("UNKNOWN")))return "UNKNOWN";
        if(findings.stream().anyMatch(f->f.severity().equals("WARNING")))return "WARNING";
        if(tvuSuccess)return "READY TO UPGRADE";
        return tvuSupplied?"UNKNOWN":"READY FOR TVU";
    }
    public int exitCode() { return switch(status) {case "BLOCKED"->2;case "UNKNOWN"->4;case "WARNING","READY FOR TVU"->1;default->0;}; }
}
