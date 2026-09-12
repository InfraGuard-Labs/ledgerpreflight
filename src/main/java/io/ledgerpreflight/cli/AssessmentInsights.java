package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.reporting.Reports;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;

/** Explanations and comparisons retain evidence identity, rather than comparing rule IDs alone. */
public final class AssessmentInsights {
    private AssessmentInsights(){}
    public static List<Finding> blockers(Assessment a){return a.findings().stream().filter(f->Set.of("BLOCKED","ERROR").contains(f.severity())).toList();}
    public static String summary(Assessment a) {
        if(a.status().equals("READY FOR TVU"))return "✓ STATIC PREFLIGHT PASSED\nSTATUS: READY FOR TVU\n\nStatic compatibility    PASS\nTVU validation          REQUIRED\n\nREMAINING GATE\nComplete TVU validation before proceeding.\n";
        if(a.status().equals("READY TO UPGRADE")){
            JsonNode tvu=Reports.JSON.valueToTree(a.evidence().get("tvu-summary"));
            return "✓ READY TO UPGRADE\n\nStatic checks    PASS\nTVU validation   PASS\n"+(tvu.path("completeSuccess").asBoolean()?"Historical transactions  "+tvu.path("succeeded").asLong()+" / "+tvu.path("processed").asLong()+"\n":"")+"\nNo upgrade blockers remain.\n\nNEXT\nContinue with the official R3 upgrade procedure and your normal change-management process.\n";
        }
        long warnings=a.findings().stream().filter(f->f.severity().equals("WARNING")).count();
        String marker=switch(a.status()){case "BLOCKED"->"✕";case "WARNING"->"!";case "READY TO UPGRADE"->"✓";default->"?";};
        StringBuilder s=new StringBuilder(marker+" "+a.status()+"\n"+blockers(a).size()+" blockers · "+warnings+" warnings\n");
        var priority=a.findings().stream().filter(f->Set.of("BLOCKED","ERROR","UNKNOWN").contains(f.severity())).limit(2).toList();
        long shownBlockers=priority.stream().filter(f->!f.severity().equals("UNKNOWN")).count(),shownWarnings=Math.min(1,warnings);
        if(blockers(a).size()>shownBlockers||warnings>shownWarnings)s.append("Showing ").append(shownBlockers).append(" of ").append(blockers(a).size()).append(" blockers · ").append(shownWarnings).append(" of ").append(warnings).append(" warnings\n");
        if(!priority.isEmpty())s.append(blockers(a).isEmpty()?"\nEVIDENCE TO RESOLVE\n":"\nWHAT STOPS THIS UPGRADE\n");
        for(Finding f:priority)s.append("\n").append(f.severity().equals("UNKNOWN")?"? ":"✕ ").append(Reports.findingSummary(f).replaceFirst("^LP-[A-Z0-9-]+ · ","")).append('\n');
        a.findings().stream().filter(f->f.severity().equals("WARNING")).sorted(Comparator.comparing(f->!f.id().equals("LP-DB-001"))).findFirst().ifPresent(f->s.append("\n! ").append(f.id().equals("LP-DB-001")?"Mixed-case PostgreSQL schema\nTVU schema handling requires validation.":Reports.findingSummary(f).replaceFirst("^LP-[A-Z0-9-]+ · ","")).append('\n'));
        if(blockers(a).size()>shownBlockers||warnings>shownWarnings)s.append("\n").append(blockers(a).size()-shownBlockers).append(" additional blockers and ").append(warnings-shownWarnings).append(" additional warnings are available in full findings.\n");
        if(priority.isEmpty())s.append("\nReview assessment concerns before completing TVU validation.\n");
        return s.toString();
    }
    public static String technicalEvidence(Finding f) {
        Map<String,String> fields=new LinkedHashMap<>();
        for(String signal:f.technicalEvidence()){int colon=signal.indexOf(": ");if(colon>0)fields.put(signal.substring(0,colon),signal.substring(colon+2));}
        StringBuilder s=new StringBuilder("TECHNICAL EVIDENCE\n"+f.id()+"\n\nArtifact: "+fields.getOrDefault("jar",f.affectedArtifact())+"\n");
        String[][] labels={{"class",f.category().equals("LEGACY_JARS")?"Duplicate class":"Calling class"},{"sourceMethod","Calling method"},{"owner","Runtime class"},{"member","Required member"},{"descriptor","JVM descriptor"},{"targetJar","Target runtime"},{"targetClass","Target class"},{"requiredMember","Required member result"},{"runtimeJar","Runtime JAR"},{"legacyJar","Legacy JAR"},{"legacyOnlyMembers","Members supplied only by shim"},{"classpathOrder","Classpath order"}};
        Set<String> shown=new HashSet<>(Set.of("jar"));
        for(String[] label:labels)if(fields.containsKey(label[0])){s.append(label[1]).append(": ").append(fields.get(label[0])).append('\n');shown.add(label[0]);}
        for(String signal:f.technicalEvidence()){int colon=signal.indexOf(": ");if(colon<1)s.append("• ").append(signal).append('\n');else if(!shown.contains(signal.substring(0,colon)))s.append(signal.substring(0,colon).replaceAll("([a-z])([A-Z])","$1 $2")).append(signal.substring(colon)).append('\n');}
        return s+"\nEvidence source: "+f.source().replace('_',' ').toLowerCase(Locale.ROOT)+"\nConfidence: "+f.confidence()+"\n";
    }
    public static String header(Assessment a) {
        JsonNode env=Reports.JSON.valueToTree(a.evidence().get("environment")),host=env.path("host"),cfg=Reports.JSON.valueToTree(a.evidence().get("schema-analysis"));
        String os=host.path("sourceHostOs").asText("UNKNOWN");if(os.equals("UNKNOWN"))os=host.path("executionOs").asText("OS not established");
        os=os.replaceAll("(Ubuntu \\d+\\.\\d+)\\.\\d+ LTS","$1");
        String db=cfg.path("safeSettings").path("databaseVendor").asText("Database not established");if(db.equals("postgresql"))db="PostgreSQL";
        String legal=cfg.path("safeSettings").path("myLegalName").asText("");
        return "LedgerPreflight "+a.productVersion()+"\n────────────────────────────────────────\n\n"+env.path("nodeName").asText("Node not established")+
            (legal.isEmpty()?"":"\n"+legal)+"\n"+a.sourceVersion()+" → "+a.targetVersion()+"\n\n"+os+" · "+db+
            "\nSchema: "+cfg.path("safeSettings").path("effectiveSchema").asText("Not established")+(cfg.path("safeSettings").path("effectiveSchema").asText().equals("Unknown")?" ("+cfg.path("safeSettings").path("schemaExplanation").asText("Evidence not established")+")":"")+
            "\nCorDapp artifacts: "+Reports.JSON.valueToTree(a.evidence().get("cordapps-current")).size()+" current → "+Reports.JSON.valueToTree(a.evidence().get("cordapps-target")).size()+" target\nTVU: "+tvuState(a)+"\n";
    }
    private static String tvuState(Assessment a){JsonNode tvu=Reports.JSON.valueToTree(a.evidence().get("tvu-summary"));return tvu.path("completeSuccess").asBoolean()?"Passed":tvu.path("failed").asLong(0)>0?"Failed":"Not completed";}
    public static String tvuReadiness(Assessment a) {
        return tvuReadiness(a,null);
    }
    public static String tvuReadiness(Assessment a,java.nio.file.Path explicitTvu) {
        JsonNode gates=Reports.JSON.valueToTree(a.gates()),host=Reports.JSON.valueToTree(a.evidence().get("environment")).path("host");
        boolean tvu=explicitTvu!=null && java.nio.file.Files.isRegularFile(explicitTvu,java.nio.file.LinkOption.NOFOLLOW_LINKS);for(JsonNode artifact:Reports.JSON.valueToTree(a.evidence().get("upgrade-kit")))if(artifact.path("role").asText().equals("TVU"))tvu=true;
        StringBuilder s=new StringBuilder("TVU READINESS\n\nStatic preflight: "+(gates.path("static").asText().equals("PASS")?"Passed":"Review required")+"\nTarget TVU: "+(tvu?"Found for "+a.targetVersion():"Not found in kit; check explicit override")+"\nTarget CorDapps: "+Reports.JSON.valueToTree(a.evidence().get("cordapps-target")).size()+" found\n");
        boolean legacyConcern=a.findings().stream().anyMatch(f->f.category().equals("LEGACY_JARS")&&!f.severity().equals("INFO"));
        s.append("Legacy dependencies: ").append(legacyConcern?"Review required — class shadowing or duplication":"No static conflict found; confirm complete historical dependencies").append("\nCurrent Java: ").append(host.path("currentJava").asText("Not established")).append("\nTarget Java requirement: ").append(host.path("targetRequiredJava").asText("Not established")).append("\nTarget Java preparation: ").append(host.path("targetJavaReadiness").asText().equals("USER_REPORTED_COMPATIBLE")?"Reported compatible; verify on validation copy":"Not independently confirmed").append("\nTVU result: ").append(tvuState(a)).append("\n\nBEFORE RUNNING\n");
        var concerns=a.findings().stream().filter(f->!f.severity().equals("INFO")).limit(5).toList();
        for(Finding f:concerns)s.append("• ").append(Reports.findingSummary(f)).append('\n');
        if(concerns.isEmpty())s.append("No static preparation concerns found.\n");
        return s+"\nUse an isolated node/database copy with the assessed target artifacts.\nThis check does not execute TVU or modify a database.\n";
    }
    public static String explanation(Finding f) {
        String changed,why;
        String member=f.technicalEvidence().stream().filter(e->e.startsWith("member: ")).map(e->e.substring(8)).findFirst().orElse("the required member");
        String owner=f.technicalEvidence().stream().filter(e->e.startsWith("owner: ")).map(e->e.substring(7)).findFirst().orElse("the runtime class");owner=owner.substring(owner.lastIndexOf('/')+1);
        switch(f.category()) {
            case "API_COMPATIBILITY", "INTERNAL_API" -> {changed="The supplied target class/member inventory differs from the requirements recorded in the CorDapp bytecode.";why="JVM linkage uses owner, member name, descriptor and invocation kind. A similarly named method or different overload cannot satisfy the recorded call. This is static linkage evidence, not proof that every transaction reaches the call.";}
            case "LEGACY_JARS" -> {changed="The prepared verifier classpath contains competing definitions of the same class.";why="The classloader selects one complete definition; it does not merge methods from different JARs. A later shim cannot add a missing method to an already selected class. Review the supplied precedence evidence before changing the classpath.";}
            case "DATABASE_SCHEMA" -> {changed="Configuration or TVU evidence indicates schema resolution needs review; this does not establish a vendor patch defect.";why="PostgreSQL quoting, search_path and Hibernate defaults can select different schemas. Normal node startup does not establish that TVU resolves the same tables. Validate on a database copy.";}
            case "TVU" -> {changed="The supplied validation evidence has not established successful processing of the complete transaction set.";why="Static checks cannot verify all historical ledger attachments. Failed, missing or inconsistent TVU evidence prevents final readiness. A few detailed records cannot explain all failures in a summary.";}
            default -> {changed="The current preparation does not satisfy the evidence requirement identified by "+f.id()+"; no unsupported release-specific change is inferred.";why=f.impact()+". "+f.recommendedNextAction();}
        }
        if(f.id().equals("LP-API-001")&&f.technicalEvidence().contains("requiredMember: absent")){
            changed=owner+" is present in the target, but "+member+" is not available in the required form"+(f.severity().equals("BLOCKED")?".":" in the supplied classes. Some ancestry is missing, so removal is not yet proven.");
            why="Historical contract bytecode calls "+owner+"."+member+". The JVM must find the exact method that call expects; a different overload or later compatibility JAR cannot substitute for it. Verification can fail when that code is reached.";
        }else if(f.id().equals("LP-API-001")){changed="The method exists, but its static/instance calling convention differs from the CorDapp's call.";why="An instance call and a static call are different JVM operations. Matching names and parameter types alone cannot make this call compatible.";}
        if(f.category().equals("INTERNAL_API")){changed="The CorDapp uses an internal Corda API. This finding alone does not prove the API changed or was removed.";why="Internal APIs do not have normal stability guarantees. Verify the exact target runtime and historical transactions before relying on this call.";}
        return "WHAT LEDGERPREFLIGHT FOUND\n"+Reports.findingSummary(f)+"\n\nWHAT CHANGED\n"+changed+
            "\n\nWHY THIS FAILS\n"+why+"\n\nIMPACT\n"+f.impact()+
            "\n\nEVIDENCE\n"+f.source()+" · "+f.confidence()+" confidence · "+f.technicalEvidence().size()+" evidence signals; open technical evidence for exact details."+
            "\n\nRECOMMENDED NEXT ACTION\n"+f.recommendedNextAction();
    }
    public static String plan(Assessment a) {
        Set<String> categories=new HashSet<>();a.findings().stream().filter(f->!f.severity().equals("INFO")).forEach(f->categories.add(f.category()));
        List<String> steps=new ArrayList<>();
        steps.add("Establish a backed-up, isolated validation copy and identify the intended target artifacts. Every later action depends on this evidence baseline.");
        if(categories.contains("JAVA")||categories.contains("UPGRADE_PATH")||categories.contains("SECURITY"))steps.add("Resolve runtime, version and incomplete-input findings first. API comparison cannot establish readiness from an incomplete or unsupported runtime.");
        if(categories.stream().anyMatch(Set.of("API_COMPATIBILITY","INTERNAL_API","LEGACY_JARS","CORDAPP","SIGNING","DEPENDENCY")::contains))steps.add("Resolve missing API requirements and target CorDapp dependencies together. Then verify the actual verifier class sources: a shadowed legacy shim cannot repair the selected runtime class. Recheck signing continuity after replacing CorDapps.");
        if(categories.contains("DATABASE_SCHEMA")||categories.contains("CONFIGURATION"))steps.add("On the validation database copy, reconcile schema, quoting and search_path with TVU configuration. This must precede TVU so configuration failures do not obscure linkage failures.");
        steps.add("Rerun static assessment after the artifact/configuration fixes. Resolve remaining blockers and unknown evidence before relying on validation results.");
        steps.add("Run the complete required TVU against the prepared copy; import all summary and failure evidence from that single run. Previous-target TVU evidence cannot establish readiness for a new target.");
        steps.add("Continue the official R3 upgrade procedure and change approval only when required TVU passes and the assessment is READY TO UPGRADE.");
        StringBuilder s=new StringBuilder("ORDERED REMEDIATION PLAN\n");for(int i=0;i<steps.size();i++)s.append(i+1).append(". ").append(steps.get(i)).append("\n\n");return s.toString();
    }
    static String key(Finding f) {
        // JAR paths are relative to the scanned root. Exclude volatile target hashes and prose.
        List<String> symbols=f.technicalEvidence().stream().filter(e->e.matches("(?i)(owner|member|descriptor|caller|callingMethod|class|method|reference|jar): .*" )).sorted().toList();
        return f.id()+"|"+f.affectedArtifact()+"|"+symbols;
    }
    public static String comparison(Assessment previous,Assessment next) {
        Map<String,Finding> old=new TreeMap<>(),now=new TreeMap<>();blockers(previous).stream().filter(f->!f.category().equals("TVU")).forEach(f->old.put(key(f),f));blockers(next).stream().filter(f->!f.category().equals("TVU")).forEach(f->now.put(key(f),f));
        StringBuilder s=new StringBuilder("Previous target: Corda "+previous.targetVersion()+"\nNew target: Corda "+next.targetVersion()+"\n");
        for(String section:List.of("RESOLVED","UNCHANGED","NEW")) {
            s.append("\n").append(section).append("\n");int count=0;
            Map<String,Finding> source=section.equals("RESOLVED")?old:now;
            for(var e:source.entrySet())if(section.equals("RESOLVED")?!now.containsKey(e.getKey()):section.equals("NEW")?!old.containsKey(e.getKey()):old.containsKey(e.getKey())) {
                Finding f=e.getValue();s.append(f.id()).append(" · ").append(f.title());
                if(section.equals("RESOLVED"))s.append(f.category().equals("TVU")?" — previous TVU evidence retired; new validation required":" — no longer BLOCKED in the new assessment; review warnings and coverage");
                s.append('\n');count++;
            }
            if(count==0)s.append("None\n");
        }
        return s+"\nPrevious status: "+previous.status()+"\nNew status: "+next.status()+"\nTVU evidence and target overrides were reset for the new target.\nPrevious TVU failures are excluded from the comparison, not marked resolved.\n";
    }
}
