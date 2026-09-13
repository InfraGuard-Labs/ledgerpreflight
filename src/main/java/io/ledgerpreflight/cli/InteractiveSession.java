package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** A live assessment session. Each action operates on the currently selected target. */
public final class InteractiveSession {
    enum Action {
        RUN("Run TVU safely"), RUN_AGAIN("Run TVU again"), IMPORT("Import existing TVU results"),
        COMPATIBILITY("View compatibility evidence"), SCHEMA("View schema evidence"), TVU("View TVU evidence"),
        EXPORT("Export full technical report"), SUPPORT("Create R3 support package"),
        EXIT("Exit");
        final String label;Action(String label){this.label=label;}
    }
    private AssessmentService.Options options;
    private Assessment assessment;
    private Path output;
    private final Path sessionRoot;
    private final SessionTerminal terminal;
    private Path tvuNodeConf;
    private String tvuSchema;
    private final SortedSet<Path> generated=new TreeSet<>();
    public InteractiveSession(AssessmentService.Options options,Assessment assessment,Path output,SessionTerminal terminal) {
        this.options=options;this.assessment=assessment;this.output=output.toAbsolutePath().normalize();this.sessionRoot=this.output;this.terminal=terminal;
        rememberReports(this.output);
    }
    public InteractiveSession(AssessmentService.Options options,Assessment assessment,Path output,SessionTerminal terminal,Path tvuNodeConf,String tvuSchema) {
        this(options,assessment,output,terminal);this.tvuNodeConf=tvuNodeConf;this.tvuSchema=tvuSchema;
    }
    static List<Action> actions(Assessment assessment) {
        List<Action> actions=new ArrayList<>();
        boolean supplied=ResultEvidence.hasTvu(assessment),runnable=AssessmentInsights.hasTvuArtifact(assessment);
        if(!supplied){if(runnable)actions.add(Action.RUN);actions.add(Action.IMPORT);}
        if(ResultEvidence.hasCompatibility(assessment))actions.add(Action.COMPATIBILITY);
        if(ResultEvidence.hasTvu(assessment))actions.add(Action.TVU);
        if(ResultEvidence.hasSchema(assessment)||AssessmentInsights.hasTvuSchemaSetup(assessment))actions.add(Action.SCHEMA);
        actions.addAll(List.of(Action.EXPORT,Action.SUPPORT));
        if(supplied){if(runnable)actions.add(Action.RUN_AGAIN);actions.add(Action.IMPORT);}
        actions.add(Action.EXIT);
        return List.copyOf(actions);
    }
    public int run()throws IOException {return run(false);}
    public int run(boolean startWithTvu)throws IOException {
        Reports.write(output,Reports.files(assessment));
        if(startWithTvu)try{runTvu();}catch(Exception e){terminal.text("TVU setup could not complete: "+Objects.toString(e.getMessage(),"Review the supplied configuration."));}
        while(true) {
            terminal.screen();terminal.text(ProductView.result(assessment));
            List<Action> choices=actions(assessment);
            int selected=terminal.choose("",choices.stream().map(a->a.label).toList());
            if(selected<0||choices.get(selected)==Action.EXIT){
                terminal.screen();terminal.text("LedgerPreflight "+assessment.productVersion()+"\nSession complete · "+ProductView.state(assessment)+"\nAssessment saved: "+output.resolve("report.html"));
                return assessment.exitCode();
            }
            terminal.screen();
            try {switch(choices.get(selected)){
                case RUN,RUN_AGAIN -> runTvu();
                case IMPORT -> importTvu();
                case COMPATIBILITY -> {terminal.text(ResultEvidence.compatibility(assessment));terminal.choose("",List.of("Back"));}
                case SCHEMA -> {terminal.text(ResultEvidence.schema(assessment));terminal.choose("",List.of("Back"));}
                case TVU -> {terminal.text(ResultEvidence.tvu(assessment));terminal.choose("",List.of("Back"));}
                case EXPORT -> {report();terminal.choose("",List.of("Back"));}
                case SUPPORT -> {support();terminal.choose("",List.of("Back"));}
                default -> {}
            }}catch(Exception e){terminal.text("! Action could not complete: "+Objects.toString(e.getMessage(),"unknown error")+"\nYour current assessment remains available.");terminal.choose("",List.of("Back"));}
        }
    }
    private void report()throws IOException {
        terminal.text("Generating complete technical assessment…");
        Map<String,String> files=Reports.files(assessment);files.put("technical-assessment.txt",Reports.terminal(assessment,true));files.put("remediation-plan.txt",AssessmentInsights.plan(assessment));files.put("upgrade-checklist.txt",checklist());
        Reports.write(output,files);rememberReports(output);generated.add(output.resolve("technical-assessment.txt"));generated.add(output.resolve("remediation-plan.txt"));terminal.text("Technical report exported\nHTML: "+output.resolve("report.html")+"\nJSON: "+output.resolve("report.json")+"\nSummary: "+output.resolve("summary.txt")+"\nTechnical text: "+output.resolve("technical-assessment.txt"));
    }
    private Path fresh(String prefix)throws IOException {
        Reports.checkNoSymlink(sessionRoot);Files.createDirectories(sessionRoot);
        return sessionRoot.resolve(prefix+"-"+UUID.randomUUID().toString().substring(0,8));
    }
    private void support()throws IOException {
        terminal.text("Selecting evidence · redacting secrets · validating package…");
        Reports.checkNoSymlink(sessionRoot);Files.createDirectories(sessionRoot);
        String node=Reports.JSON.valueToTree(assessment.evidence().get("environment")).path("nodeName").asText("Node").replaceAll("[^A-Za-z0-9_-]","-");
        if(node.isBlank())node="Node";node=node.substring(0,Math.min(80,node.length()));
        String stem=node+"-R3-support-"+java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmm"));
        Path zip=sessionRoot.resolve(stem+".zip");
        for(int sequence=2;Files.exists(zip,LinkOption.NOFOLLOW_LINKS)||Files.exists(zip.resolveSibling(zip.getFileName()+".sha256"),LinkOption.NOFOLLOW_LINKS);sequence++)zip=sessionRoot.resolve(stem+"-"+sequence+".zip");
        Path checksum=Main.createSupportPackage(zip,Main.bundleFiles(Reports.files(assessment)));
        generated.add(zip);generated.add(checksum);
        terminal.text("READY TO SHARE\n\nFile:\n"+zip+"\n\nSafety:\n✓ Secrets redacted\n✓ Private keys excluded\n✓ Keystores excluded\n✓ Final package rescanned\n✓ SHA-256 generated\n\nChecksum file:\n"+checksum);
    }
    private void rememberReports(Path directory){for(String name:List.of("report.html","report.json","summary.txt"))generated.add(directory.resolve(name));}
    private void artifacts()throws IOException {
        terminal.text("GENERATED ARTIFACTS\n");int count=0;
        for(Path path:generated)if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)){terminal.text(path.toString());count++;}
        if(count==0)terminal.text("No generated files yet. Choose Generate technical assessment.");
    }
    private void runTvu()throws Exception {
        while(true){
            if(!chooseSchemaIfNeeded())return;
            GuidedTvuExecution.Plan plan;
            try{plan=GuidedTvuExecution.inspect(options,assessment,tvuNodeConf,tvuSchema,sessionRoot);}
            catch(IOException e){
                terminal.screen();terminal.text("TVU SETUP FAILURE\n\n"+Objects.toString(e.getMessage(),"The supplied configuration could not be validated."));
                if(terminal.choose("",List.of("Use a different safe node configuration","Cancel"))!=0)return;
                if(!chooseTvuConfig())return;continue;
            }
            terminal.screen();terminal.text(AssessmentInsights.guidedSafety(plan));
            int approval=terminal.choose("Is this an isolated / non-production database copy?",List.of("Yes, run TVU","Use a different safe node configuration","Cancel"));
            if(approval==1){if(!chooseTvuConfig())return;continue;}
            if(approval!=0){terminal.text("TVU cancelled. No process was started.");return;}
            GuidedTvuExecution.Outcome result;
            try(var progress=terminal.progress()){
                result=GuidedTvuExecution.run(plan,true,86400,p->progress.show(AssessmentInsights.guidedProgress(p)),progress::cancelled);
            }
            AssessmentService.Options candidate=withTvu(result.evidencePaths());
            commit(candidate,assessGuided(candidate,result),fresh("validated"));
            return;
        }
    }
    private boolean chooseTvuConfig()throws IOException {
        String value=terminal.ask("Safe node configuration path (credentials stay in the file)");if(value.isEmpty())return false;
        Path selected=Path.of(value);Main.ensureOutputSeparate(sessionRoot,selected);SafeInputs.checkPath(selected);
        tvuNodeConf=selected;tvuSchema=null;return true;
    }
    private boolean chooseSchemaIfNeeded()throws IOException {
        if(tvuSchema!=null&&!tvuSchema.isBlank())return true;
        ConfigAnalyzer.ConfigEvidence config=tvuNodeConf==null&&assessment.evidence().get("schema-analysis") instanceof ConfigAnalyzer.ConfigEvidence c?c:new ConfigAnalyzer().analyze(tvuNodeConf);
        if(!Objects.toString(config.safeSettings().get("primarySchema"),"").isBlank())return true;
        List<String> candidates=new ArrayList<>();
        if(config.safeSettings().get("schemas") instanceof List<?> schemas)for(Object item:schemas)if(item instanceof String name&&!name.isBlank()&&!candidates.contains(name))candidates.add(name);
        if(candidates.isEmpty())return true;
        List<String> choices=new ArrayList<>(candidates);choices.add("Cancel");
        terminal.screen();terminal.text("TVU SCHEMA\n\nThe effective primary schema is not established.\nSelect the intended schema from the discovered configuration.");
        int selected=terminal.choose("Intended TVU schema",choices);if(selected<0||selected>=candidates.size())return false;
        tvuSchema=candidates.get(selected);return true;
    }
    static Assessment assessGuided(AssessmentService.Options candidate,GuidedTvuExecution.Outcome outcome)throws IOException {
        Assessment next=new AssessmentService().assess(candidate);
        next=AssessmentService.withGuidedSchemaProof(candidate,next,Objects.toString(outcome.manifest().get("schema"),""));
        Map<String,Object> evidence=new TreeMap<>(next.evidence());evidence.put("tvu-run",outcome.manifest());
        List<Finding> findings=new ArrayList<>(next.findings());
        String manifestKind=Objects.toString(outcome.manifest().get("failureKind"),outcome.failureKind());
        boolean failed=outcome.cancelled()||outcome.exitCode()!=0||!outcome.failureKind().equals("NONE")||!manifestKind.equals("NONE")
            ||Boolean.FALSE.equals(outcome.manifest().get("workspaceCleaned"))||Boolean.TRUE.equals(outcome.manifest().get("manifestWriteFailure"));
        String failureKind=outcome.failureKind().equals("NONE")?(manifestKind.equals("NONE")?"EXECUTION_FAILURE":manifestKind):outcome.failureKind();
        if(failed&&findings.stream().noneMatch(f->f.category().equals("TVU")&&f.severity().equals("BLOCKED")))
            findings.add(Finding.of("LP-TVU-EXEC",AssessmentInsights.guidedOutcome(failureKind),"UNKNOWN","TVU","HIGH","PROCESS_EXECUTION","TVU",List.of("Exit code: "+outcome.exitCode(),"Run outcome: "+failureKind),"This run cannot establish complete upgrade readiness","Review the captured evidence and run TVU safely again."));
        boolean successful=!failed&&next.evidence().get("tvu-summary") instanceof TvuAnalyzer.TvuEvidence tvu&&tvu.completeSuccess();
        return new Assessment(next.schemaVersion(),next.productVersion(),Assessment.readiness(findings,successful,true),next.sourceVersion(),next.targetVersion(),findings,Collections.unmodifiableMap(evidence));
    }
    private void importTvu()throws IOException {
        List<Path> paths=new ArrayList<>();String path=terminal.ask("TVU log, error ZIP or directory from one complete run");if(path.isEmpty())return;paths.add(Path.of(path));
        while(true){int action=terminal.choose("TVU EVIDENCE",List.of("Analyze this run","Add another file from the same run","Cancel"));if(action==0)break;if(action!=1)return;path=terminal.ask("Additional evidence path");if(!path.isEmpty())paths.add(Path.of(path));else return;}
        for(Path p:paths){Main.ensureOutputSeparate(sessionRoot,p);if(!Files.exists(p))throw new IOException("TVU evidence path does not exist");}
        reanalyze(withTvu(paths),fresh("imported-tvu"));
    }
    private AssessmentService.Options withTvu(List<Path> paths){return withTvu(options,paths);}
    static AssessmentService.Options withTvu(AssessmentService.Options options,List<Path> paths){return new AssessmentService.Options(options.node(),options.kit(),options.targetCorda(),options.tvuJar(),options.targetCordapps(),options.legacyJars(),options.nodeConf(),paths,options.verifierClasspath(),options.rulePack(),options.networkMode(),options.hostEnvironment(),options.currentRuntime());}
    private void reanalyze(AssessmentService.Options candidate,Path destination)throws IOException {commit(candidate,new AssessmentService().assess(candidate,terminal::text),destination);}
    private void commit(AssessmentService.Options candidate,Assessment next,Path destination)throws IOException {
        Reports.write(destination,Reports.files(next));options=candidate;assessment=next;output=destination;
        rememberReports(destination);terminal.text("Assessment updated · "+ProductView.state(next)+"\nReports: "+destination);
    }
    private String checklist() {
        return "UPGRADE CHECKLIST · "+assessment.targetVersion()+"\n\n1. Validate the upgrade in a lower environment first.\n2. Confirm rebuilt target CorDapps, signing continuity and target Java.\n3. Verify complete successful TVU evidence for these exact artifacts\n   and the intended database snapshot; static checks do not replace TVU.\n4. Confirm backups, restore rehearsal and the rollback plan.\n5. Follow the supported network upgrade sequence. During rolling or\n   sequential upgrades, avoid processing transactions across incompatible\n   mixed versions; coordinate participants and notaries as required.\n6. Obtain change approval and follow the supported Corda upgrade guide.\n7. Run validation/test transactions and check node health after upgrade.\n\nLedgerPreflight has not modified or upgraded your node.";
    }
}
