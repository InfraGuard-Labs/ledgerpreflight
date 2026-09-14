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
        IMPORT("Import existing TVU results"),
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
    private final SortedSet<Path> generated=new TreeSet<>();
    public InteractiveSession(AssessmentService.Options options,Assessment assessment,Path output,SessionTerminal terminal) {
        this.options=options;this.assessment=assessment;this.output=output.toAbsolutePath().normalize();this.sessionRoot=this.output;this.terminal=terminal;
        rememberReports(this.output);
    }
    static List<Action> actions(Assessment assessment) {
        List<Action> actions=new ArrayList<>();
        boolean supplied=ResultEvidence.hasTvu(assessment);
        if(!supplied)actions.add(Action.IMPORT);
        if(ResultEvidence.hasCompatibility(assessment))actions.add(Action.COMPATIBILITY);
        if(ResultEvidence.hasTvu(assessment))actions.add(Action.TVU);
        if(ResultEvidence.hasSchema(assessment)||AssessmentInsights.hasSchemaEvidence(assessment))actions.add(Action.SCHEMA);
        actions.addAll(List.of(Action.EXPORT,Action.SUPPORT));
        if(supplied)actions.add(Action.IMPORT);
        actions.add(Action.EXIT);
        return List.copyOf(actions);
    }
    public int run()throws IOException {
        Reports.write(output,Reports.files(assessment));
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
