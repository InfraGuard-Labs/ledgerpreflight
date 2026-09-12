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
        EVIDENCE("View technical evidence"), SUPPORT("Create R3 support package"), AGAIN("Run again"),
        INSTRUCTIONS("TVU instructions"), CHECKLIST("View upgrade checklist"), EXIT("Exit");
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
    static List<Action> actions(String status) {
        if(status.equals("READY FOR TVU"))return List.of(Action.INSTRUCTIONS,Action.EVIDENCE,Action.EXIT);
        if(status.equals("READY TO UPGRADE"))return List.of(Action.CHECKLIST,Action.EVIDENCE,Action.EXIT);
        return List.of(Action.EVIDENCE,Action.SUPPORT,Action.AGAIN,Action.EXIT);
    }
    public int run()throws IOException {
        Reports.write(output,Reports.files(assessment));
        while(true) {
            terminal.screen();terminal.text(ProductView.result(assessment));
            List<Action> choices=actions(assessment.status());
            int selected=terminal.choose("",choices.stream().map(a->a.label).toList());
            if(selected<0||choices.get(selected)==Action.EXIT){
                terminal.screen();terminal.text("LedgerPreflight "+assessment.productVersion()+"\nSession complete · "+ProductView.state(assessment)+"\nAssessment saved: "+output.resolve("report.html"));
                return assessment.exitCode();
            }
            terminal.screen();
            try {switch(choices.get(selected)){
                case EVIDENCE -> technical();
                case SUPPORT -> {support();terminal.choose("",List.of("Back"));}
                case AGAIN -> reanalyze(options,fresh("reassessment"));
                case INSTRUCTIONS -> instructions();
                case CHECKLIST -> {checklist();terminal.choose("",List.of("Back"));}
                default -> {}
            }}catch(Exception e){terminal.text("! Action could not complete: "+Objects.toString(e.getMessage(),"unknown error")+"\nYour current assessment remains available.");terminal.choose("",List.of("Back"));}
        }
    }
    private void technical()throws IOException {
        while(true) {
            terminal.screen();
            int choice=terminal.choose("TECHNICAL EVIDENCE",List.of("Compatibility and classpath","Runtime and artifact identity","Schema configuration","TVU results","Analysis coverage","Generate technical assessment","View generated artifacts","Back"));
            if(choice<0||choice==7)return;
            terminal.screen();
            switch(choice){
                case 0 -> page("COMPATIBILITY AND CLASSPATH\n"+Reports.json(assessment.findings())+"\nRuntime comparison\n"+Reports.json(assessment.evidence().get("runtime-api-delta"))+"\nClasspath order\n"+Reports.json(assessment.evidence().get("classpath-analysis")));
                case 1 -> page("ARTIFACT IDENTITY\n"+Reports.json(assessment.evidence().get("discovery"))+"\nCurrent physical artifacts\n"+Reports.json(assessment.evidence().get("environment"))+"\nTarget physical artifacts\n"+Reports.json(assessment.evidence().get("upgrade-kit"))+"\nHashes\n"+Reports.json(assessment.hashes()));
                case 2 -> page("SCHEMA CONFIGURATION\n"+Reports.json(assessment.evidence().get("schema-analysis")));
                case 3 -> page("TVU RESULTS\n"+Reports.json(assessment.evidence().get("tvu-summary")));
                case 4 -> page("ANALYSIS COVERAGE\n"+Reports.json(assessment.evidence().get("analysis-coverage"))+"\nDiscovery paths\n"+Reports.json(assessment.evidence().get("node-discovery")));
                case 5 -> {report();terminal.choose("",List.of("Back"));}
                case 6 -> {artifacts();terminal.choose("",List.of("Back"));}
                default -> {}
            }
        }
    }
    private void instructions()throws Exception {
        terminal.text("TVU INSTRUCTIONS\n\n"+AssessmentInsights.tvuReadiness(assessment,options.tvuJar()));
        terminal.text("Validate a backed-up isolated node and database copy first.\nUse the target TVU and rebuilt target CorDapps.\nConfirm the intended Hibernate default schema for TVU.\nStatic analysis does not replace complete TVU validation.\n\nSupply completed logs or an error ZIP with --tvu-results, or import below.");
        int choice=terminal.choose("",List.of("Import TVU evidence","Run TVU on an isolated copy","Back"));
        if(choice==0)importTvu();else if(choice==1)runTvu();else return;
        terminal.choose("",List.of("Continue"));
    }
    private void page(String text)throws IOException {
        String[] lines=text.split("\n");
        for(int i=0;i<lines.length;i+=14){terminal.screen();terminal.text(String.join("\n",Arrays.copyOfRange(lines,i,Math.min(i+14,lines.length))));
            if(i+14<lines.length){if(terminal.choose("DETAILS",List.of("Continue","Back"))!=0)return;}
            else terminal.choose("End of technical evidence",List.of("Back"));}
    }
    private void report()throws IOException {
        terminal.text("Generating complete technical assessment…");
        Map<String,String> files=Reports.files(assessment);files.put("technical-assessment.txt",Reports.terminal(assessment,true));files.put("remediation-plan.txt",AssessmentInsights.plan(assessment));
        Reports.write(output,files);rememberReports(output);generated.add(output.resolve("technical-assessment.txt"));generated.add(output.resolve("remediation-plan.txt"));terminal.text("Assessment generated\nHTML: "+output.resolve("report.html")+"\nJSON: "+output.resolve("report.json")+"\nSummary: "+output.resolve("summary.txt")+"\nTechnical text: "+output.resolve("technical-assessment.txt"));
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
        new SupportBundle().create(zip,Main.bundleFiles(Reports.files(assessment)));
        String hash;
        try(InputStream in=Files.newInputStream(zip)){var digest=java.security.MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];int n;while((n=in.read(buffer))!=-1)digest.update(buffer,0,n);hash=HexFormat.of().formatHex(digest.digest());}
        catch(java.security.NoSuchAlgorithmException e){throw new IOException(e);}
        Path checksum=zip.resolveSibling(zip.getFileName()+".sha256");Files.writeString(checksum,hash+"  "+zip.getFileName()+"\n",StandardOpenOption.CREATE_NEW);
        generated.add(zip);generated.add(checksum);
        terminal.text("READY TO SHARE\n\nFile:\n"+zip+"\n\nSafety:\n✓ Secrets redacted\n✓ Private keys excluded\n✓ Keystores excluded\n✓ Final package rescanned\n✓ SHA-256 generated\n\nChecksum file:\n"+checksum);
    }
    private void rememberReports(Path directory){for(String name:List.of("report.html","report.json","summary.txt"))generated.add(directory.resolve(name));}
    private void artifacts()throws IOException {
        terminal.text("GENERATED ARTIFACTS\n");int count=0;
        for(Path path:generated)if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)){terminal.text(path.toString());count++;}
        if(count==0)terminal.text("No generated files yet. Choose Generate technical assessment.");
    }
    private void prepare() {
        terminal.text("TVU PREPARATION · "+assessment.targetVersion()+"\n"+AssessmentInsights.header(assessment));
        terminal.text("1. Prepare a backed-up, isolated node copy and a disposable database copy.\n2. Configure the copy's node.conf to use that database; keep the real node unchanged.\n3. Place the intended target CorDapps and dependencies in the copy's cordapps/legacy-jars directories.\n4. Review missing-runtime, API and schema findings before execution.\n5. Inspect and explicitly approve the command before running TVU.\nTVU may write to the selected copy and contact its configured database. LedgerPreflight does not create or migrate databases.\nGuide: https://docs.r3.com/en/platform/corda/4.12/enterprise/node/operating/tvu/running-tvu.html");
    }
    private void runTvu()throws Exception {
        prepare();String input=terminal.ask("Prepared isolated validation-copy directory");if(input.isEmpty())return;
        Path capture=fresh("tvu-run");
        TvuExecution.Plan plan=TvuExecution.prepare(options,assessment,Path.of(input),capture);
        terminal.text("REVIEW EXECUTION\nTarget TVU version: "+assessment.targetVersion()+"\nNode copy: "+plan.base()+"\nDatabase: "+TvuExecution.databaseTarget(plan.base().resolve("node.conf"))+"\nRead-only: No — approved TVU may write to the isolated copy.\nWorking directory: "+plan.base()+"\nCommand arguments (no shell):\n"+Reports.json(plan.command())+"\nCapture directory: "+capture+
            "\nThe supplied TVU will execute with your permissions and connect to the copy's database. Confirm the copy is isolated, the TVU is trusted, and the database is disposable. No migration is requested.\nType RUN TVU ON COPY to approve; anything else cancels.");
        if(!terminal.ask("Confirmation").equals("RUN TVU ON COPY")){terminal.text("TVU execution cancelled.");return;}
        int code;
        try{code=TvuExecution.run(plan,true,terminal,3600);}catch(Exception e){terminal.text("TVU run incomplete. Captures: "+capture);markRunFailure(capture,"TVU run was interrupted, exceeded limits or could not be captured.");return;}
        terminal.text("TVU exited with code "+code+". Analyzing captured evidence…");
        if(code!=0){markRunFailure(capture,"TVU exited with code "+code+"; complete successful execution is not established.");return;}
        reanalyze(withTvu(List.of(capture)),fresh("validated"));
    }
    private void markRunFailure(Path capture,String message)throws IOException {
        AssessmentService.Options candidate=withTvu(List.of(capture));Assessment next=new AssessmentService().assess(candidate);
        List<Finding> findings=new ArrayList<>(next.findings());findings.add(Finding.of("LP-TVU-EXEC","Approved TVU run did not complete successfully","UNKNOWN","TVU","HIGH","PROCESS_EXECUTION","TVU",List.of(message),"This run cannot establish final readiness","Review the private capture and rerun complete TVU."));
        next=new Assessment(next.schemaVersion(),next.productVersion(),Assessment.readiness(findings,false,true),next.sourceVersion(),next.targetVersion(),findings,next.evidence());
        commit(candidate,next,fresh("incomplete-tvu"));
    }
    private void importTvu()throws IOException {
        List<Path> paths=new ArrayList<>();String path=terminal.ask("TVU log, error ZIP or directory from one complete run");if(path.isEmpty())return;paths.add(Path.of(path));
        while(true){int action=terminal.choose("TVU EVIDENCE",List.of("Analyze this run","Add another file from the same run","Cancel"));if(action==0)break;if(action!=1)return;path=terminal.ask("Additional evidence path");if(!path.isEmpty())paths.add(Path.of(path));else return;}
        for(Path p:paths){Main.ensureOutputSeparate(sessionRoot,p);if(!Files.exists(p))throw new IOException("TVU evidence path does not exist");}
        reanalyze(withTvu(paths),fresh("imported-tvu"));
    }
    private AssessmentService.Options withTvu(List<Path> paths){return new AssessmentService.Options(options.node(),options.kit(),options.targetCorda(),options.tvuJar(),options.targetCordapps(),options.legacyJars(),options.nodeConf(),paths,options.verifierClasspath(),options.rulePack(),options.networkMode(),options.hostEnvironment());}
    private void reanalyze(AssessmentService.Options candidate,Path destination)throws IOException {commit(candidate,new AssessmentService().assess(candidate,terminal::text),destination);}
    private void commit(AssessmentService.Options candidate,Assessment next,Path destination)throws IOException {
        Reports.write(destination,Reports.files(next));options=candidate;assessment=next;output=destination;
        rememberReports(destination);terminal.text("Assessment updated · "+next.status()+"\nReports: "+destination);
    }
    private void checklist() {
        terminal.text("UPGRADE CHECKLIST · "+assessment.targetVersion()+"\n\n1. Validate the upgrade in a lower environment first.\n2. Confirm rebuilt target CorDapps, signing continuity and target Java.\n3. Verify complete successful TVU evidence for these exact artifacts\n   and the intended database snapshot; static checks do not replace TVU.\n4. Confirm backups, restore rehearsal and the rollback plan.\n5. Follow the supported network upgrade sequence. During rolling or\n   sequential upgrades, avoid processing transactions across incompatible\n   mixed versions; coordinate participants and notaries as required.\n6. Obtain change approval and follow the supported Corda upgrade guide.\n7. Run validation/test transactions and check node health after upgrade.\n\nLedgerPreflight has not modified or upgraded your node.");
    }
}