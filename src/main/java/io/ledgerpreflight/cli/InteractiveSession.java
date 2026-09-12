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
        UNDERSTAND("Understand the blockers"), TVU("TVU validation"), REPORTS("Reports & R3 Support"),
        EXPLAIN("Explain blockers"), REVIEW("Show all findings"), PLAN("Show resolution plan"),
        READINESS("Check TVU readiness"), PREPARE("Prepare TVU validation"), RUN("Run guided TVU validation"),
        IMPORT("Import existing TVU results"), REPORT("Generate technical assessment"),
        SUPPORT("Create sanitized R3 Support package"), ARTIFACTS("View generated artifacts"),
        COMPARE("Compare another target Corda version"), ASSESSMENT("Review assessment"),
        APPROVAL("Generate change-approval report"), PACKAGE("Create evidence package"), FINAL("Review final assessment"), BACK("Back"), EXIT("Exit");
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
        if(status.equals("READY FOR TVU"))return List.of(Action.PREPARE,Action.RUN,Action.IMPORT,Action.ASSESSMENT,Action.REPORTS,Action.EXIT);
        if(status.equals("READY TO UPGRADE"))return List.of(Action.APPROVAL,Action.PACKAGE,Action.FINAL,Action.EXIT);
        return List.of(Action.UNDERSTAND,Action.TVU,Action.REPORTS,Action.EXIT);
    }
    public int run()throws IOException {
        Assessment displayed=null;
        while(true) {
            terminal.screen();
            if(displayed!=assessment){terminal.text(AssessmentInsights.header(assessment));terminal.text(AssessmentInsights.summary(assessment));displayed=assessment;}
            else terminal.text("LedgerPreflight · "+assessment.sourceVersion()+" → "+assessment.targetVersion()+"\n"+assessment.status()+"\n");
            List<Action> choices=actions(assessment.status());
            if(AssessmentInsights.blockers(assessment).isEmpty()&&choices.contains(Action.UNDERSTAND))choices=List.of(Action.ASSESSMENT,Action.TVU,Action.REPORTS,Action.EXIT);
            int selection=terminal.choose(assessment.status().equals("READY TO UPGRADE")?"OPTIONAL":"WHAT WOULD YOU LIKE TO DO?",choices.stream().map(a->a.label).toList());
            if(selection<0||choices.get(selection)==Action.EXIT){terminal.screen();terminal.text("LedgerPreflight "+assessment.productVersion()+"\nSession complete · "+assessment.status()+"\nYour assessment is saved.\nReports: "+output+"\nNo node upgrade or migration was performed.");return assessment.exitCode();}
            Action selected=choices.get(selection);
            if(Set.of(Action.UNDERSTAND,Action.TVU,Action.REPORTS).contains(selected))submenu(selected);
            else perform(selected);
        }
    }
    private void submenu(Action group)throws IOException {
        List<Action> choices=switch(group){
            case UNDERSTAND->List.of(Action.EXPLAIN,Action.REVIEW,Action.PLAN,Action.COMPARE,Action.BACK);
            case TVU->List.of(Action.READINESS,Action.PREPARE,Action.RUN,Action.IMPORT,Action.BACK);
            default->List.of(Action.REPORT,Action.SUPPORT,Action.ARTIFACTS,Action.BACK);
        };
        String title=switch(group){case UNDERSTAND->"UNDERSTAND THE BLOCKERS";case TVU->"TVU VALIDATION";default->"REPORTS & R3 SUPPORT";};
        while(true){
            terminal.screen();terminal.text("LedgerPreflight · "+assessment.status()+"\n");
            int selection=terminal.choose(title,choices.stream().map(a->a.label).toList());
            if(selection<0||choices.get(selection)==Action.BACK)return;
            Assessment before=assessment;
            perform(choices.get(selection));
            if(before!=assessment)return;
        }
    }
    private void perform(Action action)throws IOException {
            terminal.screen();
            try {switch(action) {
                case EXPLAIN -> explain();case REVIEW -> review();case PLAN -> terminal.text(AssessmentInsights.plan(assessment));
                case ASSESSMENT, FINAL -> review();case APPROVAL -> report();case PACKAGE -> support();
                case READINESS -> terminal.text(AssessmentInsights.tvuReadiness(assessment,options.tvuJar()));
                case PREPARE -> prepare();case RUN -> runTvu();case IMPORT -> importTvu();case REPORT -> report();
                case SUPPORT -> support();case COMPARE -> compare();case ARTIFACTS -> artifacts();default -> {}
            }}catch(Exception e){terminal.text("! Action could not complete: "+Objects.toString(e.getMessage(),"unknown error")+"\nYour current assessment remains available.");}
            if(!Set.of(Action.EXPLAIN,Action.REVIEW,Action.ASSESSMENT,Action.FINAL).contains(action))terminal.choose("",List.of("Back"));
    }
    private void explain()throws IOException {
        List<Finding> findings=AssessmentInsights.blockers(assessment);
        if(findings.isEmpty())findings=assessment.findings().stream().filter(f->Set.of("WARNING","UNKNOWN").contains(f.severity())).toList();
        if(findings.isEmpty()){terminal.text("No blockers or unresolved findings in this assessment.");terminal.choose("",List.of("Back"));return;}
        int index=0;
        while(true) {
            terminal.screen();
            terminal.text("\nFinding "+(index+1)+" of "+findings.size()+"\n"+AssessmentInsights.explanation(findings.get(index)));
            int action=terminal.choose("EXPLORE THIS FINDING",List.of("Show technical evidence","Next blocker","Previous blocker","Back"));
            if(action<0||action==3)return;
            if(action==0)evidence(findings.get(index));
            else index=Math.floorMod(index+(action==1?1:-1),findings.size());
        }
    }
    private void evidence(Finding finding)throws IOException {
        terminal.screen();terminal.text(AssessmentInsights.technicalEvidence(finding));
        if(terminal.choose("",List.of("Back","View raw JSON"))!=1)return;
        page(Reports.json(finding)+"\nRuntime comparison\n"+Reports.json(assessment.evidence().get("runtime-api-delta"))+
            "\nClasspath source\n"+Reports.json(assessment.evidence().get("classpath-analysis"))+"\nArtifact hashes\n"+Reports.json(assessment.hashes())+"\nEnvironment evidence\n"+Reports.json(assessment.evidence().get("environment")));
    }
    private void page(String text)throws IOException {
        String[] lines=text.split("\n");
        for(int i=0;i<lines.length;i+=14){terminal.screen();terminal.text(String.join("\n",Arrays.copyOfRange(lines,i,Math.min(i+14,lines.length))));
            if(i+14<lines.length){if(terminal.choose("DETAILS",List.of("Continue","Back"))!=0)return;}
            else terminal.choose("End of technical evidence",List.of("Back"));}
    }
    private void review()throws IOException {
        for(Finding f:assessment.findings()) {
            terminal.text(f.severity()+" · "+f.id()+" · "+f.title()+"\n"+f.impact());
            int n=terminal.choose("REVIEW FINDING",List.of("Next finding","Explain this finding","Technical evidence","Back"));
            if(n<0||n==3)return;if(n==1)terminal.text(AssessmentInsights.explanation(f));if(n==2)evidence(f);
        }
        terminal.text("All findings reviewed.");
        terminal.choose("",List.of("Back"));
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
        terminal.text("1. Prepare a backed-up, isolated node copy and a disposable 4.11/4.12 database copy.\n2. Configure the copy's node.conf to use that database; keep the real node unchanged.\n3. Place the intended target CorDapps and dependencies in the copy's cordapps/legacy-jars directories.\n4. Review missing-runtime, API and schema findings before execution.\n5. Choose Run guided TVU validation to inspect and explicitly approve the command.\nTVU may write to the selected copy and contact its configured database. LedgerPreflight does not create or migrate databases.\nGuide: https://docs.r3.com/en/platform/corda/4.12/enterprise/node/operating/tvu/running-tvu.html");
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
    private void compare()throws IOException {
        String path=terminal.ask("Another prepared upgrade-kit directory");if(path.isEmpty())return;
        Path kit=Path.of(path);Main.ensureOutputSeparate(sessionRoot,kit);if(!Files.isDirectory(kit))throw new IOException("Upgrade kit must be a directory");
        var candidate=new AssessmentService.Options(options.node(),kit,null,null,null,null,options.nodeConf(),List.of(),null,options.rulePack(),options.networkMode(),options.hostEnvironment());
        Assessment next=new AssessmentService().assess(candidate,terminal::text);
        terminal.text(AssessmentInsights.comparison(assessment,next));commit(candidate,next,fresh("target-comparison"));
    }
    private void reanalyze(AssessmentService.Options candidate,Path destination)throws IOException {commit(candidate,new AssessmentService().assess(candidate,terminal::text),destination);}
    private void commit(AssessmentService.Options candidate,Assessment next,Path destination)throws IOException {
        Reports.write(destination,Reports.files(next));options=candidate;assessment=next;output=destination;
        rememberReports(destination);terminal.text("Assessment updated · "+next.status()+"\nReports: "+destination);
    }
    private void checklist() {
        terminal.text("FINAL UPGRADE CHECKLIST · "+assessment.targetVersion()+"\n✓ Static and supplied TVU gates passed in this assessment.\n1. Confirm TVU evidence belongs to these exact artifacts and the intended full database snapshot.\n2. Confirm verified backups, restore rehearsal, target Java and deployment permissions.\n3. Confirm signing continuity, network compatibility and remaining operational checks in R3's guide.\n4. Attach the technical report and obtain change approval.\n5. Execute the official upgrade procedure with your rollback plan ready.\nLedgerPreflight has not modified or upgraded your node.");
    }
}
