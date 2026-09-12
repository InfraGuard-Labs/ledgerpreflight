package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.SyntheticFixtureFactory;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class InteractiveSessionTest {
    @TempDir Path root;
    private SessionTerminal terminal(String script,StringWriter output){return new SessionTerminal(new StringReader(script),new PrintWriter(output),false,76);}
    private String session(boolean replay,String script)throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("fixture"),replay);var opts=fixture.options(replay);
        var a=new AssessmentService().assess(opts);StringWriter out=new StringWriter();new InteractiveSession(opts,a,root.resolve("reports"),terminal(script,out)).run();return out.toString();
    }
    @Test void menusFollowActualState(){
        assertEquals(InteractiveSession.Action.UNDERSTAND,InteractiveSession.actions("BLOCKED").get(0));
        assertEquals(InteractiveSession.Action.PREPARE,InteractiveSession.actions("READY FOR TVU").get(0));
        assertEquals(InteractiveSession.Action.APPROVAL,InteractiveSession.actions("READY TO UPGRADE").get(0));
        for(String state:List.of("BLOCKED","UNKNOWN","WARNING"))assertEquals(List.of("Understand the blockers","TVU validation","Reports & R3 Support","Exit"),InteractiveSession.actions(state).stream().map(a->a.label).toList());
    }
    @Test void eofExitsWithoutLooping()throws Exception {assertTrue(session(true,"").contains("Session complete · BLOCKED"));}
    @Test void explainNavigatesBackAndShowsReasonNotOnlyTitle()throws Exception {
        String out=session(true,"1\n1\n2\n3\n4\n5\n4\n");assertTrue(out.contains("WHAT CHANGED"));assertTrue(out.contains("JVM"));assertTrue(out.contains("Finding 2 of"));
    }
    @Test void remediationConnectsApiAndClasspathDependencies()throws Exception {
        String out=session(true,"1\n3\n1\n5\n4\n");assertTrue(out.contains("Then verify the actual verifier class sources"));assertTrue(out.contains("must precede TVU"));
    }
    @Test void reportActionWritesCompleteTextHtmlJson()throws Exception {
        assertTrue(session(true,"3\n1\n1\n4\n4\n").contains("Assessment generated"));
        for(String name:List.of("report.html","report.json","technical-assessment.txt"))assertTrue(Files.size(root.resolve("reports").resolve(name))>100);
    }
    @Test void supportActionCreatesValidatedZip()throws Exception {
        assertTrue(session(true,"3\n2\n1\n4\n4\n").contains("READY TO SHARE"));
        try(var paths=Files.list(root.resolve("reports"))){assertEquals(1,paths.filter(p->p.toString().endsWith(".zip")).count());}
    }
    @Test void cancelledImportDoesNotAnalyzeOrSwitchAssessment()throws Exception {
        String out=session(true,"2\n4\n/nonexistent\n3\n1\n5\n4\n");assertFalse(out.contains("does not exist"));assertTrue(out.contains("Session complete · BLOCKED"));
    }
    @Test void invalidCompareKeepsCurrentTargetAndMenu()throws Exception {
        assertTrue(session(true,"1\n4\n/nonexistent\n1\n5\n4\n").contains("Your current assessment remains available"));
    }
    @Test void targetChangeDropsOldTvuAndTargetOverrides()throws Exception {
        var old=SyntheticFixtureFactory.create(root.resolve("old"),true);var clean=SyntheticFixtureFactory.create(root.resolve("next"),false);
        var a=new AssessmentService().assess(old.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(old.options(true),a,root.resolve("reports"),terminal("1\n4\n"+clean.kit()+"\n1\n5\n4\n",out)).run();
        assertTrue(out.toString().contains("RESOLVED"));assertTrue(out.toString().contains("TVU evidence and target overrides were reset"));
        try(var paths=Files.walk(root.resolve("reports"))){Path report=paths.filter(p->p.endsWith("report.json")).findFirst().orElseThrow();var json=Reports.JSON.readTree(report.toFile());assertFalse(json.path("evidence").path("tvu-summary").path("completeSuccess").asBoolean());}
    }
    @Test void comparisonDoesNotMergeDistinctMethodsUnderSameRule(){
        Finding a=finding("alpha"),b=finding("beta");Assessment old=new Assessment("1","0.1.0","BLOCKED","4.11","4.12",List.of(a,b),Map.of());
        Assessment next=new Assessment("1","0.1.0","BLOCKED","4.11","4.12",List.of(b),Map.of());
        assertNotEquals(AssessmentInsights.key(a),AssessmentInsights.key(b));String text=AssessmentInsights.comparison(old,next);assertTrue(text.contains("RESOLVED\nLP-API-001"));assertTrue(text.contains("UNCHANGED\nLP-API-001"));
    }
    private Finding finding(String member){return Finding.of("LP-API-001","Missing "+member,"BLOCKED","API_COMPATIBILITY","HIGH","RUNTIME_DISCOVERY","app.jar",List.of("owner: example/Api","member: "+member,"descriptor: ()V"),"Linkage failure","Supply supported API");}
    @Test void plainMenuRejectsInvalidInputAndHandlesEof()throws Exception {StringWriter out=new StringWriter();assertEquals(1,terminal("bad\n99\n2\n",out).choose("Menu",List.of("one","two")));assertFalse(out.toString().contains("\u001b"));}
    @Test void terminalStripsEscapeAndDirectionalInjection(){assertFalse(SessionTerminal.safe("\u001b[2J\u202eevil").contains("\u001b"));assertFalse(SessionTerminal.safe("\u202eevil").contains("\u202e"));}
    @Test void legalIdentityAndEnvironmentAreDiscovered()throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("identity"),false);Files.writeString(fixture.node().resolve("node.conf"),"\nmyLegalName=\"O=Example,L=London,C=GB\"\n",StandardOpenOption.APPEND);
        String header=AssessmentInsights.header(new AssessmentService().assess(fixture.options(false)));assertTrue(header.contains("O=Example"));assertFalse(header.contains("Analyzer:"));assertTrue(header.contains("CorDapps:"));assertTrue(header.contains("PostgreSQL"));
    }
    @Test void nonTtyJsonRemainsOneJsonDocument()throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("json"),false);var cmd=Main.command();StringWriter out=new StringWriter();cmd.setOut(new PrintWriter(out));
        assertEquals(1,cmd.execute("assess","--node",fixture.node().toString(),"--upgrade-kit",fixture.kit().toString(),"--output",root.resolve("json-report").toString(),"--json"));
        assertEquals("READY FOR TVU",Reports.JSON.readTree(out.toString()).path("status").asText());assertFalse(out.toString().contains("WHAT WOULD"));
    }
    @Test void tvuRefusesMissingConsentBeforeAnyExecution() {
        var plan=new TvuExecution.Plan(root,root.resolve("x.jar"),root.resolve("capture"),List.of("/does/not/exist"));
        assertThrows(IOException.class,()->TvuExecution.run(plan,false,terminal("",new StringWriter()),1));assertFalse(Files.exists(plan.capture()));
    }
    @Test void tvuRejectsRealNodeAndIdenticalDatabaseUrl()throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("tvu"),false);var a=new AssessmentService().assess(fixture.options(false));
        assertThrows(IOException.class,()->TvuExecution.prepare(fixture.options(false),a,fixture.node(),root.resolve("capture")));
        Path clone=root.resolve("clone");Files.createDirectories(clone.resolve("cordapps"));Files.copy(fixture.node().resolve("node.conf"),clone.resolve("node.conf"));
        var e=assertThrows(IOException.class,()->TvuExecution.prepare(fixture.options(false),a,clone,root.resolve("capture")));assertTrue(e.getMessage().contains("different disposable database"));
    }
    @Test void tvuCapturesApprovedProcessAndNonzeroExit()throws Exception {
        var plan=new TvuExecution.Plan(root,root.resolve("synthetic"),root.resolve("capture"),List.of("/bin/sh","-c","printf 'synthetic TVU failure\\n'; exit 7"));
        assertEquals(7,TvuExecution.run(plan,true,terminal("",new StringWriter()),5));assertTrue(Files.readString(plan.capture().resolve("console.log")).contains("synthetic TVU failure"));
    }
    @Test void importSuccessfulTvuUpdatesMenuAndExitCode()throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("import"),false);var options=fixture.options(false);var a=new AssessmentService().assess(options);StringWriter out=new StringWriter();
        int code=new InteractiveSession(options,a,root.resolve("reports"),terminal("3\n"+fixture.log()+"\n1\n1\n4\n",out)).run();
        assertEquals(0,code);assertTrue(out.toString().contains("Session complete · READY TO UPGRADE"));
    }
    private Path cloneFor(SyntheticFixtureFactory.Fixture fixture)throws IOException {
        Path clone=root.resolve("isolated-copy");Files.createDirectories(clone.resolve("cordapps"));
        Files.writeString(clone.resolve("node.conf"),Files.readString(fixture.node().resolve("node.conf")).replace("synthetic.invalid/example","disposable.invalid/validation"));return clone;
    }
    @Test void cancelledExecutionWritesNoCapture()throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("cancel"),false);Path clone=cloneFor(fixture);var options=fixture.options(false);var a=new AssessmentService().assess(options);StringWriter out=new StringWriter();
        new InteractiveSession(options,a,root.resolve("reports"),terminal("2\n"+clone+"\nNO\n1\n6\n",out)).run();
        assertTrue(out.toString().contains("TVU execution cancelled"));try(var paths=Files.list(root.resolve("reports"))){assertEquals(0,paths.count());}
    }
    @Test void failedApprovedTvuNeverReturnsReady()throws Exception {
        // The synthetic TVU has no executable main: launch must fail, never fabricate success.
        var fixture=SyntheticFixtureFactory.create(root.resolve("failed"),false);Path clone=cloneFor(fixture);var options=fixture.options(false);var a=new AssessmentService().assess(options);StringWriter out=new StringWriter();
        int code=new InteractiveSession(options,a,root.resolve("reports"),terminal("2\n"+clone+"\nRUN TVU ON COPY\n1\n4\n",out)).run();
        assertEquals(4,code);assertTrue(out.toString().contains("Session complete · UNKNOWN"));
    }
    @Test void mainScreenHidesInternalEnumsAndAnalyzerVersion()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("main"),false);var a=new AssessmentService().assess(f.options(false));String text=AssessmentInsights.header(a)+AssessmentInsights.summary(a);
        assertTrue(text.startsWith("LedgerPreflight 0.1.0"));assertTrue(text.contains("TVU: Not completed"));
        for(String internal:List.of("REQUIRED_OR_UNRESOLVED","Analyzer:","UNVERIFIED","UNKNOWN"))assertFalse(text.contains(internal));
        assertTrue(text.lines().count()<28);
    }
    @Test void readinessListsSpecificPreparationConcerns()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("readiness"),true);String text=AssessmentInsights.tvuReadiness(new AssessmentService().assess(f.options(true)));
        for(String term:List.of("Static preflight: Review required","Target TVU: Found","Target CorDapps: 1","Legacy dependencies: Review required","Mixed-case"))assertTrue(text.contains(term),term);
    }
    @Test void supportResultHasFinalSafetyAndExternalChecksum()throws Exception {
        String out=session(true,"3\n2\n1\n3\n1\n4\n4\n");
        assertTrue(out.contains("Final package rescanned"));assertTrue(out.contains("GENERATED ARTIFACTS"));
        try(var paths=Files.list(root.resolve("reports"))){assertEquals(1,paths.filter(p->p.toString().endsWith(".sha256")).count());}
    }
    @Test void databaseReviewNeverShowsCredentials()throws Exception {
        Path conf=root.resolve("node.conf");Files.writeString(conf,"database.url=\"jdbc:postgresql://person:password@db.example/validation?password=hidden\"\n");
        assertEquals("jdbc:postgresql://db.example/validation",TvuExecution.databaseTarget(conf));
    }
}
