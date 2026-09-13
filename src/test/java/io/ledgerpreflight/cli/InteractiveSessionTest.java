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
        var pending=new Assessment("1","0.1.0","READY FOR TVU","4.11","4.12",List.of(),Map.of());
        var complete=new Assessment("1","0.1.0","READY TO UPGRADE","4.11","4.12",List.of(),Map.of("tvu-evidence-supplied",true));
        assertEquals(List.of("TVU instructions","Export full technical report","Create R3 support package","Run again","Exit"),InteractiveSession.actions(pending).stream().map(a->a.label).toList());
        assertEquals(List.of("View TVU evidence","Export full technical report","Create R3 support package","Run again","Exit"),InteractiveSession.actions(complete).stream().map(a->a.label).toList());
    }
    @Test void eofExitsWithoutLooping()throws Exception {assertTrue(session(true,"").contains("Session complete · NOT READY TO UPGRADE"));}
    @Test void resultExplainsGroupedProblemsWithoutNestedTroubleshootingMenus()throws Exception {
        String out=session(true,"q\n");
        for(String term:List.of("WHAT HAPPENED","WHY IT MATTERS","WHAT TO DO","NEXT STEP","CorDapp compatibility","TVU validation"))assertTrue(out.contains(term),term);
        for(String term:List.of("Understand the blockers","Explain blockers","Show resolution plan","Confidence:","JVM descriptor"))assertFalse(out.contains(term),term);
    }
    @Test void evidenceIsAvailableOnDemand()throws Exception {
        String out=session(true,"1\n1\nq\n");assertTrue(out.contains("COMPATIBILITY EVIDENCE"));assertTrue(out.contains("InternalUtils.sum(Iterable)"));assertFalse(out.contains("technicalEvidence"));
    }
    @Test void reportActionWritesCompleteTextHtmlJson()throws Exception {
        assertTrue(session(true,"4\n1\nq\n").contains("Technical report exported"));
        for(String name:List.of("report.html","report.json","technical-assessment.txt"))assertTrue(Files.size(root.resolve("reports").resolve(name))>100);
    }
    @Test void supportActionCreatesValidatedZip()throws Exception {
        assertTrue(session(true,"5\n1\nq\n").contains("READY TO SHARE"));
        try(var paths=Files.list(root.resolve("reports"))){assertEquals(1,paths.filter(p->p.toString().endsWith(".zip")).count());}
    }
    @Test void runAgainProducesFreshAssessment()throws Exception {
        assertTrue(session(true,"6\nq\n").contains("Assessment updated"));
        try(var paths=Files.list(root.resolve("reports"))){assertTrue(paths.anyMatch(p->p.getFileName().toString().startsWith("reassessment-")));}
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
        String header=AssessmentInsights.header(new AssessmentService().assess(fixture.options(false)));assertTrue(header.contains("O=Example"));assertFalse(header.contains("Analyzer:"));assertTrue(header.contains("CorDapp JARs:"));assertTrue(header.contains("PostgreSQL"));
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
        int code=new InteractiveSession(options,a,root.resolve("reports"),terminal("1\n1\n"+fixture.log()+"\n1\n1\nq\n",out)).run();
        assertEquals(0,code);assertTrue(out.toString().contains("Session complete · READY TO UPGRADE"));
    }
    private Path cloneFor(SyntheticFixtureFactory.Fixture fixture)throws IOException {
        Path clone=root.resolve("isolated-copy");Files.createDirectories(clone.resolve("cordapps"));
        Files.writeString(clone.resolve("node.conf"),Files.readString(fixture.node().resolve("node.conf")).replace("synthetic.invalid/example","disposable.invalid/validation"));return clone;
    }
    @Test void cancelledExecutionWritesNoCapture()throws Exception {
        var fixture=SyntheticFixtureFactory.create(root.resolve("cancel"),false);Path clone=cloneFor(fixture);var options=fixture.options(false);var a=new AssessmentService().assess(options);StringWriter out=new StringWriter();
        new InteractiveSession(options,a,root.resolve("reports"),terminal("1\n2\n"+clone+"\nNO\n1\nq\n",out)).run();
        assertTrue(out.toString().contains("TVU execution cancelled"));try(var paths=Files.list(root.resolve("reports"))){assertFalse(paths.anyMatch(p->p.getFileName().toString().startsWith("tvu-run")));}
    }
    @Test void failedApprovedTvuNeverReturnsReady()throws Exception {
        // The synthetic TVU has no executable main: launch must fail, never fabricate success.
        var fixture=SyntheticFixtureFactory.create(root.resolve("failed"),false);Path clone=cloneFor(fixture);var options=fixture.options(false);var a=new AssessmentService().assess(options);StringWriter out=new StringWriter();
        int code=new InteractiveSession(options,a,root.resolve("reports"),terminal("1\n2\n"+clone+"\nRUN TVU ON COPY\n1\nq\n",out)).run();
        assertEquals(4,code);assertTrue(out.toString().contains("Session complete · NOT READY TO UPGRADE"));
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
        String out=session(true,"5\n1\nq\n");
        assertTrue(out.contains("Final package rescanned"));assertTrue(out.contains("Checksum file:"));
        try(var paths=Files.list(root.resolve("reports"))){assertEquals(1,paths.filter(p->p.toString().endsWith(".sha256")).count());}
    }
    @Test void databaseReviewNeverShowsCredentials()throws Exception {
        Path conf=root.resolve("node.conf");Files.writeString(conf,"database.url=\"jdbc:postgresql://person:password@db.example/validation?password=hidden\"\n");
        assertEquals("jdbc:postgresql://db.example/validation",TvuExecution.databaseTarget(conf));
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"dataSourceProperties.dataSource.url","dataSourceProperties.\"dataSource.url\"","database.url","dataSource.url","\"dataSource.url\""})
    void guidedTvuRecognizesEverySupportedExplicitJdbcKey(String key)throws Exception {
        Path conf=root.resolve("node.conf");Files.writeString(conf,key+"=\"jdbc:postgresql://db.example/validation\"\n");
        assertEquals("jdbc:postgresql://db.example/validation",TvuExecution.databaseTarget(conf));
    }
    @Test void guidedTvuRejectsConflictingConnectionDeclarations()throws Exception {
        Path conf=root.resolve("node.conf");Files.writeString(conf,"database.url=\"jdbc:postgresql://db.example/one\"\ndataSource.url=\"jdbc:postgresql://db.example/two\"\n");
        assertTrue(assertThrows(IOException.class,()->TvuExecution.databaseTarget(conf)).getMessage().contains("conflict"));
    }
}
