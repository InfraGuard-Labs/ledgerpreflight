package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.GuidedTvuFixtureFactory;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class GuidedTvuCliTest {
    @TempDir Path root;
    @Test void noninteractiveRunRefusesWithoutConfirmationBeforeReadingInputs() {
        StringWriter out=new StringWriter(),err=new StringWriter();var command=Main.command().setOut(new PrintWriter(out)).setErr(new PrintWriter(err));
        int code=command.execute("assess","--node","/missing-node","--upgrade-kit","/missing-kit","--run-tvu","--non-interactive");
        assertEquals(3,code);assertTrue(err.toString().contains("--confirm-isolated-db"));assertTrue(err.toString().contains("No TVU process was started"));assertEquals("",out.toString());
    }
    @Test void automationOptionsAcceptSafeConfigAndSchemaWithoutAPasswordOption() {
        var command=Main.command();command.parseArgs("assess","--node","/node","--upgrade-kit","/kit","--run-tvu","--confirm-isolated-db","--tvu-node-conf","/safe/node.conf","--tvu-schema","ExampleSchema");
        Main.Assess assess=(Main.Assess)command.getSubcommands().get("assess").getCommand();
        assertTrue(assess.runTvu);assertTrue(assess.confirmIsolatedDb);assertEquals(Path.of("/safe/node.conf"),assess.tvuNodeConf);assertEquals("ExampleSchema",assess.tvuSchema);
        assertNull(command.getSubcommands().get("assess").getCommandSpec().findOption("--db-password"));
    }
    @Test void staticCliNeverExecutesTvuEvenWhenAnIsolationFlagIsPresent()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);StringWriter out=new StringWriter(),err=new StringWriter();
        int code=Main.command().setOut(new PrintWriter(out)).setErr(new PrintWriter(err)).execute("assess","--node",fixture.assessment().node().toString(),"--upgrade-kit",fixture.assessment().kit().toString(),"--host-environment",root.resolve("host.json").toString(),"--network-mode","all-4.12","--output",fixture.reports().toString(),"--confirm-isolated-db","--json");
        assertEquals(1,code,err.toString());assertEquals("READY FOR TVU",Reports.JSON.readTree(out.toString()).path("status").asText());
        assertFalse(Files.exists(fixture.control().resolve("started.pid")));assertFalse(Files.exists(fixture.reports().resolve("tvu")));
    }
    @Test void unknownProgressNeverInventsATransactionTotalOrRepeatsRawNoise() {
        String text=AssessmentInsights.guidedProgress(new GuidedTvuExecution.Progress(null,null,null,null,3,"External verifier process started PID 123"));
        assertTrue(text.contains("Not yet reported"));assertFalse(text.contains(" / "));assertFalse(text.contains("PID"));assertFalse(text.contains("External verifier"));
    }
    @Test void observedProgressShowsOnlyActualCountersAndElapsedTime() {
        String text=AssessmentInsights.guidedProgress(new GuidedTvuExecution.Progress(650L,72L,54L,18L,271,"IN_PROGRESS"));
        assertTrue(text.contains("72 / 650"));assertTrue(text.contains("18"));assertTrue(text.contains("00:04:31"));assertFalse(text.contains("IN_PROGRESS"));
    }
    @Test void progressCancellationRestoresRawTerminalAndCursor()throws Exception {
        StringWriter writer=new StringWriter();List<String> modes=new ArrayList<>();
        SessionTerminal terminal=new SessionTerminal(new StringReader("q"),new PrintWriter(writer),true,70){@Override protected String terminalMode(String... args){modes.add(String.join(" ",args));return "saved-mode";}};
        try(var progress=terminal.progress()){progress.show("Running TVU");assertTrue(progress.cancelled());}
        assertTrue(modes.contains("-icanon -echo min 0 time 1"));assertEquals("saved-mode",modes.get(modes.size()-1));
        String output=writer.toString();assertTrue(output.lastIndexOf("\u001b[?25h")>output.lastIndexOf("\u001b[?25l"));
    }
    @Test void plainProgressStaysReadableWithoutCursorControls()throws Exception {
        StringWriter writer=new StringWriter();SessionTerminal terminal=new SessionTerminal(new StringReader("q\n"),new PrintWriter(writer),false,50);
        try(var progress=terminal.progress()){progress.show(AssessmentInsights.guidedProgress(new GuidedTvuExecution.Progress(null,7L,null,1L,2,"IN_PROGRESS")));assertTrue(progress.cancelled());}
        assertFalse(writer.toString().contains("\u001b["));assertTrue(writer.toString().contains("7"));assertTrue(writer.toString().contains("q cancels"));
    }
    @Test void decliningIsolationConfirmationCreatesNoTvuWorkspaceOrProcess()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);var assessment=new AssessmentService().assess(fixture.options());
        var terminal=new ScriptedTerminal(List.of("Run TVU safely","Cancel","Exit"),List.of());
        new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run();
        assertFalse(Files.exists(fixture.control().resolve("started.pid")));assertFalse(Files.exists(fixture.reports().resolve("tvu")));
        assertTrue(terminal.text().contains("Is this an isolated / non-production database copy?"));terminal.assertComplete();
    }
    @Test void alternateConfigurationRequiresANewAffirmativeConfirmation()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);Path alternate=root.resolve("isolated-node.conf");
        Files.writeString(alternate,Files.readString(fixture.assessment().node().resolve("node.conf")).replace("database.example/isolated_copy","validation.example/safe_copy"));
        var assessment=new AssessmentService().assess(fixture.options());
        var terminal=new ScriptedTerminal(List.of("Run TVU safely","Use a different safe node configuration","Yes, run TVU","Exit"),List.of(alternate.toString()));
        int code=new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run();
        assertEquals(0,code);assertTrue(Files.exists(fixture.control().resolve("started.pid")));assertTrue(terminal.text().contains("READY TO UPGRADE"));
        try(var files=Files.walk(fixture.reports())){Path run=files.filter(path->path.getFileName().toString().equals("tvu-run.json")).findFirst().orElseThrow();var proof=Reports.JSON.readTree(Files.readString(run));assertEquals("jdbc:postgresql://validation.example/safe_copy",proof.path("databaseTarget").asText());assertEquals("explicit alternate",proof.path("configurationSource").asText());assertTrue(proof.path("sanitizedConfigurationSha256").asText().matches("[0-9a-f]{64}"));}
        assertEquals(2,terminal.confirmationScreens);assertFalse(terminal.text().contains(GuidedTvuFixtureFactory.SECRET));terminal.assertComplete();
    }
    @Test void failedGuidedRunAutomaticallyImportsZipAndCorrelatesAllFailures()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"failed",true);var assessment=new AssessmentService().assess(fixture.options());
        var terminal=new ScriptedTerminal(List.of("Run TVU safely","Yes, run TVU","Exit"),List.of());
        assertEquals(2,new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run());
        String text=terminal.text();assertTrue(text.contains("2 blockers"));assertTrue(text.contains("650 processed"));assertTrue(text.contains("449 passed"));assertTrue(text.contains("201 failed"));assertTrue(text.contains("201 supplied failures match"));
        assertFalse(text.contains("External verifier process started"));assertFalse(text.contains("--tvu-results"));assertFalse(text.contains(GuidedTvuFixtureFactory.SECRET));terminal.assertComplete();
    }
    @Test void anotherGuidedRunCanExecuteFromTheSameAssessmentSession()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);var assessment=new AssessmentService().assess(fixture.options());
        var terminal=new ScriptedTerminal(List.of("Run TVU safely","Yes, run TVU","Run TVU again","Yes, run TVU","Exit"),List.of());
        assertEquals(0,new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run());
        try(var paths=Files.walk(fixture.reports())){assertEquals(2,paths.filter(p->p.getFileName().toString().equals("run-manifest.json")).count());}
        assertEquals(2,terminal.confirmationScreens);terminal.assertComplete();
    }
    @Test void supportActionCollectsGuidedRunEvidenceWithoutManualFileGathering()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"failed",true);var assessment=new AssessmentService().assess(fixture.options());
        var terminal=new ScriptedTerminal(List.of("Run TVU safely","Yes, run TVU","Create R3 support package","Back","Exit"),List.of());
        assertEquals(2,new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run());
        assertTrue(terminal.text().contains("READY TO SHARE"));
        try(var files=Files.walk(fixture.reports())){Path bundle=files.filter(p->p.getFileName().toString().contains("R3-support")&&p.toString().endsWith(".zip")).findFirst().orElseThrow();
            try(var zip=new java.util.zip.ZipFile(bundle.toFile())){assertNotNull(zip.getEntry("tvu-run.json"));assertNotNull(zip.getEntry("tvu-schema-execution.json"));assertNotNull(zip.getEntry("required-symbol-resolution.json"));assertNotNull(zip.getEntry("checksums.sha256"));}
        }
        assertFalse(terminal.text().contains(GuidedTvuFixtureFactory.SECRET));terminal.assertComplete();
    }
    @Test void interactiveImportAcceptsLogAndZipAndUpdatesTheCurrentResult()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"failed",true);var assessment=new AssessmentService().assess(fixture.options());
        var terminal=new ScriptedTerminal(List.of("Import existing TVU results","Add another file from the same run","Analyze this run","Exit"),List.of(fixture.assessment().log().toString(),fixture.assessment().errors().toString()));
        assertEquals(2,new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run());
        assertTrue(terminal.text().contains("650 processed"));assertTrue(terminal.text().contains("201 supplied failures match"));assertFalse(Files.exists(fixture.control().resolve("started.pid")));terminal.assertComplete();
    }
    @Test void confirmedNoninteractiveRunEmitsOneFinalJsonAssessment()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);StringWriter out=new StringWriter(),err=new StringWriter();
        int code=Main.command().setOut(new PrintWriter(out)).setErr(new PrintWriter(err)).execute("assess","--node",fixture.assessment().node().toString(),"--upgrade-kit",fixture.assessment().kit().toString(),"--host-environment",root.resolve("host.json").toString(),"--network-mode","all-4.12","--output",fixture.reports().toString(),"--run-tvu","--confirm-isolated-db","--json");
        assertEquals(0,code,err.toString());var json=Reports.JSON.readTree(out.toString());assertEquals("READY TO UPGRADE",json.path("status").asText());assertTrue(json.path("evidence").has("tvu-run"));
        assertFalse(out.toString().contains("\u001b["));assertFalse(out.toString().contains(GuidedTvuFixtureFactory.SECRET));assertFalse(err.toString().contains(GuidedTvuFixtureFactory.SECRET));
    }
    @Test void completeCountersCannotOverrideFinalCaptureOrCleanupFailure()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);Path log=root.resolve("complete.log");
        Files.writeString(log,"HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema=\"ExampleSchema\"}\ntotal: 650\nprocessed: 650\npassed: 650\nfailed: 0\n");
        var outcome=new GuidedTvuExecution.Outcome(List.of(log),Map.of("failureKind","EXECUTION_FAILURE","exitCode",0,"workspaceCleaned",false),0,"NONE",false,true);
        var assessment=InteractiveSession.assessGuided(InteractiveSession.withTvu(fixture.options(),List.of(log)),outcome);
        assertNotEquals("READY TO UPGRADE",assessment.status());assertTrue(assessment.findings().stream().anyMatch(f->f.id().equals("LP-TVU-EXEC")));
        assertNotEquals("PASS",((Map<?,?>)assessment.gates()).get("tvu"));
    }
    @Test void cliSupportCreatesVerifiedChecksumAndRefusesExistingChecksum()throws Exception {
        Path evidence=root.resolve("evidence");Files.createDirectories(evidence);Files.writeString(evidence.resolve("assessment.json"),"{\"status\":\"UNKNOWN\"}");
        Path zip=root.resolve("support.zip");StringWriter out=new StringWriter(),err=new StringWriter();
        int code=Main.command().setOut(new PrintWriter(out)).setErr(new PrintWriter(err)).execute("support-bundle","--assessment",evidence.toString(),"--output",zip.toString());
        assertEquals(0,code,err.toString());Path checksum=root.resolve("support.zip.sha256");assertEquals(GuidedTvuExecution.hash(zip)+"  support.zip\n",Files.readString(checksum));assertTrue(out.toString().contains(checksum.toString()));
        Path collision=root.resolve("collision.zip"),existing=root.resolve("collision.zip.sha256");Files.writeString(existing,"existing checksum");
        assertThrows(IOException.class,()->Main.createSupportPackage(collision,Map.of("assessment.json","{}")));assertFalse(Files.exists(collision));assertEquals("existing checksum",Files.readString(existing));
        Path unsafe=root.resolve("unsafe.zip");assertThrows(IOException.class,()->Main.createSupportPackage(unsafe,Map.of("raw-node.conf","password=secret")));assertFalse(Files.exists(unsafe));assertFalse(Files.exists(root.resolve("unsafe.zip.sha256")));
    }
    @Test void ambiguousSchemaSelectionPrecedesDatabaseConfirmationAndCanBeCancelled()throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(root,"success",false);Path config=fixture.assessment().node().resolve("node.conf");Files.writeString(config,Files.readString(config).replace("currentSchema=ExampleSchema","currentSchema=OtherSchema"));
        var assessment=new AssessmentService().assess(fixture.options());var terminal=new ScriptedTerminal(List.of("Run TVU safely","ExampleSchema","Cancel","Exit"),List.of());
        new InteractiveSession(fixture.options(),assessment,fixture.reports(),terminal).run();
        assertTrue(terminal.text().contains("TVU SCHEMA"));assertEquals(1,terminal.confirmationScreens);assertFalse(Files.exists(fixture.control().resolve("started.pid")));terminal.assertComplete();
    }
    private static final class ScriptedTerminal extends SessionTerminal {
        private final StringWriter writer;private final ArrayDeque<String> choices,answers;int confirmationScreens;
        ScriptedTerminal(List<String> choices,List<String> answers){this(new StringWriter(),choices,answers);}
        private ScriptedTerminal(StringWriter writer,List<String> choices,List<String> answers){super(new StringReader(""),new PrintWriter(writer),false,100);this.writer=writer;this.choices=new ArrayDeque<>(choices);this.answers=new ArrayDeque<>(answers);}
        @Override public int choose(String title,List<String> labels){text(title);if(title.startsWith("Is this an isolated"))confirmationScreens++;assertFalse(choices.isEmpty(),"Unexpected menu: "+labels);String requested=choices.removeFirst();int selected=labels.indexOf(requested);assertTrue(selected>=0,"Missing action "+requested+" in "+labels);return selected;}
        @Override public String ask(String prompt){text(prompt);assertFalse(answers.isEmpty(),"Unexpected prompt: "+prompt);return answers.removeFirst();}
        String text(){return writer.toString();}
        void assertComplete(){assertTrue(choices.isEmpty(),choices.toString());assertTrue(answers.isEmpty(),answers.toString());}
    }
}
