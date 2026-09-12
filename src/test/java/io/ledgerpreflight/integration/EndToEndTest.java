package io.ledgerpreflight.integration;

import io.ledgerpreflight.cli.Main;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

class EndToEndTest {
    @TempDir Path temp;
    @Test void jsonModeIsPureMachineReadableStdout()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp.resolve("inputs"),false);StringWriter output=new StringWriter();var cli=Main.command().setOut(new PrintWriter(output,true)).setErr(new PrintWriter(new StringWriter()));
        assertEquals(1,cli.execute("assess","--node",fixture.node().toString(),"--upgrade-kit",fixture.kit().toString(),"--output",temp.resolve("report").toString(),"--json"));
        assertEquals("READY FOR TVU",Reports.JSON.readTree(output.toString()).get("status").asText());assertFalse(output.toString().contains("Full details:"));assertFalse(output.toString().contains("\u001b"));
    }
    @Test void syntheticHistoricalFailureReplayIsReleaseGate()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,true);var result=new AssessmentService().assess(fixture.options(true));assertEquals("BLOCKED",result.status());assertEquals("4.11.9",result.sourceVersion());assertEquals("4.12.11",result.targetVersion());
        for(String id:List.of("LP-API-001","LP-INTERNAL-001","LP-LEGACY-001","LP-DB-001","LP-TVU-002","LP-JAVA-001","LP-PLATFORM-001"))assertTrue(result.findings().stream().anyMatch(f->f.id().equals(id)),id);
        assertTrue(result.findings().stream().filter(f->f.id().equals("LP-API-001")).flatMap(f->f.technicalEvidence().stream()).anyMatch(e->e.contains(SyntheticFixtureFactory.DESC)));
        assertTrue(result.findings().stream().anyMatch(f->f.id().equals("LP-LEGACY-001")&&f.severity().equals("BLOCKED")));
        var tvu=(TvuAnalyzer.TvuEvidence)result.evidence().get("tvu-summary");assertEquals(650L,tvu.processed());assertEquals(449L,tvu.succeeded());assertEquals(201L,tvu.failed());assertEquals(3,tvu.detailedRecords());assertEquals(List.of(3),new ArrayList<>(tvu.rootCauses().values()));
        assertTrue(tvu.issues().stream().anyMatch(s->s.contains("201 failures reported; 3 detailed")));
    }
    @Test void cleanStaticAssessmentIsOnlyReadyForTvu()throws Exception {var fixture=SyntheticFixtureFactory.create(temp,false);assertEquals("READY FOR TVU",new AssessmentService().assess(fixture.options(false)).status());}
    @Test void completeSuccessfulTvuEnablesFinalReady()throws Exception {var fixture=SyntheticFixtureFactory.create(temp,false);assertEquals("READY TO UPGRADE",new AssessmentService().assess(fixture.options(true)).status());}
    @Test void upgradeKitDiscoveryUsesActualMetadataAndLayout()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,true);var inventory=Discovery.inventory(new BytecodeScanner().scan(fixture.kit()));for(String role:List.of("RUNTIME","TVU","CORDAPP","LEGACY"))assertTrue(inventory.stream().anyMatch(a->a.role().equals(role)),role);
    }
    @Test void assessmentContentIsDeterministic()throws Exception {var fixture=SyntheticFixtureFactory.create(temp,true);var service=new AssessmentService();var first=service.assess(fixture.options(true));var second=service.assess(fixture.options(true));assertEquals(first.status(),second.status());assertEquals(first.findings(),second.findings());assertEquals(first.evidence(),second.evidence());}
    @Test void realCliProducesOfflineHtmlJsonAndSanitizedBundle()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp.resolve("inputs with spaces"),true);Path output=temp.resolve("report");StringWriter stdout=new StringWriter(),stderr=new StringWriter();var cli=Main.command().setOut(new PrintWriter(stdout,true)).setErr(new PrintWriter(stderr,true));
        int code=cli.execute("assess","--node",fixture.node().toString(),"--upgrade-kit",fixture.kit().toString(),"--tvu-results",fixture.log().toString(),"--tvu-results",fixture.errors().toString(),"--verifier-classpath",fixture.classpath().toString(),"--output",output.toString(),"--offline","--support-bundle");assertEquals(2,code,stderr.toString());assertTrue(stdout.toString().contains("BLOCKED"));
        String html=Files.readString(output.resolve("report.html"));assertTrue(html.contains("Content-Security-Policy"));assertFalse(html.contains("<script"));assertFalse(html.contains("SyntheticPasswordOnly42"));assertEquals("BLOCKED",Reports.JSON.readTree(output.resolve("report.json").toFile()).get("status").asText());assertTrue(Files.exists(output.resolve("support.zip")));
        try(ZipFile zip=new ZipFile(output.resolve("support.zip").toFile())){assertNotNull(zip.getEntry("checksums.sha256"));assertNotNull(zip.getEntry("assessment.json"));for(var entries=zip.entries();entries.hasMoreElements();){ZipEntry entry=entries.nextElement();String text=new String(zip.getInputStream(entry).readAllBytes(),StandardCharsets.UTF_8);assertFalse(text.contains("SyntheticPasswordOnly42"),entry.getName());assertFalse(entry.getName().endsWith(".jar"));}}
    }
    @Test void supportBundleNeverCollectsPrivateKeyFilesFromAssessmentDirectory()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp.resolve("inputs"),false);Path reports=temp.resolve("reports");Reports.write(reports,Reports.files(new AssessmentService().assess(fixture.options(false))));for(String name:List.of("secret.jks","secret.pem","secret.key"))Files.writeString(reports.resolve(name),"SYNTHETIC PRIVATE MATERIAL");Path bundle=temp.resolve("safe.zip");assertEquals(0,Main.command().execute("support-bundle","--assessment",reports.toString(),"--output",bundle.toString()));try(ZipFile zip=new ZipFile(bundle.toFile())){assertNull(zip.getEntry("secret.pem"));assertNull(zip.getEntry("secret.key"));assertNull(zip.getEntry("secret.jks"));}
    }
    @Test void unknownRuntimeNeverBecomesReadyWithSuccessfulTvu()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,false);Files.delete(fixture.kit().resolve("corda.jar"));var result=new AssessmentService().assess(fixture.options(true));assertFalse(result.status().startsWith("READY"));
    }
    @Test void truncatedTvuEvidenceCannotEstablishSuccess()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,false);Files.writeString(fixture.log(),"transactions processed: 650\nsucceeded: 650\n");assertFalse(new AssessmentService().assess(fixture.options(true)).status().startsWith("READY"));
    }
    @Test void cliRefusesToWriteWithinNode()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,false);assertEquals(3,Main.command().execute("assess","--node",fixture.node().toString(),"--upgrade-kit",fixture.kit().toString(),"--output",fixture.node().resolve("reports").toString()));assertFalse(Files.exists(fixture.node().resolve("reports")));
    }
    @Test void maliciousJarBlocksReadinessWithoutWritingPayload()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,false);SyntheticFixtureFactory.writeZip(fixture.kit().resolve("evil.jar"),Map.of("../../payload.txt",new byte[]{1}));var result=new AssessmentService().assess(fixture.options(true));assertFalse(result.status().startsWith("READY"));assertFalse(Files.exists(temp.resolve("payload.txt")));
    }
    @Test void changingFutureRuntimeBytesRemovesMissingMemberFinding()throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp,true);SyntheticFixtureFactory.writeZip(fixture.kit().resolve("corda.jar"),Map.of("net/corda/node/Corda.class",SyntheticFixtureFactory.emptyClass("net/corda/node/Corda"),SyntheticFixtureFactory.OWNER+".class",SyntheticFixtureFactory.utility(true),"META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class","net.corda.node.Corda","Corda-Release-Version","4.12.11"))));assertFalse(new AssessmentService().assess(fixture.options(false)).findings().stream().anyMatch(f->f.id().equals("LP-API-001")));
    }
}
