package io.ledgerpreflight.integration;

import io.ledgerpreflight.cli.*;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Independent safety boundaries around a real, original synthetic TVU subprocess. */
class IndependentGuidedTvuSafetyTest {
    @TempDir Path root;
    private static GuidedTvuExecution.Plan inspect(GuidedTvuFixtureFactory.Fixture f)throws Exception {
        return GuidedTvuExecution.inspect(f.options(),new AssessmentService().assess(f.options()),null,null,f.reports());
    }
    private static Properties observed(GuidedTvuFixtureFactory.Fixture f)throws IOException {
        Properties result=new Properties();try(InputStream in=Files.newInputStream(f.control().resolve("observed.properties"))){result.load(in);}return result;
    }
    private static Assessment reassess(GuidedTvuFixtureFactory.Fixture f,List<Path> paths)throws Exception {
        var o=f.options();return new AssessmentService().assess(new AssessmentService.Options(o.node(),o.kit(),o.targetCorda(),o.tvuJar(),o.targetCordapps(),o.legacyJars(),o.nodeConf(),paths,o.verifierClasspath(),o.rulePack(),o.networkMode(),o.hostEnvironment(),o.currentRuntime()));
    }
    @Test void staticAssessmentAndInspectionNeverStartProcessOrPrepareWorkspace()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);var node=GuidedTvuFixtureFactory.hashes(f.assessment().node());var kit=GuidedTvuFixtureFactory.hashes(f.assessment().kit());
        var plan=inspect(f);assertFalse(Files.exists(f.control().resolve("started.pid")));assertFalse(Files.exists(plan.workspace()));assertFalse(Files.exists(plan.capture()));
        assertEquals(node,GuidedTvuFixtureFactory.hashes(f.assessment().node()));assertEquals(kit,GuidedTvuFixtureFactory.hashes(f.assessment().kit()));assertFalse(String.join(" ",plan.command()).contains(GuidedTvuFixtureFactory.SECRET));
    }
    @Test void unconfirmedDatabaseNamedIsolatedCopyStillCannotStart()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);var plan=inspect(f);
        assertThrows(IOException.class,()->GuidedTvuExecution.run(plan,false,30,p->{},()->false));
        assertFalse(Files.exists(f.control().resolve("started.pid")));assertFalse(Files.exists(plan.workspace()));assertFalse(Files.exists(plan.capture()));
    }
    @Test void confirmedRunPreparesPrivateInputsLoadsSchemaAndCleansWorkspace()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);var node=GuidedTvuFixtureFactory.hashes(f.assessment().node());var kit=GuidedTvuFixtureFactory.hashes(f.assessment().kit());var plan=inspect(f);
        var progress=new CopyOnWriteArrayList<GuidedTvuExecution.Progress>();var result=GuidedTvuExecution.run(plan,true,30,progress::add,()->false);
        assertEquals(0,result.exitCode());assertFalse(result.cancelled());assertTrue(result.schemaApplied());assertTrue(result.evidencePaths().stream().allMatch(Files::isRegularFile));assertFalse(Files.exists(plan.workspace()));
        var observed=observed(f);assertEquals("rwx------",observed.getProperty("workspaceMode"));assertEquals("rw-------",observed.getProperty("configMode"));assertEquals("\"ExampleSchema\"",observed.getProperty("loadedSchema"));
        assertTrue(observed.getProperty("javaVersion").startsWith("17."));
        assertTrue(observed.getProperty("workspaceFiles").contains("cordapps/example-new-contract.jar"));assertTrue(observed.getProperty("workspaceFiles").contains("cordapps/example-new-workflow.jar"));
        assertFalse(observed.getProperty("arguments").contains(GuidedTvuFixtureFactory.SECRET));assertFalse(observed.getProperty("jvmArguments").contains(GuidedTvuFixtureFactory.SECRET));
        assertTrue(progress.stream().anyMatch(p->Objects.equals(p.processed(),650L)));assertTrue(progress.stream().noneMatch(p->p.status().contains("External verifier process started")));
        assertEquals(node,GuidedTvuFixtureFactory.hashes(f.assessment().node()));assertEquals(kit,GuidedTvuFixtureFactory.hashes(f.assessment().kit()));
        assertTrue(TvuSchemaEvidence.analyze(result.evidencePaths(),"ExampleSchema").handled());assertEquals("READY TO UPGRADE",reassess(f,result.evidencePaths()).status());
    }
    @Test void compatibleAlternateConfigurationCanBeUsedWithoutChangingIt()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);Path conf=root.resolve("safe/node.conf");Files.createDirectories(conf.getParent());Files.writeString(conf,Files.readString(f.assessment().node().resolve("node.conf")).replace("isolated_copy","alternate_copy"));
        var before=GuidedTvuFixtureFactory.hashes(conf.getParent());var plan=GuidedTvuExecution.inspect(f.options(),new AssessmentService().assess(f.options()),conf,null,f.reports());
        var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);assertEquals(0,result.exitCode());assertEquals("true",observed(f).getProperty("alternateSelected"));assertEquals(before,GuidedTvuFixtureFactory.hashes(conf.getParent()));assertFalse(Files.exists(plan.workspace()));
        assertEquals("jdbc:postgresql://database.example/alternate_copy",result.manifest().get("databaseTarget"));assertEquals("explicit alternate",result.manifest().get("configurationSource"));
        assertTrue(Objects.toString(result.manifest().get("sanitizedConfigurationSha256")).matches("[a-f0-9]{64}"));assertNotEquals(before.get("node.conf"),result.manifest().get("sanitizedConfigurationSha256"));
        String exported=Reports.json(result.manifest());assertFalse(exported.contains(GuidedTvuFixtureFactory.SECRET));assertFalse(exported.contains(conf.toString()));
    }
    @Test void incompatibleAlternateVendorIdentityOrSchemaStopsBeforeExecution()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);var a=new AssessmentService().assess(f.options());String original=Files.readString(f.assessment().node().resolve("node.conf"));
        for(String modified:List.of(original.replace("jdbc:postgresql:","jdbc:oracle:"),original.replace("CN=ExampleIssuer","CN=DifferentIssuer"),original.replace("currentSchema=ExampleSchema","currentSchema=OtherSchema"))){
            Path conf=root.resolve("alternate/node.conf");Files.createDirectories(conf.getParent());Files.writeString(conf,modified);assertThrows(IOException.class,()->GuidedTvuExecution.inspect(f.options(),a,conf,null,f.reports()));
        }
        assertFalse(Files.exists(f.control().resolve("started.pid")));
    }
    @Test void emittedCredentialIsRedactedFromAllPreservedTextAndProgress()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"secrets",false);var plan=inspect(f);var progress=new CopyOnWriteArrayList<GuidedTvuExecution.Progress>();var result=GuidedTvuExecution.run(plan,true,30,progress::add,()->false);
        assertEquals(0,result.exitCode());assertTrue(Files.exists(f.control().resolve("secret-emitted.txt")));assertFalse(Reports.json(result.manifest()).contains(GuidedTvuFixtureFactory.SECRET));assertFalse(Reports.json(progress).contains(GuidedTvuFixtureFactory.SECRET));
        try(var files=Files.walk(f.reports())){for(Path path:files.filter(Files::isRegularFile).toList())if(!path.toString().endsWith(".zip"))assertFalse(Files.readString(path).contains(GuidedTvuFixtureFactory.SECRET),path.getFileName().toString());}
        assertFalse(Files.exists(plan.workspace()));
    }
    @Test void actualErrorZipAndLogsAreDiscoveredAndAll201FailuresCorrelate()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"failed",true);var plan=inspect(f);var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);
        assertTrue(result.evidencePaths().stream().anyMatch(p->p.toString().endsWith(".zip")));var a=reassess(f,result.evidencePaths());var tvu=(TvuAnalyzer.TvuEvidence)a.evidence().get("tvu-summary");
        assertEquals(650L,tvu.processed());assertEquals(449L,tvu.succeeded());assertEquals(201L,tvu.failed());assertEquals(201,tvu.detailedRecords());assertEquals("201 supplied failures match the compatibility problem.",ProductView.correlation(a,tvu));
        assertEquals("BLOCKED",a.status());assertEquals(List.of("CorDapp compatibility","TVU validation"),ProductView.issues(a).stream().filter(ProductView.Issue::blocking).map(ProductView.Issue::title).toList());
        assertTrue(TvuSchemaEvidence.analyze(result.evidencePaths(),"ExampleSchema").handled());assertFalse(Files.exists(plan.workspace()));
        var support=new SupportBundle().create(root.resolve("support.zip"),Main.bundleFiles(Reports.files(a)));assertTrue(Files.size(support)>0);
    }
    @Test void realSchemaFailureOverridesSuccessfullyLoadedConfiguration()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"schemafail",false);var result=GuidedTvuExecution.run(inspect(f),true,30,p->{},()->false);var a=reassess(f,result.evidencePaths());
        assertEquals("BLOCKED",a.status());assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-DB-003")&&x.severity().equals("BLOCKED")));
        assertFalse(TvuSchemaEvidence.analyze(result.evidencePaths(),"ExampleSchema").handled());
    }
    @Test void aSecondApprovedRunUsesNewEvidenceAndNoStaleWorkspace()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);var first=inspect(f);var one=GuidedTvuExecution.run(first,true,30,p->{},()->false);var second=inspect(f);var two=GuidedTvuExecution.run(second,true,30,p->{},()->false);
        assertNotEquals(first.capture(),second.capture());assertNotEquals(first.workspace(),second.workspace());assertTrue(Collections.disjoint(one.evidencePaths(),two.evidencePaths()));assertFalse(Files.exists(first.workspace()));assertFalse(Files.exists(second.workspace()));
    }
    @Test void databaseConnectionAndEarlyExecutionFailuresHaveDistinctOutcomes()throws Exception {
        List<String> kinds=new ArrayList<>();for(String mode:List.of("dbfail","abort")){
            var f=GuidedTvuFixtureFactory.create(root.resolve(mode),mode,false);var plan=inspect(f);var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);kinds.add(result.failureKind());assertNotEquals(0,result.exitCode());assertFalse(Files.exists(plan.workspace()));
        }
        assertEquals("DATABASE_CONNECTION_FAILURE",kinds.get(0));assertEquals("EXECUTION_FAILURE",kinds.get(1));
    }
    @Test void changedTargetArtifactCannotRunAfterApprovalOfItsPreviousBytes()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);var plan=inspect(f);Files.write(f.validator(),new byte[]{0,1,2});
        var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);assertEquals("SETUP_FAILURE",result.failureKind());assertFalse(Files.exists(f.control().resolve("started.pid")));assertFalse(Files.exists(plan.workspace()));
    }
    @Test void requiredCurrentJdbcDriverIsNotHiddenByUnrelatedTargetDriver()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"driver",false);var result=GuidedTvuExecution.run(inspect(f),true,30,p->{},()->false);
        assertEquals(0,result.exitCode());assertEquals("NONE",result.failureKind());assertTrue(observed(f).getProperty("workspaceFiles").contains("drivers/database-driver.jar"));
    }
    @Test void diagnosticTextSurvivesMixedBinaryAndTextTvuErrorArchive()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"mixedZip",true);var result=GuidedTvuExecution.run(inspect(f),true,30,p->{},()->false);var a=reassess(f,result.evidencePaths());var tvu=(TvuAnalyzer.TvuEvidence)a.evidence().get("tvu-summary");
        assertEquals(650L,tvu.processed());assertEquals(449L,tvu.succeeded());assertEquals(201L,tvu.failed());assertEquals(201,tvu.detailedRecords());assertEquals("201 supplied failures match the compatibility problem.",ProductView.correlation(a,tvu));
        for(Path path:result.evidencePaths())if(path.toString().endsWith(".zip"))try(var zip=new java.util.zip.ZipFile(path.toFile())){assertNull(zip.getEntry("transactions/failed-transaction.bin"));long records=0;for(var entry:Collections.list(zip.entries()))try(var in=zip.getInputStream(entry)){if(new String(in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8).contains("java.lang.NoSuchMethodError"))records++;}assertEquals(201,records);}
    }
    @Test void generatedValidatorLogAloneSuppliesActualFinalTotals()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"fileLog",false);var result=GuidedTvuExecution.run(inspect(f),true,30,p->{},()->false);var a=reassess(f,result.evidencePaths());var tvu=(TvuAnalyzer.TvuEvidence)a.evidence().get("tvu-summary");
        assertEquals(0,result.exitCode());assertEquals("NONE",result.failureKind());assertEquals(650L,tvu.processed());assertEquals(650L,tvu.succeeded());assertEquals(0L,tvu.failed());assertEquals("READY TO UPGRADE",a.status());
    }
    @Test void explicitSafeAlternateDoesNotRequireProductionCredentialResolution()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"success",false);Path original=f.assessment().node().resolve("node.conf"),alternate=root.resolve("safe/node.conf");Files.createDirectories(alternate.getParent());String source=Files.readString(original);
        Files.writeString(alternate,source.replace("isolated_copy","alternate_copy"));Files.writeString(original,source.replace("\""+GuidedTvuFixtureFactory.SECRET+"\"","${UNSET_SYNTHETIC_PRODUCTION_PASSWORD}"));var before=GuidedTvuFixtureFactory.hashes(f.assessment().node());
        var plan=GuidedTvuExecution.inspect(f.options(),new AssessmentService().assess(f.options()),alternate,null,f.reports());var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);
        assertEquals(0,result.exitCode());assertEquals("true",observed(f).getProperty("alternateSelected"));assertEquals(before,GuidedTvuFixtureFactory.hashes(f.assessment().node()));assertFalse(Files.exists(plan.workspace()));
    }
    @Test void unsafeGeneratedArchiveCannotEscapeOrSupplySuccessfulEvidence()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"unsafeZip",false);var plan=inspect(f);var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);
        assertEquals("EXECUTION_FAILURE",result.failureKind());assertFalse(Files.exists(plan.workspace()));assertFalse(result.evidencePaths().stream().anyMatch(p->p.toString().endsWith(".zip")));assertNotEquals("READY TO UPGRADE",reassess(f,result.evidencePaths()).status());
        try(var files=Files.walk(root)){assertFalse(files.anyMatch(path->path.getFileName().toString().equals("escape.txt")));}
    }
    @Test void corruptGeneratedArchiveCannotBeReencodedAsTrustedEvidence()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"corruptZip",false);var plan=inspect(f);var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);
        assertEquals("EXECUTION_FAILURE",result.failureKind());assertFalse(Files.exists(plan.workspace()));assertFalse(result.evidencePaths().stream().anyMatch(p->p.toString().endsWith(".zip")));assertNotEquals("READY TO UPGRADE",reassess(f,result.evidencePaths()).status());
    }
    @Test void conflictingGeneratedSummaryCannotLeaveSuccessfulRunManifest()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"fileConflict",false);var result=GuidedTvuExecution.run(inspect(f),true,30,p->{},()->false);
        assertNotEquals("NONE",result.failureKind());assertNotEquals("NONE",result.manifest().get("failureKind"));assertNotEquals("READY TO UPGRADE",reassess(f,result.evidencePaths()).status());
    }
    private GuidedTvuFixtureFactory.Fixture legacyFixture()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"failed",true);
        SyntheticFixtureFactory.writeZip(f.assessment().kit().resolve("legacy-jars/retained-compatibility.jar"),Map.of(RequiredCompatibilityIntegrationTest.OWNER+".class",RequiredCompatibilityIntegrationTest.api(false,true,false)));
        Files.writeString(f.assessment().classpath(),"java -cp tools/external-verifier.jar:legacy-jars/retained-compatibility.jar net.corda.verifier.Main\n");return f;
    }
    @Test void approvedExecutionCopiesSuppliedLegacyJarsWithoutChangingThem()throws Exception {
        var f=legacyFixture();var before=GuidedTvuFixtureFactory.hashes(f.assessment().kit());var plan=inspect(f);var result=GuidedTvuExecution.run(plan,true,30,p->{},()->false);
        assertTrue(observed(f).getProperty("workspaceFiles").contains("legacy-jars/retained-compatibility.jar"));assertTrue(result.manifest().get("artifacts").toString().contains("retained-compatibility.jar"));assertEquals(before,GuidedTvuFixtureFactory.hashes(f.assessment().kit()));assertFalse(Files.exists(plan.workspace()));
    }
    @Test void confirmedLegacyShadowingRemainsAnExplicitGuidedRunWarning()throws Exception {
        var f=legacyFixture();var assessment=new AssessmentService().assess(f.options());assertTrue(assessment.findings().stream().anyMatch(finding->finding.category().equals("LEGACY_JARS")&&finding.severity().equals("BLOCKED")));
        var plan=GuidedTvuExecution.inspect(f.options(),assessment,null,null,f.reports());assertTrue(plan.warnings().stream().anyMatch(warning->warning.contains("shadowed")));assertFalse(Files.exists(f.control().resolve("started.pid")));
    }
}
