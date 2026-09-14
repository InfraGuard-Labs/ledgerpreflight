package io.ledgerpreflight.integration;

import io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.cli.Main;
import io.ledgerpreflight.evidence.SupportBundle;
import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import io.ledgerpreflight.reporting.Reports;
import java.nio.file.*;
import java.util.*;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Final synthetic acceptance ties exact required proof to displayed blocker counts. */
class BlockerVerifierIntegrationTest {
    @TempDir Path root;
    private static Assessment assess(SyntheticFixtureFactory.Fixture f,boolean tvu)throws Exception{return new AssessmentService().assess(ProductAcceptanceFixture.options(f,tvu));}
    static SymbolResult ordinary(Assessment a)throws Exception{
        for(var item:Reports.JSON.valueToTree(a.evidence().get("required-symbol-resolution")).path("symbols"))if(item.path("symbol").path("owner").asText().equals(BlockerVerifierFixtureFactory.CLASS_OWNER)&&item.path("symbol").path("kind").asText().equals("CLASS"))return Reports.JSON.treeToValue(item,SymbolResult.class);
        throw new AssertionError("Required ordinary CLASS proof was not exported");
    }
    private static void resolved(Assessment a)throws Exception{
        var p=ordinary(a);assertEquals(Resolution.COMPATIBLE,p.resolution());assertEquals(3,p.contexts().size());
        for(var c:p.contexts()){assertEquals(Resolution.COMPATIBLE,c.resolution());assertEquals("found",c.proof().classStatus());assertEquals("not-applicable",c.proof().memberStatus());}
        assertEquals(Set.of(HierarchyFixtureFactory.SOURCE),p.sources().stream().map(Source::sourceArtifact).collect(java.util.stream.Collectors.toSet()));
        assertEquals(Resolution.COMPATIBLE,HierarchyIntegrationTest.helper(a).resolution());
        assertTrue(Reports.JSON.valueToTree(a.evidence().get("required-symbol-resolution")).path("complete").asBoolean());
        assertFalse(a.findings().stream().anyMatch(f->f.id().equals("LP-API-003")));assertFalse(ProductView.result(a).contains("Compatibility analysis incomplete"));
    }
    private static void missingMethod(Assessment a)throws Exception{
        var p=RequiredCompatibilityIntegrationTest.required(a);assertEquals(Resolution.MISSING_METHOD,p.resolution());assertEquals("found",p.current().memberStatus());
        for(var c:p.contexts())if(c.context()!=ExecutionContext.CURRENT_NODE_RUNTIME){assertEquals(Resolution.MISSING_METHOD,c.resolution());assertEquals("found",c.proof().classStatus());assertEquals("absent",c.proof().memberStatus());}
        assertEquals(1,a.findings().stream().filter(f->f.category().equals("API_COMPATIBILITY")&&f.severity().equals("BLOCKED")).count());
    }
    @Test void noTvuRequiresCompatibilityAndUnprovenSchemaResolution()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"blocked",true);var a=assess(f,false);resolved(a);missingMethod(a);
        assertEquals("BLOCKED",a.status());assertEquals(List.of("CorDapp compatibility","Schema configuration"),ProductView.issues(a).stream().filter(ProductView.Issue::blocking).map(ProductView.Issue::title).toList());
        String result=ProductView.result(a);assertTrue(result.contains("2 blockers"));assertTrue(result.contains("1. CorDapp compatibility"));assertTrue(result.contains("2. Schema configuration"));assertFalse(result.contains("issues need attention"));assertFalse(result.contains("TVU validation"));
        assertEquals(Boolean.FALSE,a.evidence().get("tvu-evidence-supplied"));assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
    }
    @Test void suppliedFailedTvuAddsExactlyOneBlockerAndPreservesAll201Matches()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"blocked",true);var a=assess(f,true);resolved(a);missingMethod(a);
        assertEquals(List.of("CorDapp compatibility","TVU validation","Schema configuration"),ProductView.issues(a).stream().filter(ProductView.Issue::blocking).map(ProductView.Issue::title).toList());
        TvuEvidence tvu=(TvuEvidence)a.evidence().get("tvu-summary");assertEquals(650L,tvu.processed());assertEquals(449L,tvu.succeeded());assertEquals(201L,tvu.failed());assertEquals(201,tvu.detailedRecords());
        assertEquals("201 supplied failures match the compatibility problem.",ProductView.correlation(a,tvu));assertTrue(ProductView.result(a).contains("3 blockers"));assertEquals(1,a.findings().stream().filter(finding->finding.id().equals("LP-TVU-002")).count());
    }
    @Test void quotedSelectedSchemaConfigurationClearsOnlySchemaBlocker()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"configured",false);var a=assess(f,false);resolved(a);missingMethod(a);
        assertEquals("BLOCKED",a.status());assertEquals(List.of("CorDapp compatibility"),ProductView.issues(a).stream().filter(ProductView.Issue::blocking).map(ProductView.Issue::title).toList());assertTrue(ProductView.result(a).contains("1 blocker"));
        assertFalse(a.findings().stream().anyMatch(finding->finding.id().equals("LP-DB-001")&&finding.severity().equals("BLOCKED")));
    }
    @Test void allStaticProofsCompleteWaitForSuccessfulTvuBeforeUpgradeReadiness()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"compatible",true);var pending=assess(f,false);resolved(pending);assertEquals("READY FOR TVU",pending.status());assertEquals(0,ProductView.issues(pending).stream().filter(ProductView.Issue::blocking).count());
        var passed=assess(f,true);resolved(passed);assertEquals("READY TO UPGRADE",passed.status());assertEquals(0,ProductView.issues(passed).stream().filter(ProductView.Issue::blocking).count());
    }
    @Test void genuineUnresolvedVerifierClassRemainsVisibleWithoutConfirmedBlockerInflation()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"unknown",false);var a=assess(f,false);var proof=ordinary(a);assertEquals(Resolution.UNKNOWN,proof.resolution());assertEquals("UNKNOWN",a.status());
        assertEquals(Resolution.COMPATIBLE,proof.contexts().stream().filter(c->c.context()==ExecutionContext.TARGET_NODE_RUNTIME).findFirst().orElseThrow().resolution());assertEquals(Resolution.UNKNOWN,proof.contexts().stream().filter(c->c.context()==ExecutionContext.TARGET_VERIFIER).findFirst().orElseThrow().resolution());
        assertTrue(ProductView.result(a).contains("Compatibility analysis incomplete"));assertEquals(0,ProductView.issues(a).stream().filter(ProductView.Issue::blocking).count());assertFalse(ProductView.result(a).contains("1 blocker"));
    }
    @Test void genuinelyAbsentVerifierClassRemainsAConfirmedCompatibilityBlocker()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"absent",false);var a=assess(f,false);var proof=ordinary(a);assertEquals(Resolution.MISSING_CLASS,proof.resolution());assertEquals("BLOCKED",a.status());
        var verifier=proof.contexts().stream().filter(c->c.context()==ExecutionContext.TARGET_VERIFIER).findFirst().orElseThrow();assertEquals("absent",verifier.proof().classStatus());assertEquals(Resolution.MISSING_CLASS,verifier.resolution());assertFalse(ProductView.result(a).contains("Compatibility analysis incomplete"));
    }
    @Test void malformedClassPlusConfirmedBlockersAddsReviewWithoutChangingBlockerCount()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"blocked",false);
        SyntheticFixtureFactory.writeZip(f.node().resolve("cordapps/incomplete-contract.jar"),Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Cordapp-Contract-Name","Incomplete synthetic contract","Cordapp-Contract-Version","1")),"org/example/ledger/Uninspectable.class",new byte[]{0,1,2}));
        var a=assess(f,false);missingMethod(a);assertEquals("BLOCKED",a.status());assertTrue(ProductView.result(a).contains("Compatibility analysis incomplete"));assertEquals(2,ProductView.issues(a).stream().filter(ProductView.Issue::blocking).count());assertTrue(ProductView.result(a).contains("2 blockers"));
    }
    @Test void technicalReportAndSupportZipCarryResolvedClassAndUnchangedMissingMethodProof()throws Exception{
        var f=BlockerVerifierFixtureFactory.create(root,"blocked",false);var a=assess(f,true);resolved(a);missingMethod(a);var files=Reports.files(a);
        assertTrue(files.keySet().containsAll(List.of("report.html","report.json","summary.txt","required-symbol-resolution.json","execution-contexts.json")));
        Path output=root.resolve("reports");Reports.write(output,files);Path support=new SupportBundle().create(root.resolve("support.zip"),Main.bundleFiles(files));
        try(ZipFile zip=new ZipFile(support.toFile())){assertNull(zip.getEntry("node.conf"));assertNotNull(zip.getEntry("sanitized-node.conf"));assertNotNull(zip.getEntry("checksums.sha256"));
            String json=new String(zip.getInputStream(zip.getEntry("required-symbol-resolution.json")).readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);assertTrue(json.contains(BlockerVerifierFixtureFactory.CLASS_OWNER));assertTrue(json.contains("MISSING_METHOD"));assertTrue(json.contains(HierarchyFixtureFactory.TARGET_DECLARING));assertFalse(json.contains(root.toString()));
        }
    }
}
