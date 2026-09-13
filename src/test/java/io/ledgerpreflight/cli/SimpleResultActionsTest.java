package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.*;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SimpleResultActionsTest {
    @TempDir Path root;
    private List<String> actions(Assessment a){return InteractiveSession.actions(a).stream().map(x->x.label).toList();}
    @Test void compatibilitySchemaAndSuppliedTvuHaveExactlyTheRequestedActions()throws Exception{
        var f=ProductAcceptanceFixture.create(root,true,true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,true));
        assertEquals(List.of("View compatibility evidence","View schema evidence","View TVU evidence","Export full technical report","Create R3 support package","Run again","Exit"),actions(a));
    }
    @Test void compatibilityOnlyDoesNotOfferSchemaOrTvu(){
        var f=Finding.of("LP-API-001","Missing method","BLOCKED","API_COMPATIBILITY","HIGH","RUNTIME_DISCOVERY","app.jar",List.of(),"Historical verification may fail","Use a compatible runtime");
        var a=new Assessment("1","0.1.0","BLOCKED","4.11.6","4.12.11",List.of(f),Map.of());
        assertEquals(List.of("View compatibility evidence","Export full technical report","Create R3 support package","Run again","Exit"),actions(a));
    }
    @Test void readyForTvuOffersInstructionsWithoutInventingEvidence()throws Exception{
        var f=ProductAcceptanceFixture.create(root,false,false);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));
        assertEquals("READY FOR TVU",a.status());
        assertEquals(List.of("TVU instructions","Export full technical report","Create R3 support package","Run again","Exit"),actions(a));
    }
    @Test void readyToUpgradeShowsSuppliedTvuAndExportSupportActions()throws Exception{
        var f=ProductAcceptanceFixture.create(root,false,false);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,true));
        assertEquals("READY TO UPGRADE",a.status());
        assertEquals(List.of("View TVU evidence","Export full technical report","Create R3 support package","Run again","Exit"),actions(a));
    }
    @Test void threeEvidenceViewsAreHumanReadableAndPreserveCorrelationScope()throws Exception{
        var f=ProductAcceptanceFixture.create(root,true,true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,true));
        String compatibility=ResultEvidence.compatibility(a),schema=ResultEvidence.schema(a),tvu=ResultEvidence.tvu(a);
        for(String term:List.of("Affected CorDapp","example-old-contract.jar","Referenced API","InternalUtils.sum(Iterable)","Impact","Corda 4.12.11","Recommended action"))assertTrue(compatibility.contains(term),term);
        for(String term:List.of("PostgreSQL","ExampleMixedCaseIssuer","shared_reference","Why this matters","Recommended action"))assertTrue(schema.contains(term),term);
        for(String term:List.of("650","449","201","201 supplied failures match","Recommended action"))assertTrue(tvu.contains(term),term);
        for(String text:List.of(compatibility,schema,tvu))for(String forbidden:List.of("LP-","technicalEvidence","currentInventory","retained","Ljava/","sha256","\"category\"","at org.example"))assertFalse(text.contains(forbidden),forbidden);
        var limited=SyntheticFixtureFactory.create(root.resolve("limited"),true);String partial=ResultEvidence.tvu(new AssessmentService().assess(limited.options(true)));
        assertTrue(partial.contains("3 supplied failure details"));assertTrue(partial.contains("other reported failures are unclassified"));
    }
    @Test void manyDiagnosticWarningsDoNotBecomeANormalWarningCounter(){
        List<Finding> findings=new ArrayList<>();
        for(int i=0;i<1028;i++)findings.add(Finding.of("LP-INPUT-001","Input diagnostic","WARNING","SECURITY","UNKNOWN","INPUT","artifact-"+i,List.of(),"Compatibility unproven","Review supplied inputs"));
        var a=new Assessment("1","0.1.0","WARNING","4.11.6","4.12.11",findings,Map.of());String text=ProductView.result(a);
        assertTrue(text.contains("1 review needs attention"));for(String forbidden:List.of("1028","warnings","LP-","retained","currentInventory"))assertFalse(text.contains(forbidden),forbidden);
    }
    @Test void exportKeepsRawDiagnosticsWithoutAnInteractiveBrowser()throws Exception{
        var f=ActiveRuntimeRegressionTest.fixture(root.resolve("node"));var o=ProductAcceptanceFixture.options(f,true);var a=new AssessmentService().assess(o);
        StringWriter output=new StringWriter();Path reports=root.resolve("reports");
        new InteractiveSession(o,a,reports,new SessionTerminal(new StringReader("4\n1\nq\n"),new PrintWriter(output),false,100)).run();
        String text=output.toString();assertTrue(text.contains("Technical report exported"));
        for(String forbidden:List.of("View technical evidence","TECHNICAL EVIDENCE","View full technical report","currentInventory","LP-API-001","corda.jar-old"))assertFalse(text.contains(forbidden),forbidden);
        for(String file:List.of("report.html","report.json","summary.txt","technical-assessment.txt","current-runtime-selection.json","analysis-coverage.json","runtime-api-delta.json"))assertTrue(Files.size(reports.resolve(file))>0,file);
        assertTrue(Files.readString(reports.resolve("current-runtime-selection.json")).contains("corda.jar-old"));
        assertTrue(Files.readString(reports.resolve("findings.json")).contains("LP-API-001"));
    }
    @Test void environmentUsesSelectedRuntimeAndHidesHistoricalDetails()throws Exception{
        var f=ActiveRuntimeRegressionTest.fixture(root);StringWriter output=new StringWriter();
        var options=DiscoverySession.prepare(ProductAcceptanceFixture.options(f,true),new SessionTerminal(new StringReader("1\n"),new PrintWriter(output),false,100));
        assertNotNull(options);String text=output.toString();
        for(String term:List.of("Corda        4.11.6 · Platform 13","Target       4.12.11 · Platform 140","CorDapps     2 current · 2 target","TVU          Found"))assertTrue(text.contains(term),term);
        for(String term:List.of("Unknown","corda.jar-old","Inactive","confidence","coverage","drivers","warnings"))assertFalse(text.contains(term),term);
        ActiveRuntimeRegressionTest.assertActive(new AssessmentService().assess(options));
    }
    @Test void ambiguousCurrentSelectionSurvivesContinueAndReassessment()throws Exception{
        var f=ActiveRuntimeRegressionTest.fixture(root);Files.move(f.node().resolve("corda.jar"),f.node().resolve("selected-runtime.bin"));
        StringWriter output=new StringWriter();var options=DiscoverySession.prepare(ProductAcceptanceFixture.options(f,true),new SessionTerminal(new StringReader("3\n1\n"),new PrintWriter(output),false,100));
        assertNotNull(options);assertEquals("selected-runtime.bin",options.currentRuntime().getFileName().toString());assertTrue(output.toString().contains("Select active current Corda runtime"));
        var a=new AssessmentService().assess(options);ActiveRuntimeRegressionTest.assertActive(a);
        StringWriter session=new StringWriter();new InteractiveSession(options,a,root.resolve("reports"),new SessionTerminal(new StringReader("6\nq\n"),new PrintWriter(session),false,100)).run();
        assertTrue(session.toString().contains("Assessment updated"));assertFalse(session.toString().contains("Corda unknown"));
    }
}
