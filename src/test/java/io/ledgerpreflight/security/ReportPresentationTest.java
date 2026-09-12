package io.ledgerpreflight.security;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ReportPresentationTest {
    private Finding finding(String id,String severity,String title,String evidence) {
        return Finding.of(id,title,severity,"API_COMPATIBILITY","HIGH","RUNTIME_DISCOVERY","synthetic.jar",
            List.of(evidence),"Historical verification cannot complete.","Supply a supported target runtime and rerun validation.");
    }
    @Test void decisionAndActionsPrecedeCollapsedTechnicalEvidence() {
        Finding blocked=finding("LP-API-001","BLOCKED","Historical contract requires an absent method","EXACT_DESCRIPTOR_SENTINEL (Ljava/lang/Iterable;)Ljava/math/BigDecimal;");
        var assessment=new Assessment("1","0.1.0","BLOCKED","4.11.9","4.12.13",List.of(blocked),Map.of("schema-analysis",Map.of("schema","TECHNICAL_SCHEMA_SENTINEL")));
        String html=Reports.html(assessment);
        int technical=html.indexOf("id=\"technical\"");
        assertTrue(html.indexOf("What stops this upgrade")<technical);
        assertTrue(html.indexOf("What to do next")<technical);
        assertTrue(html.indexOf("EXACT_DESCRIPTOR_SENTINEL")>technical);
        assertTrue(html.indexOf("TECHNICAL_SCHEMA_SENTINEL")>technical);
        assertTrue(html.indexOf("<pre>")>technical);
        assertFalse(html.contains("<details open"));
        assertTrue(html.contains("4.11.9 → 4.12.13"));
    }
    @Test void firstPageLimitsPriorityFindingsWithoutLosingFullEvidence() {
        List<Finding> findings=new ArrayList<>();
        for(int i=1;i<=6;i++)findings.add(finding("LP-API-00"+i,"BLOCKED","Priority blocker "+i,"full evidence "+i));
        String html=Reports.html(new Assessment("1","0.1.0","BLOCKED","4.11","4.12",findings,Map.of()));
        String firstPage=html.substring(0,html.indexOf("id=\"technical\""));
        assertTrue(firstPage.contains("Priority blocker 3")); assertFalse(firstPage.contains("Priority blocker 4"));
        assertTrue(firstPage.contains("Showing 3 of 6 priority findings")); assertTrue(html.contains("full evidence 6"));
    }
    @Test void informativeFactsAreNotCountedAsPassedChecks() {
        var findings=List.of(finding("LP-FACT-1","INFO","Java requirement","Java 17 required"),finding("LP-FACT-2","INFO","Platform requirement","Platform 140 required"));
        String html=Reports.html(new Assessment("1","0.1.0","READY FOR TVU","4.11","4.12",findings,Map.of()));
        assertTrue(html.contains("<strong class=\"ready\">1</strong><span>Passed checks</span><span>of 2 readiness gates</span>"));
        assertTrue(html.contains("Required TVU validation is outstanding"));
        assertFalse(html.contains("No blockers in the supplied evidence"));
    }
    @Test void unknownEvidenceIsProminentEvenWithoutBlockers() {
        var unknown=finding("LP-INPUT-001","UNKNOWN","Runtime inventory is incomplete","unreadable fixture");
        String html=Reports.html(new Assessment("1","0.1.0","UNKNOWN","4.11","unknown",List.of(unknown),Map.of()));
        String firstPage=html.substring(0,html.indexOf("id=\"technical\""));
        assertTrue(firstPage.contains("Readiness is unproven")); assertTrue(firstPage.contains("Runtime inventory is incomplete"));
        assertTrue(firstPage.contains("<strong class=\"blocked\">0</strong>"));
    }
    @Test void reportRemainsOfflineEscapedAndContainsNoScript() {
        var hostile=finding("USR-XSS","BLOCKED","<img src=x onerror=alert(1)>","password=FakeSecret\n<script>alert(2)</script>");
        String html=Reports.html(new Assessment("1","0.1.0","BLOCKED","4.11","4.12",List.of(hostile),Map.of()));
        assertFalse(html.contains("<img")); assertFalse(html.contains("<script")); assertFalse(html.contains("FakeSecret"));
        assertTrue(html.contains("&lt;script&gt;")); assertTrue(html.contains("default-src 'none'"));
        assertFalse(html.contains("<link")); assertFalse(html.contains("<iframe"));
    }
    @Test void knownFailuresHavePlainExecutiveCausesAndThreeOrderedActions() {
        Finding api=Finding.of("LP-API-001","Required exact JVM member is absent from the supplied target hierarchy","BLOCKED","API_COMPATIBILITY","HIGH","RUNTIME_DISCOVERY","old.jar",List.of("owner: net/corda/core/internal/InternalUtils","member: sum","descriptor: (Ljava/lang/Iterable;)Ljava/math/BigDecimal;"),"Historical linkage may fail","Full original API action retained");
        Finding shim=finding("LP-LEGACY-001","BLOCKED","Technical classpath precedence finding","runtime precedes legacy");
        Finding tvu=finding("LP-TVU-002","BLOCKED","TVU verification failure","650 processed; 449 succeeded; 201 failures reported");
        String html=Reports.html(new Assessment("1","0.1.0","BLOCKED","4.11","4.12",List.of(api,shim,tvu),Map.of()));
        String executive=html.substring(0,html.indexOf("id=\"technical\""));
        assertTrue(executive.contains("Historical CorDapp requires a missing runtime member"));
        assertTrue(executive.contains("InternalUtils.sum is unavailable"));
        assertTrue(executive.contains("Java selects one whole class"));
        assertTrue(executive.contains("650 processed · 449 succeeded · 201 failures reported"));
        assertFalse(executive.contains("Ljava/lang/Iterable"));
        String actions=executive.substring(executive.indexOf("<ol class=\"actions\">"));
        assertEquals(3,actions.split("<li>",-1).length-1);
        assertTrue(actions.indexOf("supported target runtime")<actions.indexOf("selected classes"));
        assertTrue(actions.indexOf("selected classes")<actions.indexOf("Rerun the complete TVU"));
        assertTrue(html.contains("Full original API action retained"));
    }
    @Test void terminalSeparatesCurrentJavaFromAnalyzerAndPlannedTarget() {
        var host=new HostEnvironment("Ubuntu 22.04.5 LTS","amd64","17.0.12","1.8.0_442","USER_SUPPLIED_SOURCE_HOST","17","UNKNOWN","UNVERIFIED","Ubuntu 20.04","USER_SUPPLIED",List.of());
        var assessment=new Assessment("1","0.1.0","READY FOR TVU","4.11","4.12",List.of(),Map.of("environment",Map.of("host",host)));
        String output=Reports.terminal(assessment,true);
        assertTrue(output.contains("Execution host OS: Ubuntu 22.04.5 LTS (amd64)"));
        assertTrue(output.contains("Source host OS: Ubuntu 20.04"));
        assertTrue(output.contains("Current Java: 1.8.0_442 [USER_SUPPLIED_SOURCE_HOST]"));
        assertTrue(output.contains("Analyzer Java: 17.0.12 (this process)"));
        assertTrue(output.contains("Target required Java: 17; planned: UNKNOWN"));
        assertTrue(output.contains("Target Java readiness: UNVERIFIED"));
        assertTrue(output.contains("readiness gates passed"));
        assertFalse(output.contains("Current Java: 17"));
    }
}
