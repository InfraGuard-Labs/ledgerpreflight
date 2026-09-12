package io.ledgerpreflight.security;

import io.ledgerpreflight.cli.Main;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.SyntheticFixtureFactory;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TerminalPresentationTest {
    @TempDir Path temp;
    @Test void realReplayCliDefaultFitsOneScreenAndKeepsEvidenceInReport() throws Exception {
        var fixture=SyntheticFixtureFactory.create(temp.resolve("inputs"),true);
        StringWriter stdout=new StringWriter(),stderr=new StringWriter();
        int code=Main.command().setOut(new PrintWriter(stdout,true)).setErr(new PrintWriter(stderr,true)).execute("assess",
            "--node",fixture.node().toString(),"--upgrade-kit",fixture.kit().toString(),"--tvu-results",fixture.log().toString(),
            "--tvu-results",fixture.errors().toString(),"--verifier-classpath",fixture.classpath().toString(),"--output",temp.resolve("reports").toString());
        String output=stdout.toString();
        assertEquals(2,code,stderr.toString()); assertTrue(output.lines().count()<=40,output);
        assertTrue(output.contains("current-node")); assertTrue(output.contains("4.11.9 → 4.12.11"));
        assertTrue(output.contains("✕ NOT READY TO UPGRADE")); assertTrue(output.contains("! Schema configuration")); assertFalse(output.contains("✓ PASS"));
        assertTrue(output.contains("WHAT HAPPENED")); assertTrue(output.contains("NEXT")); assertTrue(output.contains("Full details:"));
        assertTrue(output.contains("3 supplied failure details"));
        assertFalse(output.contains(SyntheticFixtureFactory.DESC)); assertFalse(output.contains("sha256:"));
        assertFalse(output.contains("Analyzer Java:")); assertFalse(output.contains("SyntheticPasswordOnly42")); assertFalse(output.contains("\u001b"));
    }
    @Test void hundredsOfFindingsRemainShortAndEverySummaryLineFitsNarrowTerminal() {
        List<Finding> findings=new ArrayList<>();
        for(int i=0;i<200;i++)findings.add(Finding.of("USR-BLOCK-"+String.format("%03d",i),"Blocker "+i+" with a long explanation that must never consume the entire terminal window","BLOCKED","TEST","HIGH","USER_RULE","synthetic.jar",List.of("HIDDEN_DESCRIPTOR_"+i),"The supplied artifact needs review before historical transaction verification can be accepted.","Resolve the supplied artifact with a supported runtime and validate the complete target environment."));
        for(int i=0;i<100;i++)findings.add(Finding.of("USR-WARN-"+i,"Warning "+i,"WARNING","TEST","HIGH","USER_RULE","synthetic.jar",List.of("hidden evidence"),"Review warning evidence.","Review the supplied warning."));
        String output=Reports.terminal(new Assessment("1","0.1.0","BLOCKED","4.11","4.12",findings,Map.of("environment",Map.of("nodeName","synthetic-node"))));
        assertTrue(output.contains("1 issue needs attention"));assertEquals(1,output.split("1. Upgrade preparation",-1).length-1);
        assertTrue(output.lines().count()<=40,output);
        assertTrue(output.lines().allMatch(line->line.length()<=76),output);
        assertFalse(output.contains("HIDDEN_DESCRIPTOR")); assertFalse(output.contains("USR-BLOCK-199"));
    }
    @Test void verboseOutputRetainsCompleteDescriptorsAndAllFindings() {
        List<Finding> findings=new ArrayList<>();
        for(int i=0;i<12;i++)findings.add(Finding.of("USR-DETAIL-"+i,"Detailed finding "+i,"BLOCKED","TEST","HIGH","USER_RULE","synthetic.jar",List.of("descriptor: "+SyntheticFixtureFactory.DESC,"detail-record-"+i),"Impact","Full next action"));
        var assessment=new Assessment("1","0.1.0","BLOCKED","4.11","4.12",findings,Map.of());
        String output=Reports.terminal(assessment,true);
        assertTrue(output.contains(SyntheticFixtureFactory.DESC)); assertTrue(output.contains("detail-record-11"));
        assertTrue(output.contains("Analyzer Java:")); assertTrue(output.contains("Target Java readiness:"));
        assertFalse(output.contains("additional findings are available in the full report."));
    }
}
