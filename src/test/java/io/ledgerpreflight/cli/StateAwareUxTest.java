package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.SyntheticFixtureFactory;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class StateAwareUxTest {
    @TempDir Path root;
    @Test void readyMenusContainOnlyRelevantActions(){
        assertEquals(List.of("Prepare TVU validation","Run guided TVU validation","Import existing TVU results","Review assessment","Reports & R3 Support","Exit"),InteractiveSession.actions("READY FOR TVU").stream().map(a->a.label).toList());
        assertEquals(List.of("Generate change-approval report","Create evidence package","Review final assessment","Exit"),InteractiveSession.actions("READY TO UPGRADE").stream().map(a->a.label).toList());
    }
    @Test void zeroBlockerWarningMenuDoesNotOfferBlockers()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);
        var finding=Finding.of("X","Review schema","WARNING","DATABASE_SCHEMA","HIGH","CONFIGURATION","node.conf",List.of(),"Review required","Review schema");
        var a=new Assessment("1","0.1.0","WARNING","4.11","4.12",List.of(finding),Map.of());
        StringWriter out=new StringWriter();new InteractiveSession(f.options(false),a,root.resolve("reports"),new SessionTerminal(new StringReader("4\n"),new PrintWriter(out),false,76)).run();
        assertFalse(out.toString().contains("Understand the blockers"));assertTrue(out.toString().contains("Review assessment"));
    }
    @Test void partialCountsMatchVisibleFindings()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));String text=AssessmentInsights.summary(a);
        assertTrue(text.contains("Showing 2 of "+AssessmentInsights.blockers(a).size()+" blockers"));assertTrue(text.contains("additional warnings are available in full findings"));
    }
    @Test void humanEvidencePrecedesOptionalJsonAndReturnDoesNotRepeatAssessment()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(f.options(true),a,root.resolve("reports"),new SessionTerminal(new StringReader("1\n1\n1\n1\n4\n5\n4\n"),new PrintWriter(out),false,76)).run();
        String text=out.toString();assertTrue(text.contains("TECHNICAL EVIDENCE"));assertTrue(text.indexOf("Confidence:")<text.indexOf("View raw JSON"));assertFalse(text.contains("\"technicalEvidence\""));assertEquals(1,text.split("WHAT STOPS THIS UPGRADE",-1).length-1);
    }
    @Test void supportNamesAreReadableAndRepeatedCreationPreservesBoth()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(f.options(true),a,root.resolve("reports"),new SessionTerminal(new StringReader("3\n2\n1\n2\n1\n4\n4\n"),new PrintWriter(out),false,76)).run();
        try(var paths=Files.list(root.resolve("reports"))){var zips=paths.filter(p->p.toString().endsWith(".zip")).toList();assertEquals(2,zips.size());for(Path zip:zips)assertTrue(zip.getFileName().toString().matches("[A-Za-z0-9_-]+-R3-support-\\d{8}-\\d{4}(-\\d+)?\\.zip"));}
        assertTrue(out.toString().contains("✓ SHA-256 generated"));
    }
}
