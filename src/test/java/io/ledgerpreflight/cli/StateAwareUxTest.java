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
        var pending=new Assessment("1","0.1.0","READY FOR TVU","4.11","4.12",List.of(),Map.of());
        var ready=new Assessment("1","0.1.0","READY TO UPGRADE","4.11","4.12",List.of(),Map.of("tvu-evidence-supplied",true));
        assertEquals(List.of("Import existing TVU results","Export full technical report","Create R3 support package","Exit"),InteractiveSession.actions(pending).stream().map(a->a.label).toList());
        assertEquals(List.of("View TVU evidence","Export full technical report","Create R3 support package","Import existing TVU results","Exit"),InteractiveSession.actions(ready).stream().map(a->a.label).toList());
    }
    @Test void zeroBlockerWarningMenuDoesNotOfferBlockers()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);
        var finding=Finding.of("X","Review schema","WARNING","DATABASE_SCHEMA","HIGH","CONFIGURATION","node.conf",List.of(),"Review required","Review schema");
        var a=new Assessment("1","0.1.0","WARNING","4.11","4.12",List.of(finding),Map.of());
        StringWriter out=new StringWriter();new InteractiveSession(f.options(false),a,root.resolve("reports"),new SessionTerminal(new StringReader("q\n"),new PrintWriter(out),false,76)).run();
        assertFalse(out.toString().contains("Understand the blockers"));assertTrue(out.toString().contains("View schema evidence"));assertFalse(out.toString().contains("View compatibility evidence"));
    }
    @Test void groupedCountsDoNotPretendMissingDetailsWereSupplied()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));String text=ProductView.result(a);
        assertTrue(text.contains("3 blockers"));assertTrue(text.contains("3 supplied failure details"));
        assertFalse(text.contains("201 supplied failures match"));
    }
    @Test void evidenceRequiresExplicitSelection()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(f.options(true),a,root.resolve("reports"),new SessionTerminal(new StringReader("1\n1\nq\n"),new PrintWriter(out),false,76)).run();
        assertTrue(out.toString().contains("COMPATIBILITY EVIDENCE"));
        assertFalse(ProductView.result(a).contains("descriptor"));
    }
    @Test void supportNamesAreReadableAndRepeatedCreationPreservesBoth()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(f.options(true),a,root.resolve("reports"),new SessionTerminal(new StringReader("5\n1\n5\n1\nq\n"),new PrintWriter(out),false,76)).run();
        try(var paths=Files.list(root.resolve("reports"))){var zips=paths.filter(p->p.toString().endsWith(".zip")).toList();assertEquals(2,zips.size());for(Path zip:zips)assertTrue(zip.getFileName().toString().matches("[A-Za-z0-9_-]+-R3-support-\\d{8}-\\d{4}(-\\d+)?\\.zip"));}
        assertTrue(out.toString().contains("✓ SHA-256 generated"));
    }
}
