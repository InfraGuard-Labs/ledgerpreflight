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
        assertEquals(List.of("TVU instructions","View technical evidence","Exit"),InteractiveSession.actions("READY FOR TVU").stream().map(a->a.label).toList());
        assertEquals(List.of("View upgrade checklist","View technical evidence","Exit"),InteractiveSession.actions("READY TO UPGRADE").stream().map(a->a.label).toList());
    }
    @Test void zeroBlockerWarningMenuDoesNotOfferBlockers()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);
        var finding=Finding.of("X","Review schema","WARNING","DATABASE_SCHEMA","HIGH","CONFIGURATION","node.conf",List.of(),"Review required","Review schema");
        var a=new Assessment("1","0.1.0","WARNING","4.11","4.12",List.of(finding),Map.of());
        StringWriter out=new StringWriter();new InteractiveSession(f.options(false),a,root.resolve("reports"),new SessionTerminal(new StringReader("4\n"),new PrintWriter(out),false,76)).run();
        assertFalse(out.toString().contains("Understand the blockers"));assertTrue(out.toString().contains("View technical evidence"));
    }
    @Test void groupedCountsDoNotPretendMissingDetailsWereSupplied()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));String text=ProductView.result(a);
        assertTrue(text.contains("2 issues need attention"));assertTrue(text.contains("3 supplied failure details"));
        assertFalse(text.contains("201 supplied failures match"));
    }
    @Test void evidenceRequiresExplicitSelection()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(f.options(true),a,root.resolve("reports"),new SessionTerminal(new StringReader("1\n1\n2\n8\n4\n"),new PrintWriter(out),false,76)).run();
        assertTrue(out.toString().contains("COMPATIBILITY AND CLASSPATH"));
        assertFalse(ProductView.result(a).contains("descriptor"));
    }
    @Test void supportNamesAreReadableAndRepeatedCreationPreservesBoth()throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);var a=new AssessmentService().assess(f.options(true));StringWriter out=new StringWriter();
        new InteractiveSession(f.options(true),a,root.resolve("reports"),new SessionTerminal(new StringReader("2\n1\n2\n1\n4\n"),new PrintWriter(out),false,76)).run();
        try(var paths=Files.list(root.resolve("reports"))){var zips=paths.filter(p->p.toString().endsWith(".zip")).toList();assertEquals(2,zips.size());for(Path zip:zips)assertTrue(zip.getFileName().toString().matches("[A-Za-z0-9_-]+-R3-support-\\d{8}-\\d{4}(-\\d+)?\\.zip"));}
        assertTrue(out.toString().contains("✓ SHA-256 generated"));
    }
}
