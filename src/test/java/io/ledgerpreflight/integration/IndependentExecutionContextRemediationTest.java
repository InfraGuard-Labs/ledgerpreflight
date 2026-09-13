package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Legacy selection remains an independent question when active source analysis is bounded. */
class IndependentExecutionContextRemediationTest {
    @TempDir Path root;

    private static void limitedSourceWithoutConfirmedApiRoot(Assessment assessment){
        assertEquals("PARTIAL",((Map<?,?>)assessment.evidence().get("analysis-coverage")).get("status"));
        assertTrue(assessment.findings().stream().anyMatch(f->f.technicalEvidence().toString().contains("symbol memory")));
        assertFalse(assessment.findings().stream().anyMatch(f->f.category().equals("API_COMPATIBILITY")&&f.severity().equals("BLOCKED")),"No source API incompatibility may be fabricated after the current source scan is incomplete");
        assertTrue(ProductView.result(assessment).contains("Compatibility analysis incomplete"));
    }

    @Test void provenLegacyShadowingSurvivesExhaustedCurrentSourceBudget()throws Exception{
        var fixture=RunARegressionTest.fixture(root,true);
        Assessment assessment=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,false));
        limitedSourceWithoutConfirmedApiRoot(assessment);assertEquals("BLOCKED",assessment.status());
        var shadow=assessment.findings().stream().filter(f->f.id().equals("LP-LEGACY-001")&&f.severity().equals("BLOCKED")).findFirst().orElseThrow();
        assertEquals("LEGACY_JARS",shadow.category());
        assertFalse(shadow.affectedArtifact().startsWith("current/historical/"),"Independent remediation proof must not invent current CorDapp source attribution");
        assertTrue(shadow.technicalEvidence().toString().contains("compatibility-shim.jar"));
    }

    @Test void unprovenLegacyOrderStaysUnknownWithExhaustedCurrentSourceBudget()throws Exception{
        var fixture=RunARegressionTest.fixture(root,true);
        var options=new AssessmentService.Options(fixture.node(),fixture.kit(),null,null,null,null,null,List.of(),null,null,"all-4.12",fixture.root().resolve("host.json"));
        Assessment assessment=new AssessmentService().assess(options);
        limitedSourceWithoutConfirmedApiRoot(assessment);assertEquals("UNKNOWN",assessment.status());
        assertFalse(assessment.findings().stream().anyMatch(f->f.id().equals("LP-LEGACY-001")&&f.severity().equals("BLOCKED")),"A duplicate class without proven launch order is not confirmed shadowing");
    }
}
