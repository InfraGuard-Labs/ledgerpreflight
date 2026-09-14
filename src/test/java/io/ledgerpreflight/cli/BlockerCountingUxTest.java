package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.ConfigAnalyzer.ConfigEvidence;
import java.util.*;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BlockerCountingUxTest {
    private static Finding finding(String id,String severity,String category,String... evidence){
        return Finding.of(id,"Review the supplied configuration",severity,category,"HIGH","RUNTIME_DISCOVERY","example-contract.jar",List.of(evidence),"Required validation is not established.","Correct the configuration and validate again.");
    }
    private static Finding api(){return finding("LP-API-001","BLOCKED","API_COMPATIBILITY","sourceScope: active-current-cordapp","blockedContexts: TARGET_NODE_RUNTIME,TARGET_VERIFIER");}
    private static Finding schema(){return finding("LP-DB-001","BLOCKED","DATABASE_SCHEMA");}
    private static Assessment assessment(List<Finding> findings,boolean supplied){return new Assessment("1","0.1.0",Assessment.readiness(findings,false,supplied),"4.11.6","4.12.11",findings,Map.of("tvu-evidence-supplied",supplied));}
    private static long numbered(String text){return Pattern.compile("(?m)^\\d+\\. ").matcher(text).results().count();}
    private static List<String> actions(Assessment assessment){return InteractiveSession.actions(assessment).stream().map(a->a.label).toList();}

    @Test void noTvuHasTwoNumberedBlockersAndInstructions(){
        Assessment assessment=assessment(List.of(api(),schema()),false);String text=ProductView.result(assessment);
        assertEquals("BLOCKED",assessment.status());assertTrue(text.contains("2 blockers"));assertEquals(2,numbered(text));
        assertTrue(text.contains("1. CorDapp compatibility"));assertTrue(text.contains("2. Schema configuration"));
        assertTrue(text.contains("required TVU schema configuration is not proven"));assertTrue(text.contains("Resolve both blockers, then run TVU separately and import the results."));
        assertFalse(text.contains("Compatibility analysis incomplete"));assertFalse(text.contains("! Schema configuration"));
        assertEquals(List.of("Import existing TVU results","View compatibility evidence","View schema evidence","Export full technical report","Create R3 support package","Exit"),actions(assessment));
    }
    @Test void suppliedFailureAddsExactlyOneVisibleTvuBlocker(){
        Assessment assessment=assessment(List.of(api(),schema(),finding("LP-TVU-002","BLOCKED","TVU")),true);
        String text=ProductView.result(assessment);assertTrue(text.contains("3 blockers"));assertEquals(3,numbered(text));
        assertTrue(text.contains("1. CorDapp compatibility"));assertTrue(text.contains("2. TVU validation"));assertTrue(text.contains("3. Schema configuration"));
        assertTrue(text.contains("Resolve the CorDapp and schema blockers."));
        assertEquals(List.of("View compatibility evidence","View TVU evidence","View schema evidence","Export full technical report","Create R3 support package","Import existing TVU results","Exit"),actions(assessment));
    }
    @Test void genuineUnknownIsVisibleWithoutBecomingConfirmedBlocker(){
        Assessment assessment=assessment(List.of(api(),finding("LP-API-003","UNKNOWN","API_COMPATIBILITY","resolution: unknown")),false);
        String text=ProductView.result(assessment);assertTrue(text.contains("1 blocker · 1 unresolved review"));assertEquals(1,numbered(text));
        assertTrue(text.contains("? Compatibility analysis incomplete"));assertTrue(text.contains("complete the unresolved reviews"));
    }
    @Test void unresolvedContextOfKnownBlockerDoesNotCountThatBlockerTwice(){
        Finding partial=finding("LP-API-001","BLOCKED","API_COMPATIBILITY","blockedContexts: TARGET_NODE_RUNTIME","unknownContexts: TARGET_VERIFIER");
        String text=ProductView.result(assessment(List.of(partial),false));assertTrue(text.contains("1 blocker"));assertFalse(text.contains("unresolved review"));assertEquals(1,numbered(text));
        assertFalse(text.contains("? Compatibility analysis incomplete"));
    }
    @Test void largeResultsLinkToRemainingBlockersWithoutDumpingEveryGroup(){
        List<Finding> findings=List.of(api(),schema(),finding("LP-TVU-002","BLOCKED","TVU"),finding("LP-JAVA-002","BLOCKED","JAVA"),finding("LP-ENV-001","BLOCKED","CONFIGURATION"),finding("USR-PREP-1","BLOCKED","UPGRADE_PATH"));
        String text=ProductView.result(assessment(findings,true));assertTrue(text.contains("6 blockers"));assertEquals(3,numbered(text));
        for(String title:List.of("CorDapp compatibility","TVU validation","Schema configuration"))assertTrue(text.contains(title),title);
        assertEquals(3,Pattern.compile("WHAT HAPPENED").matcher(text).results().count());
        assertTrue(text.contains("Additional issues are explained"));assertTrue(text.contains("Resolve all 6 blockers"));
    }
    @Test void resolvedInformationAndWarningsDoNotIncreaseBlockerCount(){
        List<Finding> findings=List.of(api(),finding("LP-DB-001","INFO","DATABASE_SCHEMA"),finding("LP-MAP-001","WARNING","CONFIGURATION"));
        String text=ProductView.result(assessment(findings,false));assertTrue(text.contains("1 blocker"));assertEquals(1,numbered(text));
        assertFalse(text.contains("Schema configuration"));assertTrue(text.contains("! Environment configuration"));
    }
    @Test void unknownOnlyAndWarningOnlyKeepTheirDistinctReadiness(){
        Assessment unknown=assessment(List.of(finding("LP-API-003","UNKNOWN","API_COMPATIBILITY","resolution: unknown")),false);
        assertEquals("UNKNOWN",unknown.status());assertTrue(ProductView.result(unknown).contains("0 blockers · 1 unresolved review"));assertEquals(0,numbered(ProductView.result(unknown)));
        Assessment warning=assessment(List.of(finding("LP-MAP-001","WARNING","CONFIGURATION")),false);
        assertEquals("WARNING",warning.status());assertTrue(ProductView.result(warning).contains("0 blockers · 1 review required"));
    }
    @Test void schemaEvidenceWordingAndLayoutRemainUnchanged(){
        ConfigEvidence config=new ConfigEvidence("ExampleSchema",null,null,true,false,true,List.of(),"",Map.of("databaseVendor","PostgreSQL","effectiveSchema","ExampleSchema"));
        Assessment assessment=new Assessment("1","0.1.0","BLOCKED","4.11.6","4.12.11",List.of(schema()),Map.of("schema-analysis",config));
        assertEquals("SCHEMA EVIDENCE\n\nDatabase\nPostgreSQL\n\nPrimary / effective schema\nExampleSchema\n\nWhat LedgerPreflight found\nThe node uses a mixed-case PostgreSQL schema.\n\nWhy this matters\nTVU may require an explicit Hibernate default schema for this setup.\n\nRecommended action\nConfirm/configure the intended TVU schema and rerun validation.",ResultEvidence.schema(assessment));
        assertTrue(ProductView.result(assessment).contains("required TVU schema configuration is not proven"));
    }
}
