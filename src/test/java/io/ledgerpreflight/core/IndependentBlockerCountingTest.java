package io.ledgerpreflight.core;

import io.ledgerpreflight.reporting.Reports;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Independent presentation assertions use raw findings with deliberately unequal group counts. */
class IndependentBlockerCountingTest {
    private static Finding finding(String id,String severity,String category,String... evidence){
        return Finding.of(id,"Synthetic finding "+id,severity,category,"HIGH","SYNTHETIC","example.jar",List.of(evidence),"Resolve before upgrade","Review exact evidence and reassess");
    }
    private static Assessment assessment(Finding... findings){
        List<Finding> all=List.of(findings);return new Assessment("1","0.1.0",Assessment.readiness(all,false,false),"4.11.6","4.12.11",all,Map.of());
    }
    private static String summaryHtml(Assessment a){return Reports.html(a).split("<section class=\"technical\"",2)[0];}
    private static void count(Assessment a,int expected){
        assertEquals(expected,ProductView.issues(a).stream().filter(ProductView.Issue::blocking).count());
        assertTrue(ProductView.result(a).contains(expected+(expected==1?" blocker":" blockers")));
        assertTrue(summaryHtml(a).contains("<strong class=\"blocked\">"+expected+"</strong><span>Blockers</span>"));
    }
    @Test void threeRawCompatibilityFailuresAndSchemaAreTwoVisibleBlockers(){
        var a=assessment(finding("API-1","BLOCKED","API_COMPATIBILITY"),finding("API-2","BLOCKED","API_COMPATIBILITY"),finding("LP-LEGACY-001","BLOCKED","LEGACY_JARS"),finding("LP-DB-001","BLOCKED","DATABASE_SCHEMA"));
        count(a,2);assertTrue(summaryHtml(a).contains("CorDapp compatibility"));assertTrue(summaryHtml(a).contains("Schema configuration"));
    }
    @Test void unresolvedVerifierContextDoesNotCountKnownMethodTwice(){
        var a=assessment(finding("API-1","BLOCKED","API_COMPATIBILITY","blockedContexts: TARGET_NODE_RUNTIME","unknownContexts: TARGET_VERIFIER"),finding("LP-DB-001","BLOCKED","DATABASE_SCHEMA"));
        count(a,2);assertTrue(ProductView.result(a).contains("? Compatibility analysis incomplete"));assertTrue(ProductView.result(a).contains("1 unresolved review"));assertTrue(summaryHtml(a).contains("Compatibility analysis incomplete"));
    }
    @Test void everyConfirmedBlockerRemainsVisibleWhenThereAreMoreThanThreeGroups(){
        var a=assessment(finding("API-1","BLOCKED","API_COMPATIBILITY"),finding("TVU-1","BLOCKED","TVU"),finding("LP-DB-001","BLOCKED","DATABASE_SCHEMA"),finding("JAVA-1","BLOCKED","JAVA"),finding("CONFIG-1","ERROR","CONFIGURATION"),finding("VERSION-1","BLOCKED","UPGRADE_PATH"));
        count(a,6);String terminal=ProductView.result(a),html=summaryHtml(a);
        for(String title:List.of("CorDapp compatibility","TVU validation","Schema configuration","Target Java","Environment configuration","Upgrade preparation")){assertTrue(terminal.contains(title),title);assertTrue(html.contains(title),title);}
        assertTrue(terminal.contains("6. "));assertFalse(html.contains("Showing 3 of"));
    }
    @Test void genuineUnknownAndWarningRemainReviewableWithoutConfirmedBlockers(){
        var a=assessment(finding("API-3","UNKNOWN","API_COMPATIBILITY","resolution: unknown"),finding("MAP-1","WARNING","CORDAPP"));
        count(a,0);assertEquals("UNKNOWN",a.status());assertTrue(ProductView.result(a).contains("? Compatibility analysis incomplete"));assertTrue(ProductView.result(a).contains("! CorDapp compatibility"));assertTrue(summaryHtml(a).contains("Compatibility analysis incomplete"));
    }
}
