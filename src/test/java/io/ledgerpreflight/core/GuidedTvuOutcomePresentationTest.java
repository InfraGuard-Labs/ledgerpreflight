package io.ledgerpreflight.core;

import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GuidedTvuOutcomePresentationTest {
    private static Finding unresolvedRun(){return Finding.of("LP-TVU-002","TVU verification failure","BLOCKED","TVU","HIGH","TVU_LOG","TVU",List.of(),"Validation is incomplete.","Resolve supplied root causes and rerun the required TVU over the complete transaction set.");}
    private static Assessment assessment(String kind,List<Finding> findings,TvuEvidence summary){
        Map<String,Object> evidence=new HashMap<>();evidence.put("tvu-evidence-supplied",true);evidence.put("tvu-run",Map.of("failureKind",kind));
        if(summary!=null)evidence.put("tvu-summary",summary);
        return new Assessment("1","0.1.0","BLOCKED","4.11.6","4.12.11",findings,evidence);
    }
    @Test void cancellationExplainsTheOperatorActionWithoutClaimingHistoricalVerificationFailure(){
        Assessment assessment=assessment("USER_CANCELLATION",List.of(unresolvedRun()),null);
        String text=ProductView.result(assessment);var issue=ProductView.issues(assessment).get(0);
        assertEquals("TVU run cancelled. Partial evidence was saved.",issue.happened());
        assertTrue(text.contains("1 blocker"));assertEquals("BLOCKED",assessment.status());assertEquals(2,assessment.exitCode());
        assertFalse(text.contains("TVU verification failure"));assertFalse(text.contains("Resolve supplied root causes"));assertFalse(text.contains("USER_CANCELLATION"));
        assertEquals(1,text.split("TVU run cancelled\\.",-1).length-1);
        assertTrue(text.contains("NEXT STEP\nRun TVU again when ready to complete validation."));
        assertFalse(text.contains("0 failed"));
    }
    @Test void setupConnectionAndExecutionConditionsHaveTheirOwnCauseAndNextAction(){
        Map<String,String> descriptions=Map.of("SETUP_FAILURE","TVU setup could not be completed.","DATABASE_CONNECTION_FAILURE","TVU could not connect to the confirmed isolated database.","EXECUTION_FAILURE","The TVU run did not complete successfully.");
        for(var condition:descriptions.entrySet()){
            var assessment=assessment(condition.getKey(),List.of(unresolvedRun()),null);var issue=ProductView.issues(assessment).get(0);String text=ProductView.result(assessment);
            assertEquals(condition.getValue(),issue.happened());assertFalse(text.contains("TVU verification failure"));assertFalse(text.contains("Resolve supplied root causes"));
            assertTrue(text.contains("NEXT STEP\n"+issue.action()));assertFalse(text.contains(condition.getKey()));
        }
    }
    @Test void observedTransactionFailuresAndCorrelationRemainVisibleWhenExecutionLaterStops(){
        String owner="example/runtime/Api",descriptor="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
        Finding api=Finding.of("LP-API-001","Required API differs","BLOCKED","API_COMPATIBILITY","HIGH","BYTECODE","current/historical/cordapps/example-contract.jar",List.of("owner: "+owner,"member: value","descriptor: "+descriptor,"resolution: missing-method"),"Historical verification may fail","Use a compatible target");
        var summary=new TvuEvidence(650L,650L,449L,201L,201,Map.of("java.lang.NoSuchMethodError: "+owner.replace('/','.')+".value"+descriptor,201),false,true,false,List.of());
        for(String kind:List.of("TRANSACTION_VERIFICATION_FAILURE","USER_CANCELLATION")){
            String text=ProductView.result(assessment(kind,List.of(api,unresolvedRun()),summary));
            assertTrue(text.contains("2 blockers"));assertTrue(text.contains("650 processed · 449 passed · 201 failed."));
            assertTrue(text.contains("201 supplied failures match the compatibility problem."));
            if(kind.equals("USER_CANCELLATION"))assertTrue(text.contains("TVU run cancelled. Partial evidence was saved."));
        }
    }
    @Test void lateCaptureOrCleanupFailureDoesNotInventTransactionFailureFromSuccessfulCounters(){
        var summary=new TvuEvidence(650L,650L,650L,0L,0,Map.of(),false,true,true,List.of());
        Assessment assessment=assessment("EXECUTION_FAILURE",List.of(unresolvedRun()),summary);
        Map<String,Object> evidence=new HashMap<>(assessment.evidence());
        evidence.put("tvu-run",Map.of("failureKind","EXECUTION_FAILURE","cancelled",true,"workspaceCleaned",false));
        String text=ProductView.result(new Assessment("1","0.1.0","BLOCKED","4.11.6","4.12.11",assessment.findings(),evidence));
        assertTrue(text.contains("NOT READY TO UPGRADE"));assertTrue(text.contains("The TVU run did not complete successfully."));
        assertTrue(text.contains("Review the captured execution and cleanup evidence"));assertFalse(text.contains("TVU verification failure"));
        assertFalse(text.contains("TVU run cancelled"));assertFalse(text.contains("Partial evidence was saved"));
        assertFalse(text.toLowerCase(Locale.ROOT).contains("cleanup succeeded"));assertFalse(text.contains("workspace cleaned"));
    }
}
