package io.ledgerpreflight.core;

import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ReleaseSummaryTest {
    private static Assessment assessment(boolean supplied, boolean blocked) {
        var evidence=new HashMap<String,Object>();
        evidence.put("tvu-evidence-supplied",supplied);
        evidence.put("discovery",new Discovery.Model("4.11.6","4.12.11","13","140","1.8","17",2,3,0,0,"HIGH",List.of(),"Example runtime"));
        evidence.put("environment",Map.of("nodeName","ExampleIssuer","host",new HostEnvironment("Ubuntu 22.04","amd64","17.0.20.1","1.8.0_242","USER_SUPPLIED_SOURCE_HOST","17","UNKNOWN","UNVERIFIED","Ubuntu 18.04","USER_SUPPLIED",List.of())));
        if(supplied)evidence.put("tvu-summary",new TvuEvidence(7L,7L,7L,0L,0,Map.of(),false,true,true,List.of()));
        List<Finding> findings=blocked?List.of(Finding.of("LP-API-001","Missing required API","BLOCKED","API_COMPATIBILITY","HIGH","SYNTHETIC","example.jar",List.of(),"Historical verification can fail","Use a compatible target")):List.of();
        return new Assessment("1","0.1.0",Assessment.readiness(findings,supplied,supplied),"4.11.6","4.12.11",findings,evidence);
    }
    @Test void staticResultShowsEnvironmentAndEvidenceAbsenceWithoutInventingCounts(){
        String text=ProductView.result(assessment(false,false));
        assertTrue(text.contains("ExampleIssuer"));assertTrue(text.contains("Platform 13 → 140"));
        assertTrue(text.contains("CorDapps 2 current → 3 target"));assertTrue(text.contains("Java: 1.8.0_242 (reported) · target requires 17"));
        assertTrue(text.contains("TVU: Not supplied"));assertFalse(text.contains("processed"));assertFalse(text.contains("17.0.20.1"));
    }
    @Test void successfulImportedCountsStayVisibleWithOrWithoutStaticBlockers(){
        for(boolean blocked:List.of(false,true)){
            String text=ProductView.result(assessment(true,blocked));
            assertTrue(text.contains("TVU: Imported results · 7 processed · 7 passed · 0 failed"));
            assertTrue(text.contains(blocked?"NOT READY TO UPGRADE":"READY TO UPGRADE"));
            assertEquals(!blocked,text.contains("Follow your normal supported Corda upgrade procedure."));
        }
    }
}
