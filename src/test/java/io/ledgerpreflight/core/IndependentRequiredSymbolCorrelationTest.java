package io.ledgerpreflight.core;

import java.util.*;
import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IndependentRequiredSymbolCorrelationTest {
    private static final String OWNER="example/runtime/Api",DESCRIPTOR="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    private static Assessment assessment(String resolution){
        Finding finding=Finding.of("LP-API-001","Required API differs","BLOCKED","API_COMPATIBILITY","HIGH","BYTECODE","current/historical/cordapps/source-contract.jar",List.of("owner: "+OWNER,"member: value","descriptor: "+DESCRIPTOR,"resolution: "+resolution),"Historical verification may fail","Validate the intended target");
        return new Assessment("1","0.1.0","BLOCKED","4.11.6","4.12.11",List.of(finding),Map.of());
    }
    private static TvuEvidence evidence(){return new TvuEvidence(650L,650L,449L,201L,201,Map.of("java.lang.NoSuchMethodError: "+OWNER.replace('/','.')+".value"+DESCRIPTOR,201),false,true,false,List.of());}
    @Test void missingMethodAndChangedDescriptorCorrelateExactly(){
        for(String resolution:List.of("missing-method","descriptor-mismatch"))assertEquals("201 supplied failures match the compatibility problem.",ProductView.correlation(assessment(resolution),evidence()));
    }
    @Test void differentLinkageFailureMustNotClaimNoSuchMethodRootCause(){
        for(String resolution:List.of("access-incompatible","invocation-mismatch","missing-class","missing-field"))assertEquals("",ProductView.correlation(assessment(resolution),evidence()),resolution+" is not evidence of the reported missing-method failure");
    }
}