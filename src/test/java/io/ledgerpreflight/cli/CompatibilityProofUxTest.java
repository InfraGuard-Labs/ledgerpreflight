package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import io.ledgerpreflight.reporting.Reports;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

/** Public synthetic evidence verifies presentation independently of engine classification. */
class CompatibilityProofUxTest {
    private static final String OWNER="net/example/runtime/Arithmetic", DESC="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    private static Finding proof(String targetClass,String targetMember,String resolution,String severity,String kind) {
        return finding("cordapps/example-old-contract.jar","org/example/ledger/HistoricalContract",targetClass,targetMember,resolution,severity,kind);
    }
    private static Finding finding(String artifact,String sourceClass,String targetClass,String targetMember,String resolution,String severity,String kind) {
        return Finding.of(resolution.equals("missing-class")?"LP-API-006":resolution.equals("unknown")?"LP-API-003":"LP-API-001","Required runtime API is incompatible",severity,"API_COMPATIBILITY","HIGH","BYTECODE",artifact,List.of(
            "sourceScope: active-current-cordapp","sourceArtifact: "+artifact,"sourceClass: "+sourceClass,
            "sourceMethod: verify()V","owner: "+OWNER,"member: total","descriptor: "+(kind.equals("FIELD")?"Ljava/math/BigDecimal;":DESC),
            "kind: "+kind,"referenceType: "+(kind.equals("FIELD")?"GETSTATIC":"INVOKESTATIC"),"currentClass: found","currentMember: found","targetClass: "+targetClass,"targetMember: "+targetMember,"resolution: "+resolution),
            "Historical verification may fail","Use a supported compatible runtime and repeat validation.");
    }
    private static Assessment assessment(List<Finding> findings,Map<String,Object> evidence) {
        return new Assessment("1","0.1.0",findings.stream().anyMatch(f->f.severity().equals("BLOCKED"))?"BLOCKED":"UNKNOWN","4.11.6","4.12.11",findings,evidence);
    }
    private static void quiet(String text) {
        for(String forbidden:List.of("LP-","Ljava/","()V","technicalEvidence","sourceScope","scan budget","retained","assessment\n","View technical evidence"))
            assertFalse(text.contains(forbidden),forbidden);
    }
    @ParameterizedTest
    @CsvSource({
        "found,absent,missing-method,METHOD,Class found · Method missing",
        "absent,absent,missing-class,METHOD,Class missing · Method missing",
        "found,descriptor-mismatch,descriptor-mismatch,METHOD,Class found · Method signature changed",
        "found,absent,missing-field,FIELD,Class found · Field missing",
        "found,descriptor-mismatch,descriptor-mismatch,FIELD,Class found · Field signature changed"
    })
    void explainsIndependentRuntimeProofWithoutDescriptors(String targetClass,String targetMember,String resolution,String kind,String expected) {
        var a=assessment(List.of(proof(targetClass,targetMember,resolution,"BLOCKED",kind)),Map.of());
        String evidence=ResultEvidence.compatibility(a);
        assertTrue(evidence.contains("Affected CorDapp\nexample-old-contract.jar"));
        assertTrue(evidence.contains("Referenced API\nnet.example.runtime.Arithmetic.total"));
        assertTrue(evidence.contains("Current runtime · Corda 4.11.6\nClass found · "+(kind.equals("FIELD")?"Field":"Method")+" found"));
        assertTrue(evidence.contains("Target runtime · Corda 4.12.11\n"+expected));
        String result=ProductView.result(a);
        assertTrue(result.contains("A historical CorDapp uses an API that is not available in the target Corda runtime."));
        assertTrue(result.contains("WHAT HAPPENED"));assertTrue(result.contains("WHY IT MATTERS"));assertTrue(result.contains("WHAT TO DO"));assertTrue(result.contains("NEXT STEP"));
        quiet(evidence);quiet(result);
    }
    @ParameterizedTest
    @CsvSource({"invocation-mismatch,Invocation is incompatible with this CorDapp.","access-incompatible,Member is not accessible from this CorDapp."})
    void foundMemberStillExplainsInvocationOrAccessIncompatibility(String resolution,String expected) {
        var a=assessment(List.of(proof("found","found",resolution,"BLOCKED","METHOD")),Map.of());
        String text=ResultEvidence.compatibility(a);
        assertTrue(text.contains("Target runtime · Corda 4.12.11\nClass found · Method found"));
        assertTrue(text.contains(expected));quiet(text);
    }
    @Test void unresolvedRequiredLookupNeverClaimsRemoval() {
        Finding unknown=proof("unknown","unknown","unknown","UNKNOWN","METHOD");
        var a=assessment(List.of(unknown),Map.of());String evidence=ResultEvidence.compatibility(a),result=ProductView.result(a);
        assertTrue(evidence.contains("Target runtime · Corda 4.12.11\nClass lookup incomplete · Method lookup incomplete"));
        assertFalse(evidence.contains("Method missing"));assertFalse(evidence.contains("Class missing"));
        assertTrue(result.contains("Compatibility analysis incomplete"));assertFalse(result.contains("uses an API that is not available"));
        quiet(evidence);quiet(result);
    }
    @Test void onlyProvenSourceBytecodeCanNameAnAffectedCordapp() {
        Finding source=proof("found","absent","missing-method","BLOCKED","METHOD");
        var grouping=Finding.of("LP-API-004","Duplicate definitions","WARNING","API_COMPATIBILITY","UNKNOWN","INPUT","assessment",List.of("jar: assessment","class: org/example/ledger/Report"),"Review","Review exported evidence");
        var target=Finding.of("LP-API-003","Supplied dependency needs review","WARNING","API_COMPATIBILITY","UNKNOWN","BYTECODE","target/cordapps/example-rebuilt-contract.jar",List.of("jar: target/cordapps/example-rebuilt-contract.jar","class: org/example/ledger/RebuiltContract"),"Review","Review exported evidence");
        var runtime=Finding.of("LP-API-004","Duplicate runtime definition","WARNING","API_COMPATIBILITY","UNKNOWN","INPUT","target/corda.jar",List.of("jar: target/corda.jar"),"Review","Review exported evidence");
        var unrelated=Finding.of("LP-INTERNAL-001","Internal namespace review","WARNING","INTERNAL_API","HIGH","BYTECODE","cordapps/example-unrelated.jar",List.of("sourceScope: active-current-cordapp","sourceArtifact: cordapps/example-unrelated.jar","sourceClass: org/example/ledger/Safe"),"Review","Validate internal API use");
        String text=ResultEvidence.compatibility(assessment(List.of(source,grouping,target,runtime,unrelated),Map.of()));
        assertTrue(text.contains("example-old-contract.jar"));
        for(String forbidden:List.of("example-rebuilt-contract.jar","example-unrelated.jar","assessment","corda.jar","Report","RebuiltContract"))assertFalse(text.contains(forbidden),forbidden);
        String unproven=ResultEvidence.compatibility(assessment(List.of(grouping,target,runtime),Map.of()));
        assertTrue(unproven.contains("Source artifact not established"));
    }
    @Test void multipleCurrentSourcesAreNamedAndDuplicateApiRootsAreDisplayedOnce() {
        Finding first=finding("cordapps/example-old-contract.jar","org/example/ledger/First","found","absent","missing-method","BLOCKED","METHOD");
        Finding second=finding("cordapps/example-payments.bin","org/example/ledger/Second","found","absent","missing-method","BLOCKED","METHOD");
        var a=assessment(List.of(first,second),Map.of());String text=ResultEvidence.compatibility(a);
        assertTrue(text.contains("example-old-contract.jar"));assertTrue(text.contains("example-payments.bin"));
        assertEquals(1,text.split("Referenced API",-1).length-1);assertEquals(1,ProductView.issues(a).size());
        assertTrue(ProductView.result(a).contains("1 blocker"));
    }
    @Test void groupedSourceCountAndExportRetainExactProvenance() throws Exception {
        Finding first=proof("found","absent","missing-method","BLOCKED","METHOD");List<String> raw=new ArrayList<>(first.technicalEvidence());
        raw.add("sourceArtifact.2: cordapps/example-second-contract.jar");raw.add("referencedClasses: 3");
        var grouped=new Finding(first.id(),first.title(),first.severity(),first.category(),first.status(),first.confidence(),first.source(),first.affectedArtifact(),raw,first.impact(),first.explanation(),first.recommendedNextAction(),first.documentationReference());
        var a=assessment(List.of(grouped),Map.of());String text=ResultEvidence.compatibility(a);
        assertTrue(text.contains("example-second-contract.jar"));assertTrue(text.contains("Referenced by 3 source classes"));quiet(text);
        String exported=Reports.json(a);
        for(String proof:List.of("sourceArtifact","sourceClass","sourceMethod","referenceType","currentClass","currentMember","targetClass","targetMember","resolution",DESC))assertTrue(exported.contains(proof),proof);
    }
    @Test void absentTvuEvidenceNeverCreatesCountsOrAction() {
        var a=assessment(List.of(proof("found","absent","missing-method","BLOCKED","METHOD")),Map.of());
        assertFalse(ResultEvidence.hasTvu(a));assertFalse(InteractiveSession.actions(a).contains(InteractiveSession.Action.TVU));
        assertEquals("",ProductView.correlation(a,new TvuEvidence(null,null,null,null,0,Map.of(),false,true,false,List.of())));
        String text=ProductView.result(a);for(String count:List.of("650","449","201","processed","passed"))assertFalse(text.contains(count),count);
    }
    @ParameterizedTest
    @CsvSource({"201,201 supplied failures match,false","3,3 supplied failure details match,true"})
    void tvuCorrelationCountsOnlySuppliedMatchingFailureDetails(int details,String expected,boolean limited) {
        String root="java.lang.NoSuchMethodError: 'java.math.BigDecimal "+OWNER.replace('/','.')+".total(java.lang.Iterable)'";
        TvuEvidence tvu=new TvuEvidence(650L,650L,449L,201L,details,Map.of(root,details),false,true,false,List.of());
        Finding missing=proof("found","absent","missing-method","BLOCKED","METHOD");
        var a=assessment(List.of(missing,missing),Map.of("tvu-summary",tvu,"tvu-evidence-supplied",true));
        String text=ResultEvidence.tvu(a);assertTrue(text.contains(expected));assertTrue(text.contains("650"));assertTrue(text.contains("449"));assertTrue(text.contains("201"));
        assertEquals(limited,text.contains("other reported failures are unclassified"));
        if(limited)assertFalse(text.contains("201 supplied failures match"));quiet(text);
    }
    @Test void differentDescriptorDoesNotBecomeMatchingTvuEvidence() {
        String root="java.lang.NoSuchMethodError: 'java.math.BigDecimal "+OWNER.replace('/','.')+".total(java.lang.String)'";
        TvuEvidence tvu=new TvuEvidence(650L,650L,449L,201L,201,Map.of(root,201),false,true,false,List.of());
        var a=assessment(List.of(proof("found","absent","missing-method","BLOCKED","METHOD")),Map.of("tvu-summary",tvu));
        assertEquals("",ProductView.correlation(a,tvu));assertFalse(ResultEvidence.tvu(a).contains("supplied failures match"));
    }
}