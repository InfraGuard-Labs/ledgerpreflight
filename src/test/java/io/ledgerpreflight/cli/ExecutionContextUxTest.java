package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.ConfigAnalyzer.ConfigEvidence;
import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import io.ledgerpreflight.reporting.Reports;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

/** Independent synthetic context evidence exercises the presentation contract. */
class ExecutionContextUxTest {
    private static final String OWNER="org/example/runtime/Amounts",DESC="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    private static Finding proof(String nodeMember,String nodeResolution,String verifierMember,String verifierResolution,String blocked,String unknown) {
        List<String> evidence=new ArrayList<>(List.of("sourceScope: active-current-cordapp","sourceArtifact: cordapps/example-contracts.jar",
            "sourceClass: org/example/ledger/Agreement","sourceMethod: verify()V","owner: "+OWNER,"member: total","descriptor: "+DESC,
            "kind: METHOD","referenceType: INVOKESTATIC","currentClass: found","currentMember: found",
            "currentArtifact: corda.jar!/runtime-core.jar!/org/example/runtime/Amounts.class",
            "targetClass: "+(nodeMember.equals("unknown")?"unknown":"found"),"targetMember: "+nodeMember,"targetResolution: "+nodeResolution,
            "targetJar: corda-target.jar!/runtime-core.jar!/org/example/runtime/Amounts.class",
            "blockedContexts: "+blocked,"unknownContexts: "+unknown,"resolution: "+(!blocked.isEmpty()?nodeResolution.equals("compatible")||nodeResolution.equals("unknown")?verifierResolution:nodeResolution:"unknown")));
        if(!verifierMember.isEmpty())evidence.addAll(List.of("verifierClass: "+(verifierMember.equals("unknown")?"unknown":"found"),"verifierMember: "+verifierMember,
            "verifierResolution: "+verifierResolution,"verifierJar: external-verifier.jar!/org/example/runtime/Amounts.class"));
        return Finding.of(blocked.isEmpty()?"LP-API-003":"LP-API-001","Required runtime API is incompatible",blocked.isEmpty()?"UNKNOWN":"BLOCKED","API_COMPATIBILITY","HIGH","BYTECODE","cordapps/example-contracts.jar",evidence,
            "Historical verification may fail","Use a supported compatible runtime and repeat validation.");
    }
    private static Finding both(){return proof("absent","missing-method","absent","missing-method","TARGET_NODE_RUNTIME,TARGET_VERIFIER","");}
    private static Assessment assessment(List<Finding> findings){return assessment(findings,Map.of());}
    private static Assessment assessment(List<Finding> findings,Map<String,Object> evidence){return new Assessment("1","0.1.0",findings.stream().anyMatch(f->f.severity().equals("BLOCKED"))?"BLOCKED":"UNKNOWN","4.11.6","4.12.11",findings,evidence);}
    private static Finding replace(Finding f,String key,String value){
        List<String> evidence=new ArrayList<>(f.technicalEvidence().stream().filter(s->!s.startsWith(key+": ")).toList());evidence.add(key+": "+value);
        return new Finding(f.id(),f.title(),f.severity(),f.category(),f.status(),f.confidence(),f.source(),f.affectedArtifact(),evidence,f.impact(),f.explanation(),f.recommendedNextAction(),f.documentationReference());
    }
    private static void quiet(String text){
        for(String forbidden:List.of("LP-","Ljava/","()V","CURRENT_NODE_RUNTIME","TARGET_NODE_RUNTIME","TARGET_VERIFIER","unknownContexts","sourceScope","classpath","budget","sha256","corda.jar","external-verifier.jar","technicalEvidence","assessment\n"))assertFalse(text.contains(forbidden),forbidden);
    }
    @Test void allThreeProofsDescribeTheActualMissingMethod(){
        var a=assessment(List.of(both()));String text=ResultEvidence.compatibility(a);
        assertTrue(text.contains("Affected CorDapp\nexample-contracts.jar"));
        assertTrue(text.contains("Referenced API\norg.example.runtime.Amounts.total(Iterable)"));
        assertTrue(text.contains("Current runtime · Corda 4.11.6\nClass found · Method found"));
        assertTrue(text.contains("Target runtime · Corda 4.12.11\nClass found · Method missing"));
        assertTrue(text.contains("Target verifier · Corda 4.12.11\nClass found · Method missing"));
        assertFalse(text.contains("Class missing"));assertFalse(text.contains("lookup incomplete"));
        assertTrue(ProductView.result(a).contains("target Corda runtime and its verifier"));quiet(text);quiet(ProductView.result(a));
    }
    @Test void verifierOnlyFailureDoesNotClaimTheNodeMethodIsMissing(){
        var a=assessment(List.of(proof("found","compatible","absent","missing-method","TARGET_VERIFIER","")));
        String text=ResultEvidence.compatibility(a),result=ProductView.result(a);
        assertTrue(text.contains("Target runtime · Corda 4.12.11\nClass found · Method found"));
        assertTrue(text.contains("Target verifier · Corda 4.12.11\nClass found · Method missing"));
        assertTrue(result.contains("not available in the target verifier."));assertFalse(result.contains("not available in the target Corda runtime"));
        assertTrue(result.contains("Use a compatible target verifier"));assertTrue(result.contains("Historical transactions"));quiet(text);quiet(result);
    }
    @Test void nodeFailureDoesNotClaimTheVerifierMethodIsMissing(){
        var a=assessment(List.of(proof("absent","missing-method","found","compatible","TARGET_NODE_RUNTIME","")));
        String text=ResultEvidence.compatibility(a),result=ProductView.result(a);
        assertTrue(text.contains("Target verifier · Corda 4.12.11\nClass found · Method found"));
        assertTrue(result.contains("not available in the target Corda runtime."));assertFalse(result.contains("runtime and its verifier"));quiet(text);quiet(result);
    }
    @ParameterizedTest
    @CsvSource({"descriptor-mismatch,descriptor-mismatch,Method signature changed","found,invocation-mismatch,Invocation is incompatible with this CorDapp.","found,access-incompatible,Member is not accessible from this CorDapp."})
    void verifierLinkageExplainsItsOwnResolution(String member,String resolution,String expected){
        var a=assessment(List.of(proof("found","compatible",member,resolution,"TARGET_VERIFIER","")));
        String text=ResultEvidence.compatibility(a);assertTrue(text.contains(expected));
        String node=text.substring(text.indexOf("Target runtime"),text.indexOf("Target verifier"));
        assertFalse(node.contains(expected));assertTrue(node.contains("Method found"));quiet(text);
    }
    @ParameterizedTest
    @CsvSource({"absent,missing-method,unknown,unknown,TARGET_NODE_RUNTIME,TARGET_VERIFIER","unknown,unknown,absent,missing-method,TARGET_VERIFIER,TARGET_NODE_RUNTIME"})
    void unresolvedContextDoesNotDowngradeOtherConfirmedContext(String nodeMember,String nodeResolution,String verifierMember,String verifierResolution,String blocked,String unknown){
        var a=assessment(List.of(proof(nodeMember,nodeResolution,verifierMember,verifierResolution,blocked,unknown)));
        assertEquals(List.of("CorDapp compatibility","Compatibility analysis incomplete"),ProductView.issues(a).stream().map(ProductView.Issue::title).toList());
        String result=ProductView.result(a),text=ResultEvidence.compatibility(a);
        assertTrue(result.contains("Additional compatibility analysis is incomplete."));
        assertTrue(result.contains("NEXT STEP\nResolve the CorDapp compatibility issue first."));
        assertTrue(text.contains("Method missing"));assertTrue(text.contains("Class lookup incomplete · Method lookup incomplete"));
        assertTrue(text.contains("The confirmed incompatibility still needs resolution."));quiet(result);quiet(text);
    }
    @Test void confirmedRootPrecedesSeparateUnknownReferencesAndKeepsItsSource(){
        Finding unknown=replace(replace(proof("unknown","unknown","","","","TARGET_NODE_RUNTIME"),"owner","org/example/dependency/Unresolved"),"sourceArtifact","cordapps/example-other.jar");
        var a=assessment(List.of(unknown,both()));String result=ProductView.result(a),text=ResultEvidence.compatibility(a);
        assertTrue(result.indexOf("CorDapp compatibility")<result.indexOf("Compatibility analysis incomplete"));
        assertTrue(text.indexOf("Amounts.total")<text.indexOf("Unresolved.total"));
        assertFalse(text.contains("example-other.jar"));assertTrue(text.contains("example-contracts.jar"));
        assertTrue(result.contains("NEXT STEP\nResolve the CorDapp compatibility issue first."));quiet(result);quiet(text);
    }
    @Test void targetPairingUncertaintyIsASeparateReview(){
        Finding mapping=Finding.of("LP-CORDAPP-005","Current CorDapp has no unique target match","WARNING","CORDAPP","HIGH","INPUT","assessment",List.of("target/cordapps/example-rebuilt.jar"),"Rebuild coverage is uncertain","Supply a unique replacement");
        var a=assessment(List.of(mapping,both()));String result=ProductView.result(a),text=ResultEvidence.compatibility(a);
        assertEquals(List.of("CorDapp compatibility","Target CorDapp mapping"),ProductView.issues(a).stream().map(ProductView.Issue::title).toList());
        assertTrue(result.contains("Target CorDapp mapping: unresolved."));assertTrue(result.contains("1 issue needs attention"));
        assertFalse(result.contains("Compatibility analysis incomplete"));assertTrue(text.contains("Runtime API compatibility was checked independently."));
        assertFalse(text.contains("example-rebuilt.jar"));assertTrue(text.contains("Method missing"));quiet(result);quiet(text);
    }
    @Test void absentVerifierEvidenceDoesNotInventAnEvaluatedContext(){
        String text=ResultEvidence.compatibility(assessment(List.of(proof("absent","missing-method","","","TARGET_NODE_RUNTIME",""))));
        assertFalse(text.contains("Target verifier"));assertTrue(text.contains("Target runtime"));quiet(text);
    }
    @Test void fieldEvidenceUsesHumanFieldTermsInEachContext(){
        Finding field=replace(replace(replace(both(),"kind","FIELD"),"referenceType","GETSTATIC"),"descriptor","Ljava/math/BigDecimal;");
        String text=ResultEvidence.compatibility(assessment(List.of(field)));
        assertTrue(text.contains("Current runtime · Corda 4.11.6\nClass found · Field found"));
        assertTrue(text.contains("Target verifier · Corda 4.12.11\nClass found · Field missing"));assertFalse(text.contains("Method"));quiet(text);
    }
    @ParameterizedTest
    @CsvSource({"201,201 supplied failures match the compatibility problem.","3,3 supplied failure details match the compatibility problem; other reported failures are unclassified."})
    void verifierRootRetainsExactTvuCorrelationScope(int count,String expected){
        String root="java.lang.NoSuchMethodError: 'java.math.BigDecimal org.example.runtime.Amounts.total(java.lang.Iterable)'";
        TvuEvidence tvu=new TvuEvidence(650L,650L,449L,201L,count,Map.of(root,count),false,true,false,List.of());
        var a=assessment(List.of(proof("found","compatible","absent","missing-method","TARGET_VERIFIER","")),Map.of("tvu-summary",tvu));
        assertEquals(expected,ProductView.correlation(a,tvu));assertTrue(ResultEvidence.tvu(a).contains(expected));
    }
    @Test void exportedProofKeepsExactContextsAndSourceWhileNormalOutputStaysShort()throws Exception{
        var a=assessment(List.of(both()));String json=Reports.json(a);
        for(String term:List.of("targetResolution","verifierResolution","verifierClass","verifierMember","TARGET_NODE_RUNTIME","TARGET_VERIFIER",DESC,"sourceClass","sourceMethod","INVOKESTATIC"))assertTrue(json.contains(term),term);
        assertTrue(ProductView.result(a).lines().count()<30);assertFalse(ResultEvidence.hasTvu(a));
        assertEquals(List.of("View compatibility evidence","Export full technical report","Create R3 support package","Run again","Exit"),InteractiveSession.actions(a).stream().map(x->x.label).toList());
        quiet(ResultEvidence.compatibility(a));quiet(ProductView.result(a));
    }
    @Test void schemaWordingAndStructureRemainUnchangedWithContextFindings(){
        Finding schema=Finding.of("LP-DB-001","Mixed-case schema","WARNING","DATABASE_SCHEMA","HIGH","CONFIGURATION","node.conf",List.of(),"Review intended schema","Validate schema");
        var config=new ConfigEvidence("ExampleSchema",null,null,true,false,true,List.of(),"",Map.of("databaseVendor","PostgreSQL","effectiveSchema","ExampleSchema","additionalSchemas",List.of("shared_reference")));
        var a=assessment(List.of(schema,both()),Map.of("schema-analysis",config));
        assertEquals("SCHEMA EVIDENCE\n\nDatabase\nPostgreSQL\n\nPrimary / effective schema\nExampleSchema\n\nAdditional configured schemas\nshared_reference\n\nWhat LedgerPreflight found\nThe node uses a mixed-case PostgreSQL schema.\n\nWhy this matters\nTVU may require an explicit Hibernate default schema for this setup.\n\nRecommended action\nConfirm/configure the intended TVU schema and rerun validation.",ResultEvidence.schema(a));
    }
    @Test void compatibleContextProofCreatesNoUserFacingCompatibilityNoise(){
        var a=new Assessment("1","0.1.0","READY FOR TVU","4.11.6","4.12.11",List.of(),Map.of("required-symbol-resolution",Map.of("complete",true,"contexts",List.of("CURRENT_NODE_RUNTIME","TARGET_NODE_RUNTIME","TARGET_VERIFIER"))));
        assertFalse(ResultEvidence.hasCompatibility(a));assertTrue(ProductView.issues(a).isEmpty());
        assertTrue(ProductView.result(a).contains("Static compatibility checks passed."));quiet(ProductView.result(a));
    }
}
