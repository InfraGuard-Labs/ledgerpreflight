package io.ledgerpreflight.bytecode;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;

class ExecutionContextSymbolTest {
    private static final String OWNER="example/runtime/Arithmetic",DESC="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    private static final Member METHOD=new Member("METHOD","sum",DESC,Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC);
    private static Reference reference(){return new Reference("verify()V","METHOD",OWNER,"sum",DESC,Opcodes.INVOKESTATIC);}
    private static ClassInfo runtime(Member... members){return new ClassInfo(OWNER,"java/lang/Object",List.of(),Opcodes.ACC_PUBLIC,52,List.of(members),List.of());}
    private static ClassInfo source(String name,Reference... references){return new ClassInfo(name,"java/lang/Object",List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(references));}
    private static JarInventory app(String path,ClassInfo... classes){Map<String,ClassInfo> definitions=new TreeMap<>();for(ClassInfo cls:classes)definitions.put(cls.name(),cls);return new JarInventory(path,"synthetic",Map.of(),definitions,List.of());}
    private static List<JarInventory> consumers(){return List.of(app("cordapps/historical-contracts.jar",source("example/Contract",reference())));}
    private static Lookup lookup(String origin,ClassInfo... classes){Map<String,ClassInfo> definitions=new HashMap<>();for(ClassInfo cls:classes)definitions.put(cls.name(),cls);return owner->definitions.containsKey(owner)?new Result(State.FOUND,definitions.get(owner),List.of(origin),"Completed targeted context lookup"):new Result(State.ABSENT,null,List.of(),"Completed targeted context lookup");}
    private static Lookup current(){return lookup("current.jar!/core.jar!/"+OWNER+".class",runtime(METHOD));}
    private static Lookup node(Member... members){return lookup("target.jar!/core.jar!/"+OWNER+".class",runtime(members));}
    private static Lookup verifier(Member... members){return lookup("target.jar!/external-verifier.jar!/"+OWNER+".class",runtime(members));}
    private static Lookup unknown(){return owner->new Result(State.AMBIGUOUS,null,List.of("first.jar","second.jar"),"Same-context precedence is not established");}
    private static Analysis analyze(Lookup node,Lookup verifier){return new RequiredSymbolAnalyzer().analyze(consumers(),current(),node,verifier);}
    private static SymbolResult only(Analysis analysis){assertEquals(1,analysis.symbols().size());return analysis.symbols().get(0);}
    private static ContextResult context(SymbolResult symbol,ExecutionContext context){return symbol.contexts().stream().filter(c->c.context()==context).findFirst().orElseThrow();}
    private static Map<String,String> evidence(Analysis analysis){assertEquals(1,analysis.findings().size());return analysis.findings().get(0).evidence();}

    @Test void nodeAndVerifierCopiesResolveIndependentlyAndGroupOneRemovedMethod(){
        Analysis analysis=analyze(node(),verifier());SymbolResult symbol=only(analysis);
        assertEquals(Resolution.MISSING_METHOD,symbol.resolution());assertTrue(analysis.complete());assertEquals(3,symbol.contexts().size());
        assertEquals(Resolution.COMPATIBLE,context(symbol,ExecutionContext.CURRENT_NODE_RUNTIME).resolution());
        for(ExecutionContext target:List.of(ExecutionContext.TARGET_NODE_RUNTIME,ExecutionContext.TARGET_VERIFIER)){
            ContextResult result=context(symbol,target);assertEquals(Resolution.MISSING_METHOD,result.resolution());assertEquals("found",result.proof().classStatus());assertEquals("absent",result.proof().memberStatus());
        }
        assertEquals("TARGET_NODE_RUNTIME,TARGET_VERIFIER",evidence(analysis).get("blockedContexts"));assertEquals("",evidence(analysis).get("unknownContexts"));
        assertEquals("missing-method",evidence(analysis).get("targetResolution"));assertEquals("missing-method",evidence(analysis).get("verifierResolution"));
        assertEquals("BLOCKED",analysis.findings().get(0).severity());assertEquals(DESC,symbol.symbol().descriptor());
    }

    @Test void verifierOnlyIncompatibilityDoesNotRewriteTheCompatibleNodeProof(){
        Analysis analysis=analyze(node(METHOD),verifier());SymbolResult symbol=only(analysis);
        assertEquals(Resolution.MISSING_METHOD,symbol.resolution());assertEquals("found",symbol.target().memberStatus());assertEquals(Resolution.COMPATIBLE,context(symbol,ExecutionContext.TARGET_NODE_RUNTIME).resolution());
        assertEquals("TARGET_VERIFIER",evidence(analysis).get("blockedContexts"));assertEquals("compatible",evidence(analysis).get("targetResolution"));assertEquals("absent",evidence(analysis).get("verifierMember"));
        assertTrue(analysis.findings().get(0).message().contains("external verifier"));assertTrue(analysis.findings().get(0).nextAction().contains("external verifier"));
    }

    @Test void confirmedNodeBlockerSurvivesUnknownVerifier(){
        Analysis analysis=analyze(node(),unknown());SymbolResult symbol=only(analysis);
        assertEquals(Resolution.MISSING_METHOD,symbol.resolution());assertFalse(analysis.complete());assertEquals("BLOCKED",analysis.findings().get(0).severity());
        assertEquals("TARGET_NODE_RUNTIME",evidence(analysis).get("blockedContexts"));assertEquals("TARGET_VERIFIER",evidence(analysis).get("unknownContexts"));
        assertEquals("unknown",evidence(analysis).get("verifierClass"));assertEquals("found",evidence(analysis).get("targetClass"));
    }

    @Test void confirmedVerifierBlockerSurvivesUnknownNode(){
        Analysis analysis=analyze(unknown(),verifier());SymbolResult symbol=only(analysis);
        assertEquals(Resolution.MISSING_METHOD,symbol.resolution());assertFalse(analysis.complete());assertEquals("unknown",symbol.target().classStatus());
        assertEquals("TARGET_VERIFIER",evidence(analysis).get("blockedContexts"));assertEquals("TARGET_NODE_RUNTIME",evidence(analysis).get("unknownContexts"));assertEquals("BLOCKED",analysis.findings().get(0).severity());
    }

    @Test void unknownContextPreventsCleanResultWhenOtherTargetContextIsCompatible(){
        Analysis analysis=analyze(node(METHOD),unknown());assertEquals(Resolution.UNKNOWN,only(analysis).resolution());assertFalse(analysis.complete());
        assertEquals("compatible",evidence(analysis).get("targetResolution"));assertEquals("unknown",evidence(analysis).get("verifierResolution"));assertEquals("UNKNOWN",analysis.findings().get(0).severity());
    }

    @Test void compatibleAcrossBothTargetContextsProducesNoCompatibilityNoise(){
        Analysis analysis=analyze(node(METHOD),verifier(METHOD));assertEquals(Resolution.COMPATIBLE,only(analysis).resolution());assertTrue(analysis.complete());assertTrue(analysis.findings().isEmpty());
        assertTrue(only(analysis).contexts().stream().allMatch(c->c.resolution()==Resolution.COMPATIBLE));
    }

    @Test void omittedVerifierIsNotInventedAsAnIncompleteContext(){
        Analysis analysis=analyze(node(METHOD),null);assertTrue(analysis.complete());assertTrue(analysis.findings().isEmpty());assertEquals(2,only(analysis).contexts().size());assertTrue(analysis.verifierClasses().isEmpty());
    }

    @Test void verifierFieldDescriptorMismatchRetainsExactReferenceAndAlternative(){
        Reference field=new Reference("verify()V","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC);Member before=new Member("FIELD","amount","J",Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC),changed=new Member("FIELD","amount","I",before.access());
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/historical-contracts.jar",source("example/Contract",field))),lookup("current.jar",runtime(before)),node(before),verifier(changed));
        assertEquals(Resolution.DESCRIPTOR_MISMATCH,only(analysis).resolution());assertEquals("J",only(analysis).symbol().descriptor());assertEquals(Opcodes.GETSTATIC,only(analysis).symbol().opcode());
        assertEquals(List.of("I"),context(only(analysis),ExecutionContext.TARGET_VERIFIER).proof().availableDescriptors());assertEquals("descriptor-mismatch",evidence(analysis).get("verifierMember"));assertEquals("found",evidence(analysis).get("targetMember"));
    }

    @Test void verifierMissingClassRequiresCompletedCurrentClassEvidence(){
        Analysis analysis=analyze(node(METHOD),lookup("verifier.jar"));assertEquals(Resolution.MISSING_CLASS,only(analysis).resolution());assertEquals("LP-API-006",analysis.findings().get(0).id());assertEquals("absent",evidence(analysis).get("verifierClass"));
        Analysis incomplete=new RequiredSymbolAnalyzer().analyze(consumers(),unknown(),node(METHOD),lookup("verifier.jar"));assertEquals(Resolution.UNKNOWN,only(incomplete).resolution());assertFalse(incomplete.complete());
    }

    @Test void unrelatedCurrentUncertaintyCannotErasePositiveTargetCompatibility(){
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(consumers(),unknown(),node(METHOD),verifier(METHOD));assertTrue(analysis.complete());assertTrue(analysis.findings().isEmpty());
        assertEquals(Resolution.UNKNOWN,context(only(analysis),ExecutionContext.CURRENT_NODE_RUNTIME).resolution());assertEquals(Resolution.COMPATIBLE,only(analysis).resolution());
    }

    @Test void allSourceCallersAreRetainedButNeverRuntimeOrVerifierAsAffectedArtifacts(){
        List<JarInventory> apps=List.of(app("cordapps/one.jar!/nested.jar",source("example/First",reference()),source("example/Second",reference())),app("cordapps/two.jar",source("example/Third",reference())));
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(apps,current(),node(),verifier());assertEquals(1,analysis.findings().size());
        assertEquals(Set.of("cordapps/one.jar","cordapps/two.jar"),new HashSet<>(only(analysis).sources().stream().map(Source::sourceArtifact).toList()));assertEquals("3",evidence(analysis).get("referencedClasses"));
        assertTrue(only(analysis).contexts().stream().allMatch(c->c.sources().size()==3));assertEquals("active-current-cordapp",evidence(analysis).get("sourceScope"));
    }

    @Test void contextInventoriesDoNotFlattenNodeAndVerifierCopies(){
        Analysis analysis=analyze(node(),verifier());assertEquals(1,analysis.currentClasses().size());assertEquals(1,analysis.targetClasses().size());assertEquals(1,analysis.verifierClasses().size());
        assertFalse(analysis.targetClasses().get(0).path().contains("external-verifier"));assertTrue(analysis.verifierClasses().get(0).path().contains("external-verifier"));
    }

    @Test void workflowOnlyReferencesAreNeverLookedUpInVerifier(){
        Lookup forbidden=new Lookup(){public Result lookup(String owner){fail("Workflow API was sent to verifier");return null;}public void prefetch(Collection<String> owners){assertTrue(owners.isEmpty());}};
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(consumers(),current(),node(METHOD),forbidden,source->false);
        assertTrue(analysis.complete());assertTrue(analysis.findings().isEmpty());assertEquals(2,only(analysis).contexts().size());assertTrue(analysis.verifierClasses().isEmpty());
    }

    @Test void sharedSymbolVerifierProvenanceContainsOnlyApplicableContractCallers(){
        List<JarInventory> apps=List.of(app("cordapps/mixed.jar",source("example/Contract",reference()),source("example/Workflow",reference())));
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(apps,current(),node(METHOD),verifier(),source->source.sourceClass().equals("example/Contract"));
        assertEquals(2,only(analysis).sources().size());ContextResult verified=context(only(analysis),ExecutionContext.TARGET_VERIFIER);
        assertEquals(List.of("example/Contract"),verified.sources().stream().map(Source::sourceClass).toList());assertEquals("1",evidence(analysis).get("verifierReferenceSites"));
        assertEquals(2,context(only(analysis),ExecutionContext.TARGET_NODE_RUNTIME).sources().size());
    }

    @Test void verifierOnlyFailureDoesNotAttributeCompatibleWorkflowArtifact(){
        List<JarInventory> apps=List.of(app("cordapps/contracts.jar",source("example/Contract",reference())),app("cordapps/workflows.jar",source("example/Workflow",reference())));
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(apps,current(),node(METHOD),verifier(),source->source.sourceClass().equals("example/Contract"));
        assertEquals(2,only(analysis).sources().size());assertEquals("cordapps/contracts.jar",evidence(analysis).get("sourceArtifact"));assertFalse(evidence(analysis).containsKey("sourceArtifact.2"));assertEquals("1",evidence(analysis).get("referenceSites"));
        assertEquals("example/Contract",evidence(analysis).get("sourceClass"));
    }

    @Test void getAndPutOneFieldGroupBothContextsAndRetainApplicableCallSites(){
        Reference get=new Reference("read()V","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC),put=new Reference("write()V","FIELD",OWNER,"amount","J",Opcodes.PUTSTATIC);Member before=new Member("FIELD","amount","J",Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC);
        Analysis analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/contracts.jar",source("example/Contract",get,put))),lookup("current.jar",runtime(before)),node(),verifier());
        assertEquals(2,analysis.symbols().size());assertEquals(1,analysis.findings().size());assertEquals("2",evidence(analysis).get("referenceSites"));assertEquals("2",evidence(analysis).get("verifierReferenceSites"));assertEquals("TARGET_NODE_RUNTIME,TARGET_VERIFIER",evidence(analysis).get("blockedContexts"));
    }

    @Test void exactWinningAndShadowedOriginsArePreservedInContextProof(){
        String winner="verifier.jar!/"+OWNER+".class",shadowed="legacy-jars/shim.jar!/"+OWNER+".class";
        Lookup ordered=owner->new Result(State.FOUND,runtime(),List.of(winner),"Resolved",winner,List.of(shadowed),"Explicit verifier launch classpath order");
        Analysis analysis=analyze(node(METHOD),ordered);Proof proof=context(only(analysis),ExecutionContext.TARGET_VERIFIER).proof();
        assertEquals(winner,proof.winningArtifact());assertEquals(List.of(shadowed),proof.shadowedArtifacts());assertEquals("Explicit verifier launch classpath order",proof.precedenceEvidence());
        assertEquals(winner,evidence(analysis).get("verifierWinningArtifact"));assertEquals(shadowed,evidence(analysis).get("verifierShadowedArtifacts"));
    }
}
