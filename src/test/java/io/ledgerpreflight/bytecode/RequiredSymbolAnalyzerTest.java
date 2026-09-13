package io.ledgerpreflight.bytecode;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;

class RequiredSymbolAnalyzerTest {
    private static final String OWNER="example/runtime/Operations",DESC="(Ljava/lang/String;)I";
    private static final Member METHOD=new Member("METHOD","evaluate",DESC,Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC);
    private static Reference reference(){return new Reference("verify()V","METHOD",OWNER,"evaluate",DESC,Opcodes.INVOKESTATIC);}
    private static ClassInfo definition(String owner,String parent,Member...members){return new ClassInfo(owner,parent,List.of(),Opcodes.ACC_PUBLIC,52,List.of(members),List.of());}
    private static ClassInfo caller(String name,Reference...references){return new ClassInfo(name,"java/lang/Object",List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(references));}
    private static JarInventory app(String path,ClassInfo...classes){Map<String,ClassInfo> found=new TreeMap<>();for(ClassInfo cls:classes)found.put(cls.name(),cls);return new JarInventory(path,"synthetic",Map.of(),found,List.of());}
    private static Lookup lookup(String artifact,ClassInfo...classes){Map<String,ClassInfo> available=new HashMap<>();for(ClassInfo cls:classes)available.put(cls.name(),cls);return owner->available.containsKey(owner)?new Result(State.FOUND,available.get(owner),List.of(artifact),"Targeted lookup completed"):new Result(State.ABSENT,null,List.of(),"Targeted lookup completed");}
    private static Analysis analyze(Lookup current,Lookup target){return new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source-contract.jar",caller("example/Contract",reference()))),current,target);}
    private static Lookup current(){return lookup("corda.jar!/components/api.jar",definition(OWNER,"java/lang/Object",METHOD));}
    private static SymbolResult only(Analysis analysis){assertEquals(1,analysis.symbols().size());return analysis.symbols().get(0);}

    @Test void missingMethodProvesBothClassesAndCurrentExactMember(){
        var analysis=analyze(current(),lookup("target.jar!/components/api.jar",definition(OWNER,"java/lang/Object")));var symbol=only(analysis);
        assertEquals(Resolution.MISSING_METHOD,symbol.resolution());assertTrue(analysis.complete());assertEquals("found",symbol.current().classStatus());assertEquals("found",symbol.current().memberStatus());assertEquals("found",symbol.target().classStatus());assertEquals("absent",symbol.target().memberStatus());assertEquals("BLOCKED",analysis.findings().get(0).severity());assertEquals("missing-method",analysis.findings().get(0).evidence().get("resolution"));
    }
    @Test void exactMemberPresentInBothRuntimesIsCompatible(){
        var analysis=analyze(current(),lookup("target.jar",definition(OWNER,"java/lang/Object",METHOD)));assertEquals(Resolution.COMPATIBLE,only(analysis).resolution());assertTrue(analysis.findings().isEmpty());assertTrue(analysis.complete());assertEquals("found",only(analysis).target().memberStatus());
    }
    @Test void ownerAbsentOnlyAfterCompleteLookupIsConfirmedMissingClass(){
        var analysis=analyze(current(),lookup("target.jar"));assertEquals(Resolution.MISSING_CLASS,only(analysis).resolution());assertEquals("absent",only(analysis).target().classStatus());assertEquals("LP-API-006",analysis.findings().get(0).id());
    }
    @Test void changedDescriptorIsDistinctFromMissingMethodAndExportsAlternatives(){
        Member changed=new Member("METHOD","evaluate","(Ljava/lang/Integer;)I",METHOD.access());var analysis=analyze(current(),lookup("target.jar",definition(OWNER,"java/lang/Object",changed)));assertEquals(Resolution.DESCRIPTOR_MISMATCH,only(analysis).resolution());assertEquals(List.of(changed.descriptor()),only(analysis).target().availableDescriptors());assertEquals(DESC,analysis.findings().get(0).evidence().get("descriptor"));assertEquals("descriptor-mismatch",analysis.findings().get(0).evidence().get("targetMember"));
    }
    @Test void incompleteTargetLookupCannotClaimClassOrMemberRemoved(){
        var analysis=analyze(current(),owner->new Result(State.INCOMPLETE,null,List.of(),"Targeted entry limit reached"));assertEquals(Resolution.UNKNOWN,only(analysis).resolution());assertFalse(analysis.complete());assertEquals("unknown",only(analysis).target().classStatus());assertEquals("UNKNOWN",analysis.findings().get(0).severity());assertFalse(analysis.findings().get(0).message().contains("absent"));
    }
    @Test void incompleteCurrentProofCannotConfirmRemoval(){
        var analysis=analyze(owner->new Result(State.INCOMPLETE,null,List.of(),"Current component unavailable"),lookup("target.jar",definition(OWNER,"java/lang/Object")));assertEquals(Resolution.UNKNOWN,only(analysis).resolution());assertEquals("found",only(analysis).target().classStatus());assertEquals("absent",only(analysis).target().memberStatus());
    }
    @Test void absentCurrentMemberCannotConfirmRemoval(){
        var analysis=analyze(lookup("current.jar",definition(OWNER,"java/lang/Object")),lookup("target.jar",definition(OWNER,"java/lang/Object")));assertEquals(Resolution.UNKNOWN,only(analysis).resolution());
    }
    @Test void duplicateTargetDefinitionsRemainUnknown(){
        var analysis=analyze(current(),owner->new Result(State.AMBIGUOUS,null,List.of("a.jar","b.jar"),"Multiple class definitions"));assertEquals(Resolution.UNKNOWN,only(analysis).resolution());assertFalse(analysis.complete());
    }
    @Test void exactInheritedMemberSatisfiesReference(){
        var analysis=analyze(current(),lookup("target.jar",definition(OWNER,"example/runtime/Parent"),definition("example/runtime/Parent","java/lang/Object",METHOD)));assertEquals(Resolution.COMPATIBLE,only(analysis).resolution());assertEquals("example/runtime/Parent",only(analysis).target().declaringClass());assertTrue(analysis.targetClasses().get(0).classes().containsKey("example/runtime/Parent"));
    }
    @Test void unknownAncestorPreventsFalseRemovedMemberOrDescriptorClaim(){
        var analysis=analyze(current(),lookup("target.jar",definition(OWNER,"example/runtime/Unavailable",new Member("METHOD","evaluate","()I",METHOD.access()))));assertEquals(Resolution.UNKNOWN,only(analysis).resolution());assertEquals("unknown",only(analysis).target().memberStatus());
    }
    @Test void constructorDoesNotResolveFromParent(){
        Reference ref=new Reference("verify()V","METHOD",OWNER,"<init>","()V",Opcodes.INVOKESPECIAL);Member constructor=new Member("METHOD","<init>","()V",Opcodes.ACC_PUBLIC);
        var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",ref))),lookup("current.jar",definition(OWNER,"java/lang/Object",constructor)),lookup("target.jar",definition(OWNER,"example/runtime/Parent"),definition("example/runtime/Parent","java/lang/Object",constructor)));assertEquals(Resolution.MISSING_METHOD,only(analysis).resolution());
    }
    @Test void invocationSemanticsRemainPartOfTheRequiredQuestion(){
        var analysis=analyze(current(),lookup("target.jar",definition(OWNER,"java/lang/Object",new Member("METHOD","evaluate",DESC,Opcodes.ACC_PUBLIC))));assertEquals(Resolution.INVOCATION_MISMATCH,only(analysis).resolution());assertEquals("INVOKESTATIC",only(analysis).sources().get(0).referenceType());assertEquals("found",only(analysis).target().memberStatus());
    }
    @Test void fieldRemovedAndChangedDescriptorAreDistinct(){
        Reference ref=new Reference("verify()V","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC);Member field=new Member("FIELD","amount","J",METHOD.access());var source=List.of(app("cordapps/source.jar",caller("example/Contract",ref)));var before=lookup("current.jar",definition(OWNER,"java/lang/Object",field));
        var removed=new RequiredSymbolAnalyzer().analyze(source,before,lookup("target.jar",definition(OWNER,"java/lang/Object")));assertEquals(Resolution.MISSING_FIELD,only(removed).resolution());
        var changed=new RequiredSymbolAnalyzer().analyze(source,before,lookup("target.jar",definition(OWNER,"java/lang/Object",new Member("FIELD","amount","I",field.access()))));assertEquals(Resolution.DESCRIPTOR_MISMATCH,only(changed).resolution());assertEquals("GETSTATIC",only(changed).sources().get(0).referenceType());
    }
    @Test void sourceAttributionIsOnlyCurrentPhysicalCordappAndRetainsEveryCaller(){
        var consumers=List.of(app("cordapps/source-contract.jar!/lib/contract.jar",caller("example/First",reference()),caller("example/Second",reference())),app("cordapps/other-current.jar",caller("example/Third",reference())));
        var analysis=new RequiredSymbolAnalyzer().analyze(consumers,current(),lookup("target/target-rebuilt.jar",definition(OWNER,"java/lang/Object")));var symbol=only(analysis);assertEquals(1,analysis.findings().size());assertEquals(3,symbol.sources().size());assertEquals(Set.of("cordapps/source-contract.jar","cordapps/other-current.jar"),new HashSet<>(symbol.sources().stream().map(Source::sourceArtifact).toList()));
        assertFalse(symbol.sources().stream().anyMatch(s->s.sourceArtifact().contains("target-rebuilt")||s.sourceArtifact().equals("assessment")));assertEquals("3",analysis.findings().get(0).evidence().get("referencedClasses"));assertEquals("active-current-cordapp",analysis.findings().get(0).evidence().get("sourceScope"));assertTrue(analysis.findings().get(0).evidence().containsKey("sourceArtifact.2"));assertTrue(symbol.sources().stream().allMatch(s->s.sourceMethod().equals("verify()V")&&s.owner().equals(OWNER)&&s.member().equals("evaluate")&&s.descriptor().equals(DESC)));
    }
    @Test void duplicateApiReferencesAcrossMethodsRemainOneRootWithAllSites(){
        Reference another=new Reference("verifyAgain()V",reference().kind(),OWNER,reference().name(),DESC,reference().opcode());var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",reference(),another))),current(),lookup("target.jar",definition(OWNER,"java/lang/Object")));assertEquals(1,analysis.findings().size());assertEquals(2,only(analysis).sources().size());assertEquals("2",analysis.findings().get(0).evidence().get("referenceSites"));assertEquals("1",analysis.findings().get(0).evidence().get("referencedClasses"));
    }
    @Test void getAndPutSameRemovedFieldAreOneRootWithBothReferenceTypes(){
        Reference get=new Reference("read()V","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC),put=new Reference("write()V","FIELD",OWNER,"amount","J",Opcodes.PUTSTATIC);var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",get,put))),lookup("current.jar",definition(OWNER,"java/lang/Object",new Member("FIELD","amount","J",METHOD.access()))),lookup("target.jar",definition(OWNER,"java/lang/Object")));assertEquals(2,analysis.symbols().size());assertEquals(1,analysis.findings().size());assertEquals("2",analysis.findings().get(0).evidence().get("referenceSites"));assertEquals(Set.of("GETSTATIC","PUTSTATIC"),new HashSet<>(analysis.symbols().stream().flatMap(s->s.sources().stream()).map(Source::referenceType).toList()));
    }
    @Test void ancestorQueriesAreBatchedAcrossDistinctRequiredOwners(){
        List<List<String>> batches=new ArrayList<>();Map<String,ClassInfo> runtime=new HashMap<>();for(int i=0;i<4;i++){runtime.put("example/runtime/Child"+i,definition("example/runtime/Child"+i,"example/runtime/Parent"+i));runtime.put("example/runtime/Parent"+i,definition("example/runtime/Parent"+i,"java/lang/Object",METHOD));}
        Lookup supplied=new Lookup(){public Result lookup(String owner){return runtime.containsKey(owner)?new Result(State.FOUND,runtime.get(owner),List.of("runtime.jar"),""):new Result(State.ABSENT,null,List.of(),"");}public void prefetch(Collection<String> owners){batches.add(List.copyOf(owners));}};
        List<Reference> refs=new ArrayList<>();for(int i=0;i<4;i++)refs.add(new Reference("verify()V","METHOD","example/runtime/Child"+i,"evaluate",DESC,Opcodes.INVOKESTATIC));var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",refs.toArray(Reference[]::new)))),supplied,supplied);assertTrue(analysis.complete());assertTrue(analysis.findings().isEmpty());assertEquals(4,batches.size());assertTrue(batches.stream().allMatch(batch->batch.size()==4));assertTrue(batches.get(1).stream().allMatch(owner->owner.contains("Parent")));
    }
    @Test void localCordappCallsAndPlatformClassesDoNotRequireRuntimeScanning(){
        Reference local=new Reference("verify()V","METHOD","example/Helper","evaluate",DESC,Opcodes.INVOKESTATIC);Reference platform=new Reference("verify()V","METHOD","java/lang/String","length","()I",Opcodes.INVOKEVIRTUAL);Lookup never=owner->{fail("Unexpected runtime lookup "+owner);return null;};
        var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",local,platform),definition("example/Helper","java/lang/Object",METHOD))),never,never);assertTrue(analysis.complete());assertTrue(analysis.symbols().isEmpty());
    }
    @Test void inheritedCallUsingLocalOwnerStillResolvesRuntimeParent(){
        String child="example/Contract";Reference ref=new Reference("verify()V","METHOD",child,"evaluate",DESC,Opcodes.INVOKESTATIC);ClassInfo local=new ClassInfo(child,OWNER,List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(ref));var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",local)),current(),lookup("target.jar",definition(OWNER,"java/lang/Object")));assertEquals(Resolution.MISSING_METHOD,analysis.symbols().get(0).resolution());assertEquals(1,analysis.findings().size());assertFalse(analysis.targetClasses().stream().anyMatch(j->j.classes().containsKey(child)));
    }
    @Test void internalApiContextRemainsSecondaryAndGeneric(){
        String owner="net/corda/example/internal/Support";Reference ref=new Reference("verify()V","METHOD",owner,"evaluate",DESC,Opcodes.INVOKESTATIC);var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",ref))),lookup("current.jar",definition(owner,"java/lang/Object",METHOD)),lookup("target.jar",definition(owner,"java/lang/Object")));assertEquals(2,analysis.findings().size());assertEquals("LP-API-001",analysis.findings().get(0).id());assertEquals("LP-INTERNAL-001",analysis.findings().get(1).id());assertEquals("WARNING",analysis.findings().get(1).severity());
    }
    @Test void boundedRequiredReferencesRemainUnknownWhenCollectionCannotComplete(){
        List<Reference> refs=new ArrayList<>();for(int i=0;i<4200;i++)refs.add(new Reference("verify()V","METHOD",OWNER,"method"+i,"()V",Opcodes.INVOKESTATIC));var analysis=new RequiredSymbolAnalyzer().analyze(List.of(app("cordapps/source.jar",caller("example/Contract",refs.toArray(Reference[]::new)))),lookup("current.jar"),lookup("target.jar"));assertFalse(analysis.complete());assertTrue(analysis.findings().stream().anyMatch(f->f.id().equals("LP-ANALYSIS-LIMIT")&&f.severity().equals("UNKNOWN")));assertTrue(analysis.symbols().size()<=4096);
    }
}
