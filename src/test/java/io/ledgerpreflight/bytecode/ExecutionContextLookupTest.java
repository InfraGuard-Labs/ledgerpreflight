package io.ledgerpreflight.bytecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

class ExecutionContextLookupTest {
    @TempDir Path temp;
    private static final String OWNER="example/runtime/ExampleApi";
    private static byte[] definition(boolean member){
        ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,OWNER,null,"java/lang/Object",null);
        if(member)w.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"someMethod","()V",null,null).visitEnd();
        w.visitEnd();return w.toByteArray();
    }
    private static byte[] zip(Map<String,byte[]> entries)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();try(ZipOutputStream z=new ZipOutputStream(out)){
            for(var item:new TreeMap<>(entries).entrySet()){z.putNextEntry(new ZipEntry(item.getKey()));z.write(item.getValue());z.closeEntry();}
        }return out.toByteArray();
    }
    private Path jar(String name,Map<String,byte[]> entries)throws IOException{return Files.write(temp.resolve(name),zip(entries));}
    private static byte[] api(boolean member)throws IOException{return zip(Map.of(OWNER+".class",definition(member)));}
    private static byte[] verifier(boolean member)throws IOException{return zip(Map.of(OWNER+".class",definition(member),"META-INF/MANIFEST.MF",("Manifest-Version: 1.0\r\nMain-Class: example.validation.ExternalVerifier\r\n\r\n").getBytes(StandardCharsets.UTF_8)));}
    private static Artifact artifact(Path path,Role role){return new Artifact(path,path.getFileName().toString(),"",role);}
    private static TargetedRuntimeLookup lookup(Scope scope,Artifact...inputs){return new TargetedRuntimeLookup(List.of(inputs),Limits.defaults(),scope,List.of());}
    private static boolean hasMethod(Result result){return result.info().members().stream().anyMatch(m->m.name().equals("someMethod")&&m.descriptor().equals("()V"));}

    @Test void selectedRuntimeWinsOverGenericSupportingDuplicate()throws Exception {
        Path runtime=jar("selected.jar",Map.of("components/api.jar",api(true))),driver=jar("monitoring.jar",Map.of(OWNER+".class",definition(false)));
        Result result=lookup(Scope.NODE_RUNTIME,artifact(runtime,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER);
        assertEquals(State.FOUND,result.state());assertTrue(hasMethod(result));assertTrue(result.winningOrigin().startsWith("selected.jar!/components/api.jar!/"));assertTrue(result.shadowedOrigins().isEmpty());
    }
    @Test void supportingCopyCannotSupplyMissingRuntimeMember()throws Exception {
        Path runtime=jar("selected.jar",Map.of(OWNER+".class",definition(false))),driver=jar("extension.jar",Map.of(OWNER+".class",definition(true)));
        Result result=lookup(Scope.NODE_RUNTIME,artifact(runtime,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER);
        assertEquals(State.FOUND,result.state());assertFalse(hasMethod(result));
    }
    @Test void supportingDependencyIsAvailableOnlyWhenRuntimeOwnerIsAbsent()throws Exception {
        Path runtime=jar("selected.jar",Map.of("marker.txt",new byte[]{1})),driver=jar("dependency.jar",Map.of(OWNER+".class",definition(true)));
        Result result=lookup(Scope.NODE_RUNTIME,artifact(runtime,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER);
        assertEquals(State.FOUND,result.state());assertTrue(result.winningOrigin().startsWith("dependency.jar!/"));assertTrue(result.precedenceEvidence().contains("absent after complete lookup"));
    }
    @Test void supportingDependencyCannotReplaceAnIncompleteOrAmbiguousRuntime()throws Exception {
        Path malformed=Files.writeString(temp.resolve("broken.jar"),"broken"),driver=jar("dependency.jar",Map.of(OWNER+".class",definition(true)));
        assertEquals(State.INCOMPLETE,lookup(Scope.NODE_RUNTIME,artifact(malformed,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER).state());
        Path duplicate=jar("duplicate.jar",Map.of("a.jar",api(true),"b.jar",api(false)));
        assertEquals(State.AMBIGUOUS,lookup(Scope.NODE_RUNTIME,artifact(duplicate,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER).state());
    }
    @Test void irrelevantMalformedSupportingArtifactCannotPoisonRuntimeProof()throws Exception {
        Path runtime=jar("selected.jar",Map.of(OWNER+".class",definition(true))),driver=Files.writeString(temp.resolve("broken.jar"),"broken");
        assertEquals(State.FOUND,lookup(Scope.NODE_RUNTIME,artifact(runtime,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER).state());
    }
    @Test void nodeAndNestedVerifierResolveIndependently()throws Exception {
        Path capsule=jar("target.jar",Map.of("components/api.jar",api(false),"tools/checker.jar",verifier(false)));
        var node=lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME));var verifier=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME));
        assertEquals(ContextPresence.PRESENT,verifier.contextPresence());assertEquals(List.of("target.jar!/tools/checker.jar"),verifier.verifierComponents());
        Result n=node.lookup(OWNER),v=verifier.lookup(OWNER);assertEquals(State.FOUND,n.state());assertEquals(State.FOUND,v.state());assertFalse(hasMethod(n));assertFalse(hasMethod(v));
        assertTrue(n.winningOrigin().contains("components/api.jar"));assertTrue(v.winningOrigin().contains("tools/checker.jar"));
    }
    @Test void compatibleNodeDoesNotHideIncompatibleNestedVerifier()throws Exception {
        Path capsule=jar("target.jar",Map.of("components/api.jar",api(true),"tools/checker.jar",verifier(false)));
        Result n=lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME)).lookup(OWNER),v=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME)).lookup(OWNER);
        assertEquals(State.FOUND,n.state());assertTrue(hasMethod(n));assertEquals(State.FOUND,v.state());assertFalse(hasMethod(v));
    }
    @Test void explicitlySelectedVerifierRootDoesNotCompeteWithNode()throws Exception {
        Path runtime=jar("target.jar",Map.of(OWNER+".class",definition(true))),verifier=jar("validation.jar",Map.of(OWNER+".class",definition(false)));
        Artifact[] artifacts={artifact(runtime,Role.RUNTIME),artifact(verifier,Role.VERIFIER)};
        assertTrue(hasMethod(lookup(Scope.NODE_RUNTIME,artifacts).lookup(OWNER)));assertFalse(hasMethod(lookup(Scope.VERIFIER,artifacts).lookup(OWNER)));
    }
    @Test void explicitSameContextOrderSelectsWinningDefinitionAndRetainsShadowedOrigin()throws Exception {
        Path first=jar("first.jar",Map.of(OWNER+".class",definition(false))),second=jar("second.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.NODE_RUNTIME,artifact(first,Role.RUNTIME),artifact(second,Role.RUNTIME));lookup.setProvenClasspathOrder(List.of("first.jar","second.jar"));
        Result result=lookup.lookup(OWNER);assertEquals(State.FOUND,result.state());assertFalse(hasMethod(result));assertEquals(List.of("second.jar!/"+OWNER+".class"),result.shadowedOrigins());assertTrue(result.precedenceEvidence().contains("Exact supplied classpath"));
        assertThrows(IllegalStateException.class,()->lookup.setProvenClasspathOrder(List.of("second.jar","first.jar")));
    }
    @Test void unknownSameContextOrderingRemainsAmbiguous()throws Exception {
        Path first=jar("first.jar",Map.of(OWNER+".class",definition(false))),second=jar("second.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.NODE_RUNTIME,artifact(first,Role.RUNTIME),artifact(second,Role.RUNTIME));assertEquals(State.AMBIGUOUS,lookup.lookup(OWNER).state());
    }
    @Test void physicalCapsuleOrderDoesNotInventInternalComponentOrder()throws Exception {
        Path capsule=jar("target.jar",Map.of("a.jar",api(false),"b.jar",api(true)));
        for(List<String> order:List.of(List.of("target.jar"),List.of("target.jar","target.jar!/b.jar"))){
            var lookup=lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME));lookup.setProvenClasspathOrder(order);assertEquals(State.AMBIGUOUS,lookup.lookup(OWNER).state());
        }
        var proven=lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME));proven.setProvenClasspathOrder(List.of("target.jar!/b.jar","target.jar!/a.jar"));assertTrue(hasMethod(proven.lookup(OWNER)));
    }
    @Test void unknownVerifierOrderingDoesNotMakeNodeUnknown()throws Exception {
        Path capsule=jar("target.jar",Map.of("api.jar",api(true),"first-checker.jar",verifier(false),"second-checker.jar",verifier(true)));
        assertEquals(State.FOUND,lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME)).lookup(OWNER).state());assertEquals(State.AMBIGUOUS,lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME)).lookup(OWNER).state());
    }
    @Test void verifierWinsBeforeLegacyShimWhenActualOrderIsKnown()throws Exception {
        Path capsule=jar("target.jar",Map.of("api.jar",api(false),"tools/checker.jar",verifier(false))),legacy=jar("compatibility.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME),artifact(legacy,Role.LEGACY));
        assertTrue(lookup.components().stream().anyMatch(c->c.label().equals("target.jar!/tools/checker.jar")&&c.role()==Role.VERIFIER));
        lookup.setProvenClasspathOrder(List.of("target.jar!/tools/checker.jar","compatibility.jar"));Result result=lookup.lookup(OWNER);
        assertEquals(State.FOUND,result.state());assertFalse(hasMethod(result));assertEquals(List.of("compatibility.jar!/"+OWNER+".class"),result.shadowedOrigins());
    }
    @Test void verifierWithoutOrderCannotAssumeLegacyLoses()throws Exception {
        Path verifier=Files.write(temp.resolve("validation.jar"),verifier(false)),legacy=jar("compatibility.jar",Map.of(OWNER+".class",definition(true)));
        assertEquals(State.AMBIGUOUS,lookup(Scope.VERIFIER,artifact(verifier,Role.VERIFIER),artifact(legacy,Role.LEGACY)).lookup(OWNER).state());
    }
    @Test void malformedVerifierBodyIsIsolatedFromNodeProof()throws Exception {
        byte[] badVerifier=zip(Map.of("META-INF/MANIFEST.MF","Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\n\r\n".getBytes(StandardCharsets.UTF_8),OWNER+".class",new byte[]{1,2,3}));
        Path capsule=jar("target.jar",Map.of("api.jar",api(true),"tools/checker.jar",badVerifier));
        assertEquals(State.FOUND,lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME)).lookup(OWNER).state());assertEquals(State.INCOMPLETE,lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME)).lookup(OWNER).state());
    }
    @Test void optionalVerifierAbsenceRequiresCompleteBoundedContextDiscovery()throws Exception {
        Path capsule=jar("target.jar",Map.of("api.jar",api(true)));
        var absent=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME));assertEquals(ContextPresence.ABSENT,absent.contextPresence());assertTrue(absent.contextComplete());
        Limits d=Limits.defaults();Limits shallow=new Limits(d.maxArchiveBytes(),d.maxNestedBytes(),d.maxReadBytes(),d.maxEntries(),0,d.maxNestedArchives(),d.maxOwners(),d.maxClassBytes(),d.maxMembers(),d.maxSignatureBytes(),d.maxMillis(),d.javaFeature());
        var incomplete=new TargetedRuntimeLookup(List.of(artifact(capsule,Role.RUNTIME)),shallow,Scope.VERIFIER,List.of());assertEquals(ContextPresence.UNKNOWN,incomplete.contextPresence());assertFalse(incomplete.contextComplete());assertEquals(State.INCOMPLETE,incomplete.lookup(OWNER).state());
    }
    @Test void allScopeRetainsConservativeLegacyApiBehavior()throws Exception {
        Path capsule=jar("target.jar",Map.of("api.jar",api(true),"tools/checker.jar",verifier(false)));
        assertEquals(State.AMBIGUOUS,lookup(Scope.ALL,artifact(capsule,Role.RUNTIME)).lookup(OWNER).state());
    }
    @Test void exactClassLoadSourceCanProveSameContextWinnerWithoutClasspath()throws Exception {
        Path first=jar("first.jar",Map.of(OWNER+".class",definition(false))),second=jar("second.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.NODE_RUNTIME,artifact(first,Role.RUNTIME),artifact(second,Role.RUNTIME));lookup.setSelectedClassSources(Map.of(OWNER,"second.jar"));
        Result result=lookup.lookup(OWNER);assertEquals(State.FOUND,result.state());assertTrue(hasMethod(result));assertTrue(result.precedenceEvidence().contains("class-load evidence"));assertEquals(List.of("first.jar!/"+OWNER+".class"),result.shadowedOrigins());
    }
    @Test void contradictoryClassLoadAndClasspathProofIsOwnerLocalIncomplete()throws Exception {
        Path first=jar("first.jar",Map.of(OWNER+".class",definition(false))),second=jar("second.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.NODE_RUNTIME,artifact(first,Role.RUNTIME),artifact(second,Role.RUNTIME));lookup.setProvenClasspathOrder(List.of("first.jar","second.jar"));lookup.setSelectedClassSources(Map.of(OWNER,"second.jar"));
        assertEquals(State.INCOMPLETE,lookup.lookup(OWNER).state());assertEquals(State.ABSENT,lookup.lookup("example/Unrelated").state());
    }
    @Test void unresolvedClassLoadSourceCannotBeSilentlyIgnored()throws Exception {
        Path runtime=jar("selected.jar",Map.of(OWNER+".class",definition(true)));
        for(String source:List.of("","other.jar")){
            var lookup=lookup(Scope.NODE_RUNTIME,artifact(runtime,Role.RUNTIME));lookup.setSelectedClassSources(Map.of(OWNER,source));assertEquals(State.INCOMPLETE,lookup.lookup(OWNER).state());
        }
    }
    @Test void parentCapsuleClassLoadSourceDoesNotInventNestedWinner()throws Exception {
        Path capsule=jar("target.jar",Map.of("a.jar",api(false),"b.jar",api(true)));
        var lookup=lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME));lookup.setSelectedClassSources(Map.of(OWNER,"target.jar"));assertEquals(State.INCOMPLETE,lookup.lookup(OWNER).state());
    }
    @Test void archiveCountBoundsDistinctComponentsWhileRepeatedPassesKeepByteBounds()throws Exception {
        Path capsule=jar("target.jar",Map.of("api.jar",api(true),"tools/checker.jar",verifier(false)));
        Limits d=Limits.defaults();Limits two=new Limits(d.maxArchiveBytes(),d.maxNestedBytes(),d.maxReadBytes(),d.maxEntries(),d.maxDepth(),2,d.maxOwners(),d.maxClassBytes(),d.maxMembers(),d.maxSignatureBytes(),d.maxMillis(),d.javaFeature());
        var lookup=new TargetedRuntimeLookup(List.of(artifact(capsule,Role.RUNTIME)),two,Scope.VERIFIER,List.of());
        assertEquals(ContextPresence.PRESENT,lookup.contextPresence());assertEquals(State.FOUND,lookup.lookup(OWNER).state());assertEquals(State.ABSENT,lookup.lookup("example/Another").state());
        Path tooMany=jar("many.jar",Map.of("a.jar",api(true),"b.jar",api(true),"c.jar",api(true)));
        assertEquals(State.INCOMPLETE,new TargetedRuntimeLookup(List.of(artifact(tooMany,Role.RUNTIME)),two,Scope.NODE_RUNTIME,List.of()).lookup(OWNER).state());
        Limits fewBytes=new Limits(d.maxArchiveBytes(),d.maxNestedBytes(),1500,d.maxEntries(),d.maxDepth(),2,d.maxOwners(),d.maxClassBytes(),d.maxMembers(),d.maxSignatureBytes(),d.maxMillis(),d.javaFeature());
        var charged=new TargetedRuntimeLookup(List.of(artifact(capsule,Role.RUNTIME)),fewBytes,Scope.VERIFIER,List.of());
        charged.contextPresence();for(int i=0;i<5;i++)charged.lookup("example/Absent"+i);
        assertEquals(State.INCOMPLETE,charged.lookup(OWNER).state());
    }
    @Test void thinVerifierUsesSharedComponentOnlyWhenVerifierEvidenceNamesIt()throws Exception {
        byte[] thin=zip(Map.of("META-INF/MANIFEST.MF","Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\n\r\n".getBytes(StandardCharsets.UTF_8)));
        Path capsule=jar("target.jar",Map.of("api.jar",api(true),"checker.jar",thin));
        assertEquals(State.ABSENT,lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME)).lookup(OWNER).state());
        var ordered=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME));ordered.setProvenClasspathOrder(List.of("target.jar!/checker.jar","target.jar!/api.jar"));
        assertEquals(State.FOUND,ordered.lookup(OWNER).state());assertTrue(hasMethod(ordered.lookup(OWNER)));
        var loaded=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME));loaded.setSelectedClassSources(Map.of(OWNER,"target.jar!/api.jar"));assertEquals(State.FOUND,loaded.lookup(OWNER).state());
    }
}
