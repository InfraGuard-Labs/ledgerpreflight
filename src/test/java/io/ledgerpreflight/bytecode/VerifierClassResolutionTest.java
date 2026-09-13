package io.ledgerpreflight.bytecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import io.ledgerpreflight.bytecode.TargetedRuntimeLookup.Limits;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

class VerifierClassResolutionTest {
    @TempDir Path temp;
    private static final String OWNER="example/runtime/OrdinaryType",API="example/runtime/RequiredApi";
    private static byte[] definition(String owner,int members,String parent){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,owner,null,parent,null);
        for(int i=0;i<members;i++){MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,i==0?"required":"helper"+i,"()I",null,null);method.visitCode();method.visitInsn(Opcodes.ICONST_1);method.visitInsn(Opcodes.IRETURN);method.visitMaxs(1,0);method.visitEnd();}
        writer.visitEnd();return writer.toByteArray();
    }
    private static byte[] zip(Map<String,byte[]> entries)throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(out)){for(var item:new TreeMap<>(entries).entrySet()){zip.putNextEntry(new ZipEntry(item.getKey()));zip.write(item.getValue());zip.closeEntry();}}return out.toByteArray();}
    private Path jar(String name,Map<String,byte[]> entries)throws IOException {return Files.write(temp.resolve(name),zip(entries));}
    private static Reference cls(String owner){return new Reference("inspect()V","CLASS",owner,"","",0,null);}
    private static Reference method(String owner){return new Reference("inspect()V","METHOD",owner,"required","()I",Opcodes.INVOKESTATIC,false);}
    private TargetedRuntimeLookup lookup(Path path,Scope scope,Limits limits){return new TargetedRuntimeLookup(List.of(new Artifact(path,path.getFileName().toString(),"",scope==Scope.VERIFIER?Role.VERIFIER:Role.RUNTIME)),limits,scope,List.of());}
    private Analysis assess(Path current,Path node,Path verifier,Limits limits,Reference...refs){ClassInfo caller=new ClassInfo("example/Contract","java/lang/Object",List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(refs));return new RequiredSymbolAnalyzer().analyze(List.of(new JarInventory("example-contract.jar","",Map.of(),Map.of(caller.name(),caller),List.of())),lookup(current,Scope.NODE_RUNTIME,Limits.defaults()),lookup(node,Scope.NODE_RUNTIME,Limits.defaults()),lookup(verifier,Scope.VERIFIER,limits));}
    private Analysis assess(Path current,Path node,Path verifier,Reference...refs){return assess(current,node,verifier,Limits.defaults(),refs);}
    private static SymbolResult symbol(Analysis analysis,String owner,String kind){return analysis.symbols().stream().filter(s->s.symbol().owner().equals(owner)&&s.symbol().kind().equals(kind)).findFirst().orElseThrow();}
    private static Proof verifier(SymbolResult symbol){return symbol.contexts().stream().filter(c->c.context()==ExecutionContext.TARGET_VERIFIER).findFirst().orElseThrow().proof();}
    private static Limits members(int count){Limits old=Limits.defaults();return new Limits(old.maxArchiveBytes(),old.maxNestedBytes(),old.maxReadBytes(),old.maxEntries(),old.maxDepth(),old.maxNestedArchives(),old.maxOwners(),old.maxClassBytes(),count,old.maxSignatureBytes(),old.maxMillis(),old.javaFeature());}

    @Test void equivalentVerifierCopiesResolveClassPresenceWithoutChoosingMemberWinner()throws Exception {
        byte[] type=definition(OWNER,1,"java/lang/Object");Path node=jar("node.jar",Map.of(OWNER+".class",type));byte[] component=zip(Map.of(OWNER+".class",type));Path verifier=jar("verifier.jar",Map.of("first.jar",component,"second.jar",component));
        Analysis result=assess(node,node,verifier,cls(OWNER),method(OWNER));assertEquals(Resolution.COMPATIBLE,symbol(result,OWNER,"CLASS").resolution());assertEquals("found",verifier(symbol(result,OWNER,"CLASS")).classStatus());assertEquals(Resolution.UNKNOWN,symbol(result,OWNER,"METHOD").resolution());
    }
    @Test void classOnlyQuestionDoesNotRetainUnneededMemberSignatures()throws Exception {
        byte[] type=definition(OWNER,4,"java/lang/Object");Path node=jar("node.jar",Map.of(OWNER+".class",type)),verifier=jar("verifier.jar",Map.of(OWNER+".class",type));Analysis result=assess(node,node,verifier,members(1),cls(OWNER));assertEquals(Resolution.COMPATIBLE,symbol(result,OWNER,"CLASS").resolution());assertTrue(result.complete());assertTrue(result.findings().isEmpty());
    }
    @Test void classPresenceDoesNotDependOnUnneededParent()throws Exception {
        byte[] type=definition(OWNER,0,"example/UnavailableParent");Path node=jar("node.jar",Map.of(OWNER+".class",type)),verifier=jar("verifier.jar",Map.of(OWNER+".class",type));Analysis result=assess(node,node,verifier,cls(OWNER));assertEquals(Resolution.COMPATIBLE,symbol(result,OWNER,"CLASS").resolution());assertTrue(result.complete());
    }
    @Test void separateNodeAndBundledVerifierCopiesRemainIndependent()throws Exception {
        byte[] type=definition(OWNER,1,"java/lang/Object");Path current=jar("current.jar",Map.of(OWNER+".class",type));Path target=jar("target.jar",Map.of(OWNER+".class",type,"tools/verifier.jar",zip(Map.of("META-INF/MANIFEST.MF","Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),OWNER+".class",type))));
        var artifacts=List.of(new Artifact(target,"target.jar","",Role.RUNTIME));ClassInfo caller=new ClassInfo("example/Contract","java/lang/Object",List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(cls(OWNER)));Analysis result=new RequiredSymbolAnalyzer().analyze(List.of(new JarInventory("example-contract.jar","",Map.of(),Map.of(caller.name(),caller),List.of())),lookup(current,Scope.NODE_RUNTIME,Limits.defaults()),new TargetedRuntimeLookup(artifacts,Limits.defaults(),Scope.NODE_RUNTIME,List.of()),new TargetedRuntimeLookup(artifacts,Limits.defaults(),Scope.VERIFIER,List.of()));assertEquals(Resolution.COMPATIBLE,symbol(result,OWNER,"CLASS").resolution());assertTrue(verifier(symbol(result,OWNER,"CLASS")).artifacts().get(0).contains("tools/verifier.jar!/"));
    }
    @Test void completeVerifierAbsenceIsConfirmed()throws Exception {
        Path node=jar("node.jar",Map.of(OWNER+".class",definition(OWNER,1,"java/lang/Object"))),verifier=jar("verifier.jar",Map.of("readme.txt",new byte[]{1}));Analysis result=assess(node,node,verifier,cls(OWNER));assertEquals(Resolution.MISSING_CLASS,symbol(result,OWNER,"CLASS").resolution());assertEquals("absent",verifier(symbol(result,OWNER,"CLASS")).classStatus());
    }
    @Test void malformedRequiredClassRemainsUnknown()throws Exception {
        Path node=jar("node.jar",Map.of(OWNER+".class",definition(OWNER,1,"java/lang/Object"))),verifier=jar("verifier.jar",Map.of(OWNER+".class",new byte[]{1,2,3}));assertEquals(Resolution.UNKNOWN,symbol(assess(node,node,verifier,cls(OWNER)),OWNER,"CLASS").resolution());
    }
    @Test void mixedClassAndMemberQuestionsKeepIndependentSafetyOutcomes()throws Exception {
        byte[] type=definition(OWNER,4,"java/lang/Object");Path node=jar("node.jar",Map.of(OWNER+".class",type)),verifier=jar("verifier.jar",Map.of(OWNER+".class",type));Analysis result=assess(node,node,verifier,members(1),cls(OWNER),method(OWNER));assertEquals(Resolution.COMPATIBLE,symbol(result,OWNER,"CLASS").resolution());assertEquals(Resolution.UNKNOWN,symbol(result,OWNER,"METHOD").resolution());assertFalse(result.complete());
    }
    @Test void malformedMixedQuestionCannotBecomeConfirmedClassAbsence()throws Exception {
        Path node=jar("node.jar",Map.of(OWNER+".class",definition(OWNER,1,"java/lang/Object"))),verifier=jar("verifier.jar",Map.of(OWNER+".class",new byte[]{1,2,3}));Analysis result=assess(node,node,verifier,cls(OWNER),method(OWNER));assertEquals(Resolution.UNKNOWN,symbol(result,OWNER,"CLASS").resolution());assertEquals(Resolution.UNKNOWN,symbol(result,OWNER,"METHOD").resolution());assertNotEquals("absent",verifier(symbol(result,OWNER,"CLASS")).classStatus());
    }
    @Test void nonEquivalentSameContextCopiesRemainUnknownWithoutOrder()throws Exception {
        Path node=jar("node.jar",Map.of(OWNER+".class",definition(OWNER,1,"java/lang/Object"))),verifier=jar("verifier.jar",Map.of("first.jar",zip(Map.of(OWNER+".class",definition(OWNER,1,"java/lang/Object"))),"second.jar",zip(Map.of(OWNER+".class",definition(OWNER,2,"java/lang/Object")))));assertEquals(Resolution.UNKNOWN,symbol(assess(node,node,verifier,cls(OWNER)),OWNER,"CLASS").resolution());
    }
    @Test void resolvedOrdinaryClassDoesNotLeaveGenericIncompleteBesideTrueMissingMethod()throws Exception {
        byte[] type=definition(OWNER,2,"java/lang/Object"),oldApi=definition(API,1,"java/lang/Object"),newApi=definition(API,0,"java/lang/Object");Path current=jar("current.jar",Map.of(OWNER+".class",type,API+".class",oldApi)),node=jar("node.jar",Map.of(OWNER+".class",type,API+".class",newApi));byte[] duplicate=zip(Map.of(OWNER+".class",type));Path verifier=jar("verifier.jar",Map.of(API+".class",newApi,"first.jar",duplicate,"second.jar",duplicate));Analysis result=assess(current,node,verifier,cls(OWNER),method(API));assertEquals(Resolution.MISSING_METHOD,symbol(result,API,"METHOD").resolution());assertEquals("absent",verifier(symbol(result,API,"METHOD")).memberStatus());assertEquals(Resolution.COMPATIBLE,symbol(result,OWNER,"CLASS").resolution());assertTrue(result.complete());assertEquals(1,result.findings().size());assertEquals("LP-API-001",result.findings().get(0).id());
    }
}
