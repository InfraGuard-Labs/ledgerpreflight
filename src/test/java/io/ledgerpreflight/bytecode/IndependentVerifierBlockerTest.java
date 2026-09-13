package io.ledgerpreflight.bytecode;

import java.nio.file.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

/** Independent class-presence questions must not relax member or context selection. */
class IndependentVerifierBlockerTest {
    @TempDir Path root;
    private static final String OWNER="org/example/runtime/OrdinaryType",CALLER="org/example/contract/Agreement";
    private static Reference cls(){return new Reference("verify()V","CLASS",OWNER,"","",0);}
    private static Reference method(){return new Reference("verify()V","METHOD",OWNER,"calculate","()I",Opcodes.INVOKESTATIC,false);}
    private static byte[] type(String parent,int access,boolean method,int value){
        ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,access|Opcodes.ACC_SUPER,OWNER,null,parent,null);
        if(method){var m=w.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"calculate","()I",null,null);m.visitCode();m.visitIntInsn(Opcodes.BIPUSH,value);m.visitInsn(Opcodes.IRETURN);m.visitMaxs(1,0);m.visitEnd();}
        w.visitEnd();return w.toByteArray();
    }
    private static byte[] ordinary(){return type("java/lang/Object",Opcodes.ACC_PUBLIC,true,7);}
    private TargetedRuntimeLookup runtime(String label,Role role,Map<String,byte[]> entries,List<String> order)throws Exception{
        Path path=root.resolve(label);try(var zip=new ZipOutputStream(Files.newOutputStream(path))){for(var e:new TreeMap<>(entries).entrySet()){zip.putNextEntry(new ZipEntry(e.getKey()));zip.write(e.getValue());zip.closeEntry();}}
        return new TargetedRuntimeLookup(List.of(new Artifact(path,label,"",role)),TargetedRuntimeLookup.Limits.defaults(),role==Role.VERIFIER?Scope.VERIFIER:Scope.NODE_RUNTIME,order);
    }
    private static byte[] archive(Map<String,byte[]> entries)throws IOException{
        var bytes=new ByteArrayOutputStream();try(var zip=new ZipOutputStream(bytes)){for(var e:new TreeMap<>(entries).entrySet()){zip.putNextEntry(new ZipEntry(e.getKey()));zip.write(e.getValue());zip.closeEntry();}}return bytes.toByteArray();
    }
    private Analysis analyze(Map<String,byte[]> target,Map<String,byte[]> verifier,List<String> order,Reference...refs)throws Exception{
        var current=runtime("current.jar",Role.RUNTIME,Map.of(OWNER+".class",ordinary()),List.of());
        var next=runtime("target.jar",Role.RUNTIME,target,List.of());var check=runtime("verifier.jar",Role.VERIFIER,verifier,order);
        var caller=new ClassInfo(CALLER,"java/lang/Object",List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(refs));
        return new RequiredSymbolAnalyzer().analyze(List.of(new JarInventory("cordapps/historical.jar","",Map.of(),Map.of(CALLER,caller),List.of())),current,next,check);
    }
    private Analysis analyze(Map<String,byte[]> verifier,Reference...refs)throws Exception{return analyze(Map.of(OWNER+".class",ordinary()),verifier,List.of(),refs);}
    private static SymbolResult symbol(Analysis a,String kind){return a.symbols().stream().filter(s->s.symbol().kind().equals(kind)).findFirst().orElseThrow();}
    private static ContextResult context(SymbolResult s,ExecutionContext context){return s.contexts().stream().filter(c->c.context()==context).findFirst().orElseThrow();}
    private static Map<String,byte[]> duplicate(byte[] first,byte[] second)throws Exception{return Map.of(OWNER+".class",first,"lib/copy.jar",archive(Map.of(OWNER+".class",second)));}

    @Test void directClassInEachIndependentContextResolvesWithoutMemberQuestion()throws Exception{
        var a=analyze(Map.of(OWNER+".class",ordinary()),cls());var s=symbol(a,"CLASS");assertEquals(Resolution.COMPATIBLE,s.resolution());assertTrue(a.complete());assertTrue(a.findings().isEmpty());
        for(var c:s.contexts()){assertEquals("found",c.proof().classStatus());assertEquals("not-applicable",c.proof().memberStatus());assertEquals(Resolution.COMPATIBLE,c.resolution());}
    }
    @Test void byteIdenticalVerifierCopiesEstablishClassPresence()throws Exception{
        var a=analyze(duplicate(ordinary(),ordinary()),cls());assertEquals(Resolution.COMPATIBLE,symbol(a,"CLASS").resolution());assertTrue(a.complete());assertTrue(a.findings().isEmpty());
        var proof=context(symbol(a,"CLASS"),ExecutionContext.TARGET_VERIFIER).proof();assertEquals(2,proof.artifacts().size());assertEquals("",proof.winningArtifact());assertTrue(proof.shadowedArtifacts().isEmpty());assertTrue(proof.precedenceEvidence().contains("SHA-256 identical"));assertEquals("not-applicable",proof.memberStatus());
    }
    @Test void classOnlyLookupDoesNotNeedUnreferencedParent()throws Exception{
        var a=analyze(Map.of(OWNER+".class",type("org/example/runtime/UnavailableParent",Opcodes.ACC_PUBLIC,false,0)),cls());assertEquals(Resolution.COMPATIBLE,symbol(a,"CLASS").resolution());assertTrue(a.complete());
    }
    @Test void completeVerifierAbsenceIsConfirmedRatherThanIncomplete()throws Exception{
        var a=analyze(Map.of("metadata/present",new byte[0]),cls());var s=symbol(a,"CLASS");assertEquals(Resolution.MISSING_CLASS,s.resolution());assertEquals("absent",context(s,ExecutionContext.TARGET_VERIFIER).proof().classStatus());assertTrue(a.complete());
        assertEquals(Resolution.COMPATIBLE,context(s,ExecutionContext.TARGET_NODE_RUNTIME).resolution());
    }
    @Test void malformedVerifierClassKeepsOnlyVerifierUnknown()throws Exception{
        var a=analyze(Map.of(OWNER+".class",new byte[]{0,1,2}),cls());var s=symbol(a,"CLASS");assertEquals(Resolution.UNKNOWN,s.resolution());assertFalse(a.complete());
        assertEquals(Resolution.COMPATIBLE,context(s,ExecutionContext.CURRENT_NODE_RUNTIME).resolution());assertEquals(Resolution.COMPATIBLE,context(s,ExecutionContext.TARGET_NODE_RUNTIME).resolution());assertEquals(Resolution.UNKNOWN,context(s,ExecutionContext.TARGET_VERIFIER).resolution());
    }
    @Test void conflictingAccessCopiesCannotCertifyAccessibleClass()throws Exception{
        var a=analyze(duplicate(ordinary(),type("java/lang/Object",0,true,7)),cls());assertNotEquals(Resolution.COMPATIBLE,symbol(a,"CLASS").resolution());
    }
    @Test void malformedDuplicateCannotBeHiddenByAValidCopy()throws Exception{
        var a=analyze(duplicate(ordinary(),new byte[]{0,1,2}),cls());assertEquals(Resolution.UNKNOWN,symbol(a,"CLASS").resolution());assertFalse(a.complete());
    }
    @Test void structurallyTruncatedClassRemainsUnknown()throws Exception{
        byte[] valid=ordinary();var a=analyze(Map.of(OWNER+".class",Arrays.copyOf(valid,valid.length-2)),cls());assertEquals(Resolution.UNKNOWN,symbol(a,"CLASS").resolution());assertFalse(a.complete());
    }
    @Test void unsupportedClassVersionCannotEstablishCompatibility()throws Exception{
        byte[] future=ordinary();future[7]=62;var a=analyze(Map.of(OWNER+".class",future),cls());assertEquals(Resolution.UNKNOWN,symbol(a,"CLASS").resolution());assertFalse(a.complete());
    }
    @Test void wrongClassfileMagicCannotEstablishCompatibility()throws Exception{
        byte[] invalid=ordinary();Arrays.fill(invalid,0,4,(byte)0);var a=analyze(Map.of(OWNER+".class",invalid),cls());assertEquals(Resolution.UNKNOWN,symbol(a,"CLASS").resolution());assertFalse(a.complete());
    }
    @Test void classPresenceDoesNotPopulateMemberCacheWithFalseAbsence()throws Exception{
        var a=analyze(Map.of(OWNER+".class",ordinary()),cls(),method());assertEquals(Resolution.COMPATIBLE,symbol(a,"CLASS").resolution());assertEquals(Resolution.COMPATIBLE,symbol(a,"METHOD").resolution());assertTrue(a.complete());
    }
    @Test void classPresenceCannotChooseBetweenDifferentMethodProviders()throws Exception{
        var a=analyze(duplicate(ordinary(),type("java/lang/Object",Opcodes.ACC_PUBLIC,false,0)),cls(),method());var s=symbol(a,"METHOD");assertEquals(Resolution.UNKNOWN,s.resolution());assertFalse(a.complete());assertEquals(Resolution.COMPATIBLE,context(s,ExecutionContext.TARGET_NODE_RUNTIME).resolution());
    }
    @Test void provenVerifierOrderStillSelectsMissingMember()throws Exception{
        var absent=type("java/lang/Object",Opcodes.ACC_PUBLIC,false,0);var copies=Map.of("lib/first.jar",archive(Map.of(OWNER+".class",absent)),"lib/second.jar",archive(Map.of(OWNER+".class",ordinary())));var a=analyze(Map.of(OWNER+".class",ordinary()),copies,List.of("verifier.jar!/lib/first.jar","verifier.jar!/lib/second.jar"),cls(),method());
        assertEquals(Resolution.MISSING_METHOD,symbol(a,"METHOD").resolution());assertEquals(Resolution.COMPATIBLE,symbol(a,"CLASS").resolution());
    }
    @Test void genuineNodeAbsenceDoesNotEraseFoundVerifierProof()throws Exception{
        var a=analyze(Map.of("metadata/present",new byte[0]),Map.of(OWNER+".class",ordinary()),List.of(),cls());var s=symbol(a,"CLASS");assertEquals(Resolution.MISSING_CLASS,s.resolution());assertEquals(Resolution.COMPATIBLE,context(s,ExecutionContext.TARGET_VERIFIER).resolution());assertEquals("found",context(s,ExecutionContext.TARGET_VERIFIER).proof().classStatus());
    }
}
