package io.ledgerpreflight.bytecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

class TargetedRuntimeLookupTest {
    @TempDir Path temp;
    private static final String OWNER="example/runtime/RequiredApi";
    private static byte[] definition(String owner,String descriptor){
        ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,owner,null,"java/lang/Object",null);
        w.visitField(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"value","J",null,null).visitEnd();
        if(descriptor!=null)w.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"calculate",descriptor,null,null).visitEnd();
        w.visitEnd();return w.toByteArray();
    }
    private static byte[] zip(Map<String,byte[]> entries)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();try(ZipOutputStream z=new ZipOutputStream(out)){
            for(var item:new TreeMap<>(entries).entrySet()){z.putNextEntry(new ZipEntry(item.getKey()));z.write(item.getValue());z.closeEntry();}
        }return out.toByteArray();
    }
    private Path jar(String name,Map<String,byte[]> entries)throws IOException {return Files.write(temp.resolve(name),zip(entries));}
    private TargetedRuntimeLookup lookup(Path path){return new TargetedRuntimeLookup(List.of(new Artifact(path,path.getFileName().toString())));}
    private static Limits limits(long bytes,int entries,int depth,int owners,int classBytes,long signatureBytes){
        return new Limits(1024*1024,1024*1024,bytes,entries,depth,32,owners,classBytes,200,signatureBytes,30000,17);
    }
    @Test void exactLookupRetainsOnlySignaturesAndPhysicalComponentOrigin()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"(Ljava/lang/String;)I")));
        Result result=lookup(path).lookup(OWNER);assertEquals(State.FOUND,result.state());assertTrue(result.info().references().isEmpty());
        assertTrue(result.info().members().stream().anyMatch(m->m.kind().equals("METHOD")&&m.name().equals("calculate")&&m.descriptor().equals("(Ljava/lang/String;)I")));
        assertTrue(result.info().members().stream().anyMatch(m->m.kind().equals("FIELD")&&m.descriptor().equals("J")));
        assertEquals(List.of("runtime.jar!/"+OWNER+".class"),result.origins());
    }
    @Test void nestedComponentsAreSearchedThroughTwoLevels()throws Exception {
        Path path=jar("runtime.bin",Map.of("lib/outer.jar",zip(Map.of("components/api.jar",zip(Map.of(OWNER+".class",definition(OWNER,"()V")))))));
        Result result=lookup(path).lookup(OWNER);assertEquals(State.FOUND,result.state());assertTrue(result.origins().get(0).contains("runtime.bin!/lib/outer.jar!/components/api.jar!/"));
    }
    @Test void absenceRequiresCompleteNestedLookup()throws Exception {
        Path path=jar("runtime.jar",Map.of("api.jar",zip(Map.of("example/Other.class",definition("example/Other",null)))));
        assertEquals(State.ABSENT,lookup(path).lookup(OWNER).state());
    }
    @Test void broadPartialDoesNotPoisonRequiredClassLookup()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V"),"unrelated/Huge.class",new byte[3*1024*1024],"large-resource.bin",new byte[33*1024*1024]));
        assertFalse(new BytecodeScanner().scan(path).issues().isEmpty());assertEquals(State.FOUND,lookup(path).lookup(OWNER).state());
    }
    @Test void duplicateOwnersAcrossComponentsAreAmbiguousEvenIfDefinitionsMatch()throws Exception {
        byte[] api=zip(Map.of(OWNER+".class",definition(OWNER,"()V")));
        Path path=jar("runtime.jar",Map.of("first.jar",api,"second.jar",api));assertEquals(State.AMBIGUOUS,lookup(path).lookup(OWNER).state());
    }
    @Test void duplicateOwnersAcrossPhysicalArtifactsAreAmbiguous()throws Exception {
        Path a=jar("one.jar",Map.of(OWNER+".class",definition(OWNER,"()V"))),b=jar("two.jar",Map.of(OWNER+".class",definition(OWNER,"()V")));
        assertEquals(State.AMBIGUOUS,new TargetedRuntimeLookup(List.of(new Artifact(a,"one.jar"),new Artifact(b,"two.jar"))).lookup(OWNER).state());
    }
    @Test void malformedNestedArchivePreventsFalseFoundAndFalseAbsent()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V"),"broken.jar",new byte[]{1,2,3}));
        var lookup=lookup(path);lookup.prefetch(List.of(OWNER,"example/Absent"));assertEquals(State.INCOMPLETE,lookup.lookup(OWNER).state());assertEquals(State.INCOMPLETE,lookup.lookup("example/Absent").state());
    }
    @Test void malformedRequiredClassDoesNotPoisonIndependentOwner()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V"),"example/Broken.class",new byte[]{1,2,3}));
        var lookup=lookup(path);lookup.prefetch(List.of(OWNER,"example/Broken"));assertEquals(State.FOUND,lookup.lookup(OWNER).state());assertEquals(State.INCOMPLETE,lookup.lookup("example/Broken").state());
    }
    @Test void mismatchedClassEntryNameCannotProvePresence()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition("example/Other","()V")));assertEquals(State.INCOMPLETE,lookup(path).lookup(OWNER).state());
    }
    @Test void traversalAndMalformedArchiveAreIncompleteWithoutExtraction()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V"),"../outside",new byte[]{1}));assertEquals(State.INCOMPLETE,lookup(path).lookup(OWNER).state());
        Path invalid=Files.writeString(temp.resolve("invalid.jar"),"not an archive");assertEquals(State.INCOMPLETE,lookup(invalid).lookup(OWNER).state());assertFalse(Files.exists(temp.getParent().resolve("outside")));
    }
    @Test void ownByteEntryDepthAndCacheLimitsRemainIncomplete()throws Exception {
        Path path=jar("runtime.jar",Map.of("lib/api.jar",zip(Map.of(OWNER+".class",definition(OWNER,"()V")))));
        var artifact=List.of(new Artifact(path,"runtime.jar"));
        for(Limits budget:List.of(limits(1,100,4,16,10000,100000),limits(100000,1,4,16,10000,100000),limits(100000,100,0,16,10000,100000),limits(100000,100,4,16,1,100000),limits(100000,100,4,16,10000,1)))
            assertEquals(State.INCOMPLETE,new TargetedRuntimeLookup(artifact,budget).lookup(OWNER).state(),budget.toString());
        var limited=new TargetedRuntimeLookup(artifact,limits(100000,100,4,1,10000,100000));limited.prefetch(List.of(OWNER,"example/Another"));assertEquals(State.FOUND,limited.lookup(OWNER).state());assertEquals(State.INCOMPLETE,limited.lookup("example/Another").state());
    }
    @Test void unopenedUnrelatedClassSizeDoesNotConsumeTargetedBudget()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V"),"example/Large.class",new byte[30000]));
        var lookup=new TargetedRuntimeLookup(List.of(new Artifact(path,"runtime.jar")),limits(1000,100,4,16,1000,100000));
        lookup.prefetch(List.of(OWNER,"example/Large"));assertEquals(State.FOUND,lookup.lookup(OWNER).state());assertEquals(State.INCOMPLETE,lookup.lookup("example/Large").state());
    }
    @Test void javaEightAndSeventeenChooseTheirOwnMultiReleaseDefinition()throws Exception {
        Path path=jar("runtime.jar",Map.of("META-INF/MANIFEST.MF","Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),OWNER+".class",definition(OWNER,"()V"),"META-INF/versions/17/"+OWNER+".class",definition(OWNER,null)));
        var artifacts=List.of(new Artifact(path,"runtime.jar"));
        assertEquals(2,new TargetedRuntimeLookup(artifacts,8).lookup(OWNER).info().members().size());assertEquals(1,new TargetedRuntimeLookup(artifacts,17).lookup(OWNER).info().members().size());
    }
    @Test void largeSignedManifestSectionsDoNotPreventRequiredClassLookup()throws Exception {
        StringBuilder manifest=new StringBuilder("Manifest-Version: 1.0\r\nMulti-Release: true\r\nClass-Path: unused.jar\r\n");
        for(int i=0;i<2000;i++)manifest.append(" unused-component-").append(i).append(".jar\r\n");
        manifest.append("\r\n");for(int i=0;i<12000;i++)manifest.append("Name: unrelated/Entry").append(i).append(".class\r\nSHA-256-Digest: synthetic-manifest-section\r\n\r\n");
        Path path=jar("signed-runtime.jar",Map.of("META-INF/MANIFEST.MF",manifest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),OWNER+".class",definition(OWNER,"()V"),"META-INF/versions/17/"+OWNER+".class",definition(OWNER,null)));
        Result result=lookup(path).lookup(OWNER);assertEquals(State.FOUND,result.state());assertEquals(1,result.info().members().size());assertTrue(result.origins().get(0).contains("META-INF/versions/17/"));
    }
    @Test void unsupportedAndPreviewBytecodeCannotEstablishCompatibility()throws Exception {
        byte[] future=definition(OWNER,"()V");future[7]=65;
        Path futureJar=jar("future.jar",Map.of(OWNER+".class",future));assertEquals(State.INCOMPLETE,lookup(futureJar).lookup(OWNER).state());
        byte[] preview=definition(OWNER,"()V");preview[4]=(byte)255;preview[5]=(byte)255;preview[7]=61;
        Path previewJar=jar("preview.jar",Map.of(OWNER+".class",preview));assertEquals(State.INCOMPLETE,lookup(previewJar).lookup(OWNER).state());
        preview[4]=0;preview[5]=1;Path invalidMinor=jar("invalid-minor.jar",Map.of(OWNER+".class",preview));assertEquals(State.INCOMPLETE,lookup(invalidMinor).lookup(OWNER).state());
        byte[] java17=definition(OWNER,"()V");java17[7]=61;
        Path seventeenJar=jar("seventeen.jar",Map.of(OWNER+".class",java17));var artifacts=List.of(new Artifact(seventeenJar,"seventeen.jar"));
        assertEquals(State.INCOMPLETE,new TargetedRuntimeLookup(artifacts,8).lookup(OWNER).state());assertEquals(State.FOUND,new TargetedRuntimeLookup(artifacts,17).lookup(OWNER).state());
    }
    @Test void expectedIdentityHashAndSnapshotAreChecked()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V")));String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
        var correct=new TargetedRuntimeLookup(List.of(new Artifact(path,"runtime.jar",digest)));assertEquals(State.FOUND,correct.lookup(OWNER).state());
        var incorrect=new TargetedRuntimeLookup(List.of(new Artifact(path,"runtime.jar","0".repeat(64))));assertEquals(State.INCOMPLETE,incorrect.lookup(OWNER).state());assertEquals(State.INCOMPLETE,incorrect.lookup("example/Another").state());
        Files.writeString(path,"changed");assertEquals(State.INCOMPLETE,correct.lookup(OWNER).state());
    }
    @Test void symlinkIsNotFollowedByDirectLookup()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V"))),link=temp.resolve("linked.jar");Files.createSymbolicLink(link,path);
        assertEquals(State.INCOMPLETE,lookup(link).lookup(OWNER).state());
    }
    @Test void selectedEntryCrcMismatchCannotProduceAProof()throws Exception {
        byte[] data=zip(Map.of(OWNER+".class",definition(OWNER,"()V")));
        for(int i=0;i<data.length-20;i++)if(data[i]==0x50&&data[i+1]==0x4b&&data[i+2]==1&&data[i+3]==2){data[i+16]^=1;break;}
        Path path=Files.write(temp.resolve("crc.jar"),data);assertEquals(State.INCOMPLETE,lookup(path).lookup(OWNER).state());
    }
    @Test void duplicateArchiveNamesAndNestedBombDoNotEstablishUniqueness()throws Exception {
        byte[] component=zip(Map.of(OWNER+".class",definition(OWNER,"()V"))),data=zip(Map.of("first.jar",component,"other.jar",component));
        byte[] before="other.jar".getBytes(java.nio.charset.StandardCharsets.UTF_8),after="first.jar".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for(int i=0;i<=data.length-before.length;i++){boolean equal=true;for(int j=0;j<before.length;j++)if(data[i+j]!=before[j])equal=false;if(equal)System.arraycopy(after,0,data,i,after.length);}
        Path duplicate=Files.write(temp.resolve("duplicate.jar"),data);assertEquals(State.INCOMPLETE,lookup(duplicate).lookup(OWNER).state());
        Path bomb=jar("bomb.jar",Map.of(OWNER+".class",definition(OWNER,"()V"),"bomb.jar",new byte[2*1024*1024]));assertEquals(State.INCOMPLETE,lookup(bomb).lookup(OWNER).state());
    }
    @Test void batchedAndRepeatedLookupAreDeterministic()throws Exception {
        Path path=jar("runtime.jar",Map.of(OWNER+".class",definition(OWNER,"()V")));var a=lookup(path);a.prefetch(List.of(OWNER,"example/Absent"));var b=lookup(path);b.prefetch(List.of("example/Absent",OWNER));
        assertEquals(a.lookup(OWNER),b.lookup(OWNER));assertEquals(a.lookup("example/Absent"),b.lookup("example/Absent"));assertSame(a.lookup(OWNER),a.lookup(OWNER));
        assertEquals(State.INCOMPLETE,a.lookup(null).state());assertEquals(State.INCOMPLETE,a.lookup("../outside").state());
    }
}
