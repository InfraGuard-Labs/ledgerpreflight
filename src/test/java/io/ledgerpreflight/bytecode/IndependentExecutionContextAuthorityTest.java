package io.ledgerpreflight.bytecode;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

class IndependentExecutionContextAuthorityTest {
    @TempDir Path temp;
    private static final String OWNER="example/runtime/RequiredApi";
    private static byte[] definition(boolean present){
        ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,OWNER,null,"java/lang/Object",null);
        if(present)w.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"required","()V",null,null).visitEnd();w.visitEnd();return w.toByteArray();
    }
    private static byte[] zip(Map<String,byte[]> entries)throws IOException{
        ByteArrayOutputStream out=new ByteArrayOutputStream();try(ZipOutputStream z=new ZipOutputStream(out)){for(var e:new TreeMap<>(entries).entrySet()){z.putNextEntry(new ZipEntry(e.getKey()));z.write(e.getValue());z.closeEntry();}}return out.toByteArray();
    }
    private Path jar(String name,Map<String,byte[]> entries)throws IOException{return Files.write(temp.resolve(name),zip(entries));}
    private static byte[] manifest(String main){return ("Manifest-Version: 1.0\r\nMain-Class: "+main+"\r\n\r\n").getBytes(StandardCharsets.UTF_8);}
    private static TargetedRuntimeLookup lookup(Scope scope,Artifact... artifacts){return new TargetedRuntimeLookup(List.of(artifacts),Limits.defaults(),scope,List.of());}
    private static Artifact artifact(Path path,Role role){return new Artifact(path,path.getFileName().toString(),"",role);}
    private static boolean method(Result result){return result.info().members().stream().anyMatch(m->m.name().equals("required"));}

    @Test void selectedRuntimeRoleCannotBeOverriddenByIncidentalVerifierEntryClass()throws Exception{
        Path node=jar("selected-runtime.jar",Map.of("META-INF/MANIFEST.MF",manifest("net.corda.node.Corda"),OWNER+".class",definition(true),"net/corda/verifier/Main.class",new byte[]{0}));
        Path driver=jar("support.jar",Map.of(OWNER+".class",definition(false)));
        Result result=lookup(Scope.NODE_RUNTIME,artifact(node,Role.RUNTIME),artifact(driver,Role.SUPPORTING)).lookup(OWNER);
        assertEquals(State.FOUND,result.state());assertTrue(method(result));assertTrue(result.winningOrigin().startsWith("selected-runtime.jar!/"));
    }

    @Test void incidentalVerifierClassInSelectedRuntimeDoesNotInventVerifierContext()throws Exception{
        Path node=jar("selected-runtime.jar",Map.of("META-INF/MANIFEST.MF",manifest("net.corda.node.Corda"),OWNER+".class",definition(true),"net/corda/verifier/Main.class",new byte[]{0}));
        assertEquals(ContextPresence.ABSENT,lookup(Scope.VERIFIER,artifact(node,Role.RUNTIME)).contextPresence());
    }

    @Test void explicitNestedNodeEntrypointWinsOverIncidentalVerifierMarker()throws Exception{
        byte[] node=zip(Map.of("META-INF/MANIFEST.MF",manifest("net.corda.node.Corda"),OWNER+".class",definition(true),"net/corda/verifier/Main.class",new byte[]{0}));
        byte[] verifier=zip(Map.of("META-INF/MANIFEST.MF",manifest("example.ExternalVerifier"),OWNER+".class",definition(false)));
        Path capsule=jar("selected-runtime.jar",Map.of("lib/node.jar",node,"tools/verifier.jar",verifier));
        Result n=lookup(Scope.NODE_RUNTIME,artifact(capsule,Role.RUNTIME)).lookup(OWNER),v=lookup(Scope.VERIFIER,artifact(capsule,Role.RUNTIME)).lookup(OWNER);
        assertEquals(State.FOUND,n.state());assertTrue(method(n));assertEquals(State.FOUND,v.state());assertFalse(method(v));assertTrue(v.winningOrigin().contains("tools/verifier.jar"));
    }

    @Test void unresolvedManifestDependencyPreventsFalseMissingOwnerProof()throws Exception{
        byte[] headers="Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\nClass-Path: missing-shared-api.jar\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        Path verifier=jar("verifier.jar",Map.of("META-INF/MANIFEST.MF",headers,"marker.txt",new byte[]{1}));
        assertEquals(State.INCOMPLETE,lookup(Scope.VERIFIER,artifact(verifier,Role.VERIFIER)).lookup(OWNER).state(),"Unresolved declared classpath entries make absent-owner proof incomplete");
    }

    @Test void unrelatedManifestDependencyDoesNotDowngradeKnownOwnerProof()throws Exception{
        byte[] headers="Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\nClass-Path: missing-shared-api.jar\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        Path verifier=jar("verifier.jar",Map.of("META-INF/MANIFEST.MF",headers,OWNER+".class",definition(false)));
        Result result=lookup(Scope.VERIFIER,artifact(verifier,Role.VERIFIER)).lookup(OWNER);
        assertEquals(State.FOUND,result.state());assertFalse(method(result),"A later declared dependency cannot add a method to this selected definition");
    }

    @Test void earlierUnresolvedManifestDependencyPreventsCertifyingLaterShim()throws Exception{
        byte[] headers="Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\nClass-Path: missing-shared-api.jar\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        Path verifier=jar("verifier.jar",Map.of("META-INF/MANIFEST.MF",headers,"marker.txt",new byte[]{1}));
        Path shim=jar("shim.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.VERIFIER,artifact(verifier,Role.VERIFIER),artifact(shim,Role.LEGACY));
        lookup.setProvenClasspathOrder(List.of("verifier.jar","shim.jar"));
        assertEquals(State.INCOMPLETE,lookup.lookup(OWNER).state(),"An unresolved dependency before the shim could supply the winning class");
    }

    @Test void explicitEarlierWinnerSurvivesUnrelatedLaterManifestDependency()throws Exception{
        byte[] headers="Manifest-Version: 1.0\r\nMain-Class: example.ExternalVerifier\r\nClass-Path: missing-shared-api.jar\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        Path verifier=jar("verifier.jar",Map.of("META-INF/MANIFEST.MF",headers,"marker.txt",new byte[]{1}));
        Path shim=jar("shim.jar",Map.of(OWNER+".class",definition(true)));
        var lookup=lookup(Scope.VERIFIER,artifact(verifier,Role.VERIFIER),artifact(shim,Role.LEGACY));
        lookup.setProvenClasspathOrder(List.of("shim.jar","verifier.jar"));
        Result result=lookup.lookup(OWNER);assertEquals(State.FOUND,result.state());assertTrue(method(result));
    }
}
