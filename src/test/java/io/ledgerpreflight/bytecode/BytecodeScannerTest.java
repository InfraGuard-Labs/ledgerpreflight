package io.ledgerpreflight.bytecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;

class BytecodeScannerTest {
    @TempDir Path temp;
    static final String OWNER="net/corda/core/internal/InternalUtils";
    static final String DESC="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    static byte[] definition(String owner,String descriptor,boolean staticMember){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,owner,null,"java/lang/Object",null);
        if(descriptor!=null)writer.visitMethod(Opcodes.ACC_PUBLIC|(staticMember?Opcodes.ACC_STATIC:0),"sum",descriptor,null,null).visitEnd();writer.visitEnd();return writer.toByteArray();
    }
    static byte[] consumer(){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,"example/Contract",null,"java/lang/Object",null);
        MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC,"verify","()V",null,null);method.visitCode();method.visitInsn(Opcodes.ACONST_NULL);method.visitMethodInsn(Opcodes.INVOKESTATIC,OWNER,"sum",DESC,false);method.visitInsn(Opcodes.POP);method.visitInsn(Opcodes.RETURN);method.visitMaxs(1,1);method.visitEnd();writer.visitEnd();return writer.toByteArray();
    }
    Path jar(String name,Map<String,byte[]> entries)throws IOException {Path path=temp.resolve(name);Files.write(path,zip(entries));return path;}
    static byte[] zip(Map<String,byte[]> entries)throws IOException{ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(bytes)){for(var entry:new TreeMap<>(entries).entrySet()){zip.putNextEntry(new ZipEntry(entry.getKey()));zip.write(entry.getValue());zip.closeEntry();}}return bytes.toByteArray();}
    List<JarInventory> scan(Path path){ScanResult scan=new BytecodeScanner().scan(path);assertTrue(scan.issues().isEmpty(),scan.issues().toString());return scan.jars();}
    @Test void exactRemovedMethodAndInternalUsageAreBothReported()throws IOException{
        var current=scan(jar("current.jar",Map.of("example/Contract.class",consumer())));var target=scan(jar("target.jar",Map.of(OWNER+".class",definition(OWNER,null,true))));
        var issues=new CompatibilityAnalyzer().analyze(current,target,List.of(),false);
        assertTrue(issues.stream().anyMatch(i->i.id().equals("LP-API-001")&&i.severity().equals("BLOCKED")&&i.evidence().get("descriptor").equals(DESC)));
        assertTrue(issues.stream().anyMatch(i->i.id().equals("LP-INTERNAL-001")));
    }
    @Test void sameNameWrongDescriptorDoesNotSatisfyReference()throws IOException{
        var current=scan(jar("current.jar",Map.of("example/Contract.class",consumer())));var target=scan(jar("target.jar",Map.of(OWNER+".class",definition(OWNER,"(Ljava/util/Collection;)Ljava/math/BigDecimal;",true))));
        assertTrue(new CompatibilityAnalyzer().analyze(current,target,List.of(),false).stream().anyMatch(i->i.id().equals("LP-API-001")&&i.severity().equals("BLOCKED")));
    }
    @Test void runtimeRestorationAutomaticallyRemovesBlocker()throws IOException{
        var current=scan(jar("current.jar",Map.of("example/Contract.class",consumer())));var target=scan(jar("target.jar",Map.of(OWNER+".class",definition(OWNER,DESC,true))));
        assertFalse(new CompatibilityAnalyzer().analyze(current,target,List.of(),false).stream().anyMatch(i->i.severity().equals("BLOCKED")));
    }
    @Test void staticInstanceMismatchIsDetected()throws IOException{
        var current=scan(jar("current.jar",Map.of("example/Contract.class",consumer())));var target=scan(jar("target.jar",Map.of(OWNER+".class",definition(OWNER,DESC,false))));
        assertTrue(new CompatibilityAnalyzer().analyze(current,target,List.of(),false).stream().anyMatch(i->i.message().contains("static/instance")));
    }
    @Test void shimRequiresProvenPrecedenceForBlockedShadowFinding()throws IOException{
        var target=scan(jar("target.jar",Map.of(OWNER+".class",definition(OWNER,null,true))));var shim=scan(jar("shim.jar",Map.of(OWNER+".class",definition(OWNER,DESC,true))));
        var analyzer=new CompatibilityAnalyzer();assertEquals("WARNING",analyzer.analyze(List.of(),target,shim,false).get(0).severity());assertEquals("BLOCKED",analyzer.analyze(List.of(),target,shim,true).get(0).severity());
    }
    @Test void nestedArchiveIsInventoried()throws IOException{
        var jars=scan(jar("outer.jar",Map.of("lib/inner.jar",zip(Map.of(OWNER+".class",definition(OWNER,DESC,true))))));assertEquals(2,jars.size());assertTrue(jars.stream().anyMatch(j->j.path().equals("outer.jar!/lib/inner.jar")&&j.classes().containsKey(OWNER)));
    }
    @Test void multiReleaseSelectsJava17OnlyWhenManifestOptsIn()throws IOException{
        Map<String,byte[]> entries=new HashMap<>();entries.put(OWNER+".class",definition(OWNER,DESC,true));entries.put("META-INF/versions/17/"+OWNER+".class",definition(OWNER,null,true));entries.put("META-INF/versions/21/"+OWNER+".class",definition(OWNER,DESC,true));
        assertEquals(1,scan(jar("ordinary.jar",entries)).get(0).classes().get(OWNER).members().size());entries.put("META-INF/MANIFEST.MF","Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));assertEquals(0,scan(jar("multi.jar",entries)).get(0).classes().get(OWNER).members().size());
    }
    @Test void maliciousArchivePathsRejectedWithoutExtraction()throws IOException{
        var result=new BytecodeScanner().scan(jar("evil.jar",Map.of("../../outside.txt",new byte[]{1})));assertFalse(result.issues().isEmpty());assertTrue(result.jars().isEmpty());assertFalse(Files.exists(temp.getParent().resolve("outside.txt")));
    }
    @Test void boundedArchiveExpansionStopsBomb()throws IOException{
        Path input=jar("bomb.jar",Map.of("large.txt",new byte[10000]));var result=new BytecodeScanner(new Limits(100000,1024,4096,100,2,100,100)).scan(input);assertFalse(result.issues().isEmpty());assertTrue(result.jars().isEmpty());
    }
    @Test void malformedJarProducesStructuredIssue()throws IOException{
        Path input=temp.resolve("broken.jar");Files.writeString(input,"not a zip");var result=new BytecodeScanner().scan(input);assertEquals(1,result.issues().size());assertTrue(result.jars().isEmpty());
    }
    @Test void malformedClassProducesStructuredIssue()throws IOException{
        var result=new BytecodeScanner().scan(jar("broken-class.jar",Map.of("Test.class",new byte[]{1,2,3})));assertFalse(result.issues().isEmpty());
    }
    @Test void missingZipEndRecordIsRejected()throws IOException{
        byte[] complete=zip(Map.of(OWNER+".class",definition(OWNER,DESC,true)));Path input=temp.resolve("truncated.jar");Files.write(input,Arrays.copyOf(complete,complete.length-22));var result=new BytecodeScanner().scan(input);assertFalse(result.issues().isEmpty());assertTrue(result.jars().isEmpty());
    }
    @Test void truncatedNestedArchiveIsReported()throws IOException{
        byte[] complete=zip(Map.of(OWNER+".class",definition(OWNER,DESC,true)));var result=new BytecodeScanner().scan(jar("nested-broken.jar",Map.of("inner.jar",Arrays.copyOf(complete,complete.length-22))));assertFalse(result.issues().isEmpty());assertFalse(result.jars().stream().anyMatch(j->j.path().contains("!/")));
    }
    @Test void symlinkEscapeSkipped()throws IOException{
        Path outside=temp.resolve("outside");Files.createDirectory(outside);Files.write(outside.resolve("x.jar"),zip(Map.of(OWNER+".class",definition(OWNER,DESC,true))));Path root=temp.resolve("root");Files.createDirectory(root);
        try{Files.createSymbolicLink(root.resolve("link"),outside);}catch(UnsupportedOperationException|FileSystemException e){org.junit.jupiter.api.Assumptions.assumeTrue(false,"Symlinks unavailable in test environment");}
        var result=new BytecodeScanner().scan(root);assertTrue(result.jars().isEmpty());assertFalse(result.issues().isEmpty());
    }
    @Test void scanAndFindingsAreDeterministic()throws IOException{
        Path path=jar("current.jar",Map.of("example/Contract.class",consumer()));assertEquals(new BytecodeScanner().scan(path),new BytecodeScanner().scan(path));
    }
    @Test void bootstrapHandlesAreExactMemberReferences()throws IOException{
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,"example/Dynamic",null,"java/lang/Object",null);MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC,"call","()V",null,null);method.visitCode();method.visitLdcInsn(new Handle(Opcodes.H_INVOKESTATIC,OWNER,"sum",DESC,false));method.visitInsn(Opcodes.POP);method.visitInsn(Opcodes.RETURN);method.visitMaxs(1,1);method.visitEnd();writer.visitEnd();var inventory=scan(jar("dynamic.jar",Map.of("example/Dynamic.class",writer.toByteArray())));assertTrue(inventory.get(0).classes().get("example/Dynamic").references().stream().anyMatch(r->r.owner().equals(OWNER)&&r.descriptor().equals(DESC)&&r.isStatic()));
    }
    @Test void inheritedMethodSatisfiesReference()throws IOException{
        ClassWriter child=new ClassWriter(0);child.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,OWNER,null,"example/Parent",null);child.visitEnd();var current=scan(jar("current.jar",Map.of("example/Contract.class",consumer())));var target=scan(jar("target.jar",Map.of(OWNER+".class",child.toByteArray(),"example/Parent.class",definition("example/Parent",DESC,true))));assertFalse(new CompatibilityAnalyzer().analyze(current,target,List.of(),false).stream().anyMatch(i->i.severity().equals("BLOCKED")));
    }
    @Test void missingParentMakesMissingMemberUncertain()throws IOException{
        ClassWriter child=new ClassWriter(0);child.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,OWNER,null,"example/Unknown",null);child.visitEnd();var current=scan(jar("current.jar",Map.of("example/Contract.class",consumer())));var target=scan(jar("target.jar",Map.of(OWNER+".class",child.toByteArray())));assertTrue(new CompatibilityAnalyzer().analyze(current,target,List.of(),false).stream().anyMatch(i->i.id().equals("LP-API-001")&&i.severity().equals("WARNING")));
    }
    @Test void exactFieldDescriptorsAndStaticSemanticsAreCompared()throws IOException{
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,"example/Fields",null,"java/lang/Object",null);MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC,"read","()V",null,null);method.visitCode();method.visitFieldInsn(Opcodes.GETSTATIC,OWNER,"value","I");method.visitInsn(Opcodes.POP);method.visitInsn(Opcodes.RETURN);method.visitMaxs(1,1);method.visitEnd();writer.visitEnd();
        ClassWriter target=new ClassWriter(0);target.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,OWNER,null,"java/lang/Object",null);target.visitField(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"value","J",null,null).visitEnd();target.visitEnd();
        var current=scan(jar("fields.jar",Map.of("example/Fields.class",writer.toByteArray())));var runtime=scan(jar("runtime.jar",Map.of(OWNER+".class",target.toByteArray())));assertTrue(new CompatibilityAnalyzer().analyze(current,runtime,List.of(),false).stream().anyMatch(i->i.id().equals("LP-API-001")&&i.evidence().get("kind").equals("FIELD")&&i.evidence().get("descriptor").equals("I")));
    }
    @Test void constructorsAreNotInherited()throws IOException{
        ClassWriter consumer=new ClassWriter(0);consumer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC,"example/Constructor",null,"java/lang/Object",null);MethodVisitor method=consumer.visitMethod(Opcodes.ACC_PUBLIC,"call","()V",null,null);method.visitCode();method.visitTypeInsn(Opcodes.NEW,OWNER);method.visitInsn(Opcodes.DUP);method.visitMethodInsn(Opcodes.INVOKESPECIAL,OWNER,"<init>","()V",false);method.visitInsn(Opcodes.POP);method.visitInsn(Opcodes.RETURN);method.visitMaxs(2,1);method.visitEnd();consumer.visitEnd();
        var current=scan(jar("construct.jar",Map.of("example/Constructor.class",consumer.toByteArray())));var target=scan(jar("target.jar",Map.of(OWNER+".class",definition(OWNER,null,true))));assertTrue(new CompatibilityAnalyzer().analyze(current,target,List.of(),false).stream().anyMatch(i->i.id().equals("LP-API-001")&&i.severity().equals("BLOCKED")&&i.evidence().get("member").equals("<init>")));
    }
    @Test void recursionLimitStopsNestedJarChain()throws IOException{
        byte[] nested=zip(Map.of("leaf.txt",new byte[]{1}));for(int i=0;i<3;i++)nested=zip(Map.of("inner.jar",nested));Path input=temp.resolve("deep.jar");Files.write(input,nested);var result=new BytecodeScanner(new Limits(1000000,1000000,1000000,100,1,100,100)).scan(input);assertFalse(result.issues().isEmpty());assertTrue(result.jars().isEmpty());
    }
    @Test void legacyDuplicatesAreReportedWithoutTargetClass()throws IOException{
        var first=scan(jar("one.jar",Map.of(OWNER+".class",definition(OWNER,DESC,true))));var second=scan(jar("two.jar",Map.of(OWNER+".class",definition(OWNER,DESC,true))));List<JarInventory> legacy=new ArrayList<>(first);legacy.addAll(second);assertTrue(new CompatibilityAnalyzer().analyze(List.of(),List.of(),legacy,false).stream().anyMatch(i->i.id().equals("LP-LEGACY-002")&&i.severity().equals("WARNING")));
    }
}
