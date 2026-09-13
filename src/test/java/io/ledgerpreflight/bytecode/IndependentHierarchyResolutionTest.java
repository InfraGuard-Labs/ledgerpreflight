package io.ledgerpreflight.bytecode;

import java.lang.reflect.InvocationTargetException;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import io.ledgerpreflight.bytecode.TargetedRuntimeLookup.Limits;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

/** Independent JVM execution oracles; no product/runtime-specific hierarchy names. */
class IndependentHierarchyResolutionTest {
    @TempDir Path scratch;
    private static final int P=Opcodes.ACC_PUBLIC,S=Opcodes.ACC_STATIC,F=Opcodes.ACC_FINAL,FACE=P|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT;
    private static final String OWNER="fixture/runtime/Facade",CALLER="fixture/contract/Caller",DESC="(Ljava/lang/Iterable;I)I";
    private static final Member STATIC_METHOD=new Member("METHOD","helper",DESC,P|S);
    private static final Member INSTANCE_METHOD=new Member("METHOD","helper",DESC,P);
    private static Reference method(int opcode){return new Reference("run()I","METHOD",OWNER,"helper",DESC,opcode,opcode==Opcodes.INVOKEINTERFACE);}
    private static byte[] type(String name,String parent,int access,List<String> faces,Member member,Integer value,boolean constructor){
        ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,access|((access&Opcodes.ACC_INTERFACE)==0?Opcodes.ACC_SUPER:0),name,null,parent,faces.toArray(String[]::new));
        if(constructor&&(access&Opcodes.ACC_INTERFACE)==0){var m=w.visitMethod(P,"<init>","()V",null,null);m.visitCode();m.visitVarInsn(Opcodes.ALOAD,0);m.visitMethodInsn(Opcodes.INVOKESPECIAL,parent,"<init>","()V",false);m.visitInsn(Opcodes.RETURN);m.visitMaxs(1,1);m.visitEnd();}
        if(member!=null){
            if(member.kind().equals("FIELD")){Object constant=member.descriptor().equals("J")?(Object)Long.valueOf(7):Integer.valueOf(7);w.visitField(member.access(),member.name(),member.descriptor(),null,constant).visitEnd();}
            else {var m=w.visitMethod(member.access(),member.name(),member.descriptor(),null,null);if((member.access()&Opcodes.ACC_ABSTRACT)==0){m.visitCode();m.visitIntInsn(Opcodes.BIPUSH,value==null?7:value);m.visitInsn(Opcodes.IRETURN);int locals=member.isStatic()?0:1;for(var t:Type.getArgumentTypes(member.descriptor()))locals+=t.getSize();m.visitMaxs(1,locals);}m.visitEnd();}
        }
        w.visitEnd();return w.toByteArray();
    }
    private static byte[] type(String name,String parent,int access,List<String> faces,Member member,Integer value){return type(name,parent,access,faces,member,value,true);}
    private static Map<String,byte[]> direct(Member member){return Map.of(OWNER,type(OWNER,"java/lang/Object",P,List.of(),member,7));}
    private static Map<String,byte[]> chain(String prefix,int depth,Member member){
        Map<String,byte[]> result=new HashMap<>();result.put(OWNER,type(OWNER,"fixture/runtime/"+prefix+"0",P,List.of(),null,null));
        for(int i=0;i<depth;i++){String name="fixture/runtime/"+prefix+i,parent=i+1==depth?"java/lang/Object":"fixture/runtime/"+prefix+(i+1);result.put(name,type(name,parent,0,List.of(),i+1==depth?member:null,7));}
        return result;
    }
    private static ClassInfo info(byte[] bytes){
        ClassReader r=new ClassReader(bytes);List<Member> members=new ArrayList<>();r.accept(new ClassVisitor(Opcodes.ASM9){
            @Override public MethodVisitor visitMethod(int access,String name,String desc,String sig,String[] exceptions){members.add(new Member("METHOD",name,desc,access));return null;}
            @Override public FieldVisitor visitField(int access,String name,String desc,String sig,Object value){members.add(new Member("FIELD",name,desc,access));return null;}
        },ClassReader.SKIP_CODE|ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
        return new ClassInfo(r.getClassName(),r.getSuperName(),List.of(r.getInterfaces()),r.getAccess(),r.readUnsignedShort(6),members,List.of());
    }
    private static Lookup lookup(Map<String,byte[]> bytes){
        Map<String,ClassInfo> classes=new HashMap<>();bytes.forEach((name,body)->classes.put(name,info(body)));
        return name->classes.containsKey(name)?new Result(State.FOUND,classes.get(name),List.of("runtime.jar!/"+name+".class"),"Complete independent synthetic directory"):new Result(State.ABSENT,null,List.of(),"Complete independent synthetic directory");
    }
    private static Analysis analyze(Reference ref,Map<String,byte[]> before,Map<String,byte[]> after,boolean subclass){
        ClassInfo caller=new ClassInfo(CALLER,subclass?OWNER:"java/lang/Object",List.of(),P|Opcodes.ACC_SUPER,52,List.of(),List.of(ref));
        JarInventory app=new JarInventory("cordapps/historical.jar","synthetic",Map.of(),Map.of(CALLER,caller),List.of());
        return new RequiredSymbolAnalyzer().analyze(List.of(app),lookup(before),lookup(after));
    }
    private static SymbolResult only(Analysis a){assertEquals(1,a.symbols().size());return a.symbols().get(0);}
    private static byte[] invocation(Reference ref,boolean subclass){
        ClassWriter w=new ClassWriter(0);String parent=subclass?OWNER:"java/lang/Object";w.visit(Opcodes.V1_8,P|Opcodes.ACC_SUPER,CALLER,null,parent,null);
        var init=w.visitMethod(P,"<init>","()V",null,null);init.visitCode();init.visitVarInsn(Opcodes.ALOAD,0);init.visitMethodInsn(Opcodes.INVOKESPECIAL,parent,"<init>","()V",false);init.visitInsn(Opcodes.RETURN);init.visitMaxs(1,1);init.visitEnd();
        var m=w.visitMethod(P|S,"run","()I",null,null);m.visitCode();
        if(!ref.isStatic()){String receiver=subclass?CALLER:OWNER;m.visitTypeInsn(Opcodes.NEW,receiver);m.visitInsn(Opcodes.DUP);m.visitMethodInsn(Opcodes.INVOKESPECIAL,receiver,"<init>","()V",false);}
        if(ref.kind().equals("FIELD")){m.visitFieldInsn(ref.opcode(),ref.owner(),ref.name(),ref.descriptor());if(ref.descriptor().equals("J"))m.visitInsn(Opcodes.L2I);}
        else {for(Type argument:Type.getArgumentTypes(ref.descriptor())){if(argument.getSort()==Type.INT)m.visitIntInsn(Opcodes.BIPUSH,7);else m.visitInsn(Opcodes.ACONST_NULL);}m.visitMethodInsn(ref.opcode(),ref.owner(),ref.name(),ref.descriptor(),Boolean.TRUE.equals(ref.ownerInterface()));}
        m.visitInsn(Opcodes.IRETURN);m.visitMaxs(4,0);m.visitEnd();w.visitEnd();return w.toByteArray();
    }
    private static Object run(Map<String,byte[]> runtime,Reference ref,boolean subclass)throws Throwable{
        Map<String,byte[]> bytes=new HashMap<>(runtime);bytes.put(CALLER,invocation(ref,subclass));
        ClassLoader loader=new ClassLoader(IndependentHierarchyResolutionTest.class.getClassLoader()){@Override protected Class<?> findClass(String name)throws ClassNotFoundException{byte[] body=bytes.get(name.replace('.','/'));if(body==null)throw new ClassNotFoundException(name);return defineClass(name,body,0,body.length);}};
        try{return loader.loadClass(CALLER.replace('/','.')).getMethod("run").invoke(null);}catch(InvocationTargetException e){throw e.getCause();}
    }

    @Test void publicFacadeThroughNonPublicLayersResolvesInheritedStaticInDifferentChains()throws Throwable{
        var before=chain("OldLayer",18,STATIC_METHOD);var after=chain("NewLayer",23,STATIC_METHOD);Reference ref=method(Opcodes.INVOKESTATIC);
        assertEquals(7,run(before,ref,false));assertEquals(7,run(after,ref,false));var a=analyze(ref,before,after,false);var p=only(a);
        assertEquals(Resolution.COMPATIBLE,p.resolution());assertTrue(a.complete());assertTrue(a.findings().isEmpty());assertEquals("fixture/runtime/OldLayer17",p.current().declaringClass());assertEquals("fixture/runtime/NewLayer22",p.target().declaringClass());assertEquals(List.of("runtime.jar!/fixture/runtime/OldLayer17.class"),p.current().declaringArtifacts());assertEquals(List.of("runtime.jar!/fixture/runtime/NewLayer22.class"),p.target().declaringArtifacts());
    }
    @Test void inheritedCurrentMethodAndCompletelyMissingTargetRemainConfirmedBlocker()throws Throwable{
        var before=chain("Old",5,STATIC_METHOD);var after=chain("New",8,null);var ref=method(Opcodes.INVOKESTATIC);
        assertEquals(7,run(before,ref,false));assertThrows(NoSuchMethodError.class,()->run(after,ref,false));var a=analyze(ref,before,after,false);
        assertEquals(Resolution.MISSING_METHOD,only(a).resolution());assertTrue(a.complete());assertEquals("BLOCKED",a.findings().get(0).severity());
    }
    @Test void changedDescriptorInAncestorIsNotCompatible()throws Throwable{
        var before=chain("Old",4,STATIC_METHOD);var after=chain("New",5,new Member("METHOD","helper","(Ljava/lang/String;)I",P|S));var ref=method(Opcodes.INVOKESTATIC);
        assertThrows(NoSuchMethodError.class,()->run(after,ref,false));var p=only(analyze(ref,before,after,false));assertEquals(Resolution.DESCRIPTOR_MISMATCH,p.resolution());assertEquals(List.of("(Ljava/lang/String;)I"),p.target().availableDescriptors());
    }
    @Test void inheritedStaticFieldThroughNonPublicBaseRemainsAccessible()throws Throwable{
        Member field=new Member("FIELD","amount","J",P|S|F);var ref=new Reference("run()I","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC);var after=chain("Fields",4,field);
        assertEquals(7,run(after,ref,false));var p=only(analyze(ref,direct(field),after,false));assertEquals(Resolution.COMPATIBLE,p.resolution());assertEquals("fixture/runtime/Fields3",p.target().declaringClass());
    }
    @Test void fieldWithDifferentDescriptorOnFacadeDoesNotHideExactInheritedField()throws Throwable{
        Member field=new Member("FIELD","amount","J",P|S|F);var ref=new Reference("run()I","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC);var after=chain("Fields",2,field);
        after.put(OWNER,type(OWNER,"fixture/runtime/Fields0",P,List.of(),new Member("FIELD","amount","I",P|S|F),null));
        assertEquals(7,run(after,ref,false));assertEquals(Resolution.COMPATIBLE,only(analyze(ref,direct(field),after,false)).resolution());
    }
    @Test void inheritedFieldStaticInstanceMismatchStillBlocks()throws Throwable{
        Member field=new Member("FIELD","amount","J",P|S|F);var ref=new Reference("run()I","FIELD",OWNER,"amount","J",Opcodes.GETSTATIC);var after=chain("Fields",2,new Member("FIELD","amount","J",P));
        assertThrows(IncompatibleClassChangeError.class,()->run(after,ref,false));assertEquals(Resolution.INVOCATION_MISMATCH,only(analyze(ref,direct(field),after,false)).resolution());
    }
    @Test void inheritedMethodStaticInstanceMismatchStillBlocks()throws Throwable{
        var ref=method(Opcodes.INVOKESTATIC);var after=chain("Mismatch",4,INSTANCE_METHOD);
        assertThrows(IncompatibleClassChangeError.class,()->run(after,ref,false));assertEquals(Resolution.INVOCATION_MISMATCH,only(analyze(ref,direct(STATIC_METHOD),after,false)).resolution());
    }
    @Test void inaccessibleInheritedMemberDoesNotBecomePublicThroughFacade()throws Throwable{
        var ref=method(Opcodes.INVOKESTATIC);
        for(int access:List.of(S,Opcodes.ACC_PRIVATE|S)){
            var after=chain("Restricted",3,new Member("METHOD","helper",DESC,access));
            assertThrows(IllegalAccessError.class,()->run(after,ref,false));assertNotEquals(Resolution.COMPATIBLE,only(analyze(ref,direct(STATIC_METHOD),after,false)).resolution());
        }
    }
    @Test void legalSpecialCallResolvesInheritedSuperclassMethod()throws Throwable{
        var ref=method(Opcodes.INVOKESPECIAL);var after=chain("Special",4,INSTANCE_METHOD);
        assertEquals(7,run(after,ref,true));assertEquals(Resolution.COMPATIBLE,only(analyze(ref,direct(INSTANCE_METHOD),after,true)).resolution());
    }
    @Test void specialCallFromUnrelatedCallerIsNotProvenCompatible()throws Throwable{
        var ref=method(Opcodes.INVOKESPECIAL);var runtime=direct(INSTANCE_METHOD);
        assertThrows(VerifyError.class,()->run(runtime,ref,false));assertNotEquals(Resolution.COMPATIBLE,only(analyze(ref,runtime,runtime,false)).resolution());
    }
    private static Map<String,byte[]> superclassDefaults(boolean specific,boolean classMethod){
        String first="fixture/runtime/First",second="fixture/runtime/Second",parent="fixture/runtime/Parent";Map<String,byte[]> result=new HashMap<>();
        result.put(first,type(first,"java/lang/Object",FACE,List.of(),INSTANCE_METHOD,11));result.put(second,type(second,"java/lang/Object",FACE,specific?List.of(first):List.of(),INSTANCE_METHOD,29));
        result.put(parent,type(parent,"java/lang/Object",P,List.of(first),classMethod?INSTANCE_METHOD:null,7));result.put(OWNER,type(OWNER,parent,P,List.of(second),null,null));return result;
    }
    @Test void moreSpecificChildInterfaceWinsOverSuperclassInterfaceDefault()throws Throwable{
        var ref=method(Opcodes.INVOKEVIRTUAL);var after=superclassDefaults(true,false);assertEquals(29,run(after,ref,false));var p=only(analyze(ref,direct(INSTANCE_METHOD),after,false));
        assertEquals(Resolution.COMPATIBLE,p.resolution());assertEquals("fixture/runtime/Second",p.target().declaringClass());
    }
    @Test void defaultConflictAcrossSuperclassAndChildInterfacesCannotBeCompatible()throws Throwable{
        var ref=method(Opcodes.INVOKEVIRTUAL);var after=superclassDefaults(false,false);assertThrows(IncompatibleClassChangeError.class,()->run(after,ref,false));
        assertNotEquals(Resolution.COMPATIBLE,only(analyze(ref,direct(INSTANCE_METHOD),after,false)).resolution());
    }
    @Test void realSuperclassClassMethodDominatesCompetingInterfaceDefaults()throws Throwable{
        var ref=method(Opcodes.INVOKEVIRTUAL);var after=superclassDefaults(false,true);assertEquals(7,run(after,ref,false));var p=only(analyze(ref,direct(INSTANCE_METHOD),after,false));
        assertEquals(Resolution.COMPATIBLE,p.resolution());assertEquals("fixture/runtime/Parent",p.target().declaringClass());
    }
    @Test void staticInterfaceMethodIsNotInheritedBySubinterface()throws Throwable{
        var ref=new Reference("run()I","METHOD",OWNER,"helper",DESC,Opcodes.INVOKESTATIC,true);String parent="fixture/runtime/StaticFace";
        var before=Map.of(OWNER,type(OWNER,"java/lang/Object",FACE,List.of(),STATIC_METHOD,7));var after=Map.of(OWNER,type(OWNER,"java/lang/Object",FACE,List.of(parent),null,null),parent,type(parent,"java/lang/Object",FACE,List.of(),STATIC_METHOD,7));
        assertEquals(7,run(before,ref,false));assertThrows(NoSuchMethodError.class,()->run(after,ref,false));assertEquals(Resolution.MISSING_METHOD,only(analyze(ref,before,after,false)).resolution());
    }
    @Test void publicObjectMethodRecordsActualDeclaringClass(){
        for(boolean face:List.of(false,true)){
            var ref=new Reference("run()V","METHOD",OWNER,"toString","()Ljava/lang/String;",face?Opcodes.INVOKEINTERFACE:Opcodes.INVOKEVIRTUAL,face);
            var runtime=Map.of(OWNER,type(OWNER,"java/lang/Object",face?FACE:P,List.of(),null,null));var p=only(analyze(ref,runtime,runtime,false));
            assertEquals(Resolution.COMPATIBLE,p.resolution());assertEquals("java/lang/Object",p.current().declaringClass());assertEquals("java/lang/Object",p.target().declaringClass());
        }
    }
    @Test void constructorIsNotInheritedEvenWhenParentDeclaresExactConstructor(){
        var ref=new Reference("run()V","METHOD",OWNER,"<init>","()V",Opcodes.INVOKESPECIAL,false);String parent="fixture/runtime/Parent";
        var after=Map.of(OWNER,type(OWNER,parent,P,List.of(),null,null,false),parent,type(parent,"java/lang/Object",P,List.of(),null,null));
        assertEquals(Resolution.MISSING_METHOD,only(analyze(ref,direct(null),after,false)).resolution());
    }
    @Test void missingRequiredAncestorRemainsUnknown(){
        var a=analyze(method(Opcodes.INVOKESTATIC),direct(STATIC_METHOD),Map.of(OWNER,type(OWNER,"fixture/runtime/Missing",P,List.of(),null,null)),false);
        assertEquals(Resolution.UNKNOWN,only(a).resolution());assertFalse(a.complete());
    }
    @Test void cyclicRequiredHierarchyRemainsBoundedUnknown(){
        String other="fixture/runtime/Cycle";var after=Map.of(OWNER,type(OWNER,other,P,List.of(),null,null),other,type(other,OWNER,P,List.of(),null,null));
        var a=analyze(method(Opcodes.INVOKESTATIC),direct(STATIC_METHOD),after,false);assertEquals(Resolution.UNKNOWN,only(a).resolution());assertFalse(a.complete());
    }
    @Test void excessiveHierarchyDepthRemainsBoundedUnknown(){
        var a=analyze(method(Opcodes.INVOKESTATIC),direct(STATIC_METHOD),chain("TooDeep",180,STATIC_METHOD),false);assertEquals(Resolution.UNKNOWN,only(a).resolution());assertFalse(a.complete());
    }

    private static byte[] archive(Map<String,byte[]> entries)throws IOException{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(var zip=new ZipOutputStream(bytes)){for(var entry:new TreeMap<>(entries).entrySet()){zip.putNextEntry(new ZipEntry(entry.getKey()));zip.write(entry.getValue());zip.closeEntry();}}return bytes.toByteArray();
    }
    private static byte[] runtimeArchive(Map<String,byte[]> classes)throws IOException{Map<String,byte[]> entries=new TreeMap<>();classes.forEach((name,body)->entries.put(name+".class",body));return archive(entries);}
    private Analysis targeted(Map<String,byte[]> first,Map<String,byte[]> second,List<String> order)throws Exception{
        return targeted(first,second,order,Limits.defaults());
    }
    private Analysis targeted(Map<String,byte[]> first,Map<String,byte[]> second,List<String> order,Limits limits)throws Exception{
        return targeted(first,second,order,limits,true);
    }
    private Analysis targeted(Map<String,byte[]> first,Map<String,byte[]> second,List<String> order,Limits limits,boolean hints)throws Exception{
        Path current=Files.write(scratch.resolve("current.jar"),runtimeArchive(direct(STATIC_METHOD)));
        Path target=Files.write(scratch.resolve("target.jar"),archive(Map.of("components/first.jar",runtimeArchive(first),"components/second.jar",runtimeArchive(second))));
        var before=new TargetedRuntimeLookup(List.of(new Artifact(current,"current.jar","",Role.RUNTIME)),Limits.defaults(),Scope.NODE_RUNTIME,List.of());
        var after=new TargetedRuntimeLookup(List.of(new Artifact(target,"target.jar","",Role.RUNTIME)),limits,Scope.NODE_RUNTIME,order);
        var caller=new ClassInfo(CALLER,"java/lang/Object",List.of(),P,52,List.of(),List.of(method(Opcodes.INVOKESTATIC)));
        var apps=List.of(new JarInventory("cordapps/historical.jar","",Map.of(),Map.of(CALLER,caller),List.of()));
        return hints?new RequiredSymbolAnalyzer().analyze(apps,before,after):new RequiredSymbolAnalyzer().analyze(apps,withoutHints(before),withoutHints(after));
    }
    private static Lookup withoutHints(TargetedRuntimeLookup lookup){return new Lookup(){public Result lookup(String owner){return lookup.lookup(owner);}public void prefetch(Collection<String> owners){lookup.prefetch(owners);}};}
    @Test void locallyDiscoveredAncestorMustBeCheckedAgainstLaterComponentDuplicate()throws Exception{
        String parent="fixture/runtime/Base";var first=Map.of(OWNER,type(OWNER,parent,P,List.of(),null,null),parent,type(parent,"java/lang/Object",P,List.of(),STATIC_METHOD,7));
        var second=Map.of(parent,type(parent,"java/lang/Object",P,List.of(),null,null));var a=targeted(first,second,List.of());
        assertEquals(Resolution.UNKNOWN,only(a).resolution());assertFalse(a.complete(),"A local signature hint is not proof of global ancestor selection");
    }
    @Test void laterComponentAncestorWinnerCannotBeReplacedByLocalCompatibleHint()throws Exception{
        String parent="fixture/runtime/Base";var first=Map.of(OWNER,type(OWNER,parent,P,List.of(),null,null),parent,type(parent,"java/lang/Object",P,List.of(),STATIC_METHOD,7));
        var second=Map.of(parent,type(parent,"java/lang/Object",P,List.of(),null,null));var a=targeted(first,second,List.of("target.jar!/components/second.jar","target.jar!/components/first.jar"));
        assertEquals(Resolution.MISSING_METHOD,only(a).resolution());assertTrue(a.complete());
    }
    @Test void selectedFacadeParentChainControlsResolutionRatherThanShadowedChain()throws Exception{
        String good="fixture/runtime/Good",missing="fixture/runtime/MissingHelper";
        var first=Map.of(OWNER,type(OWNER,good,P,List.of(),null,null),good,type(good,"java/lang/Object",P,List.of(),STATIC_METHOD,7));
        var second=Map.of(OWNER,type(OWNER,missing,P,List.of(),null,null),missing,type(missing,"java/lang/Object",P,List.of(),null,null));
        var a=targeted(first,second,List.of("target.jar!/components/second.jar","target.jar!/components/first.jar"));assertEquals(Resolution.MISSING_METHOD,only(a).resolution());assertTrue(a.complete());
    }
    @Test void unusedShadowedFacadeParentDoesNotLeaveFalseIncompleteFinding()throws Exception{
        String good="fixture/runtime/Good";var first=Map.of(OWNER,type(OWNER,good,P,List.of(),null,null),good,type(good,"java/lang/Object",P,List.of(),STATIC_METHOD,7));
        var second=Map.of(OWNER,type(OWNER,"fixture/runtime/UnavailableShadowedParent",P,List.of(),null,null));
        var a=targeted(first,second,List.of("target.jar!/components/first.jar","target.jar!/components/second.jar"));assertEquals(Resolution.COMPATIBLE,only(a).resolution());assertTrue(a.complete());assertTrue(a.findings().isEmpty());assertEquals(List.of("target.jar!/components/first.jar!/fixture/runtime/Good.class"),only(a).target().declaringArtifacts());
    }
    @Test void selectedDirectDeclarationIsNotPoisonedByShadowedHierarchyHintBudget()throws Exception{
        String unused="fixture/runtime/OversizedUnusedParent";
        byte[] unparsed=new byte[1025];new Random(17).nextBytes(unparsed);
        var second=Map.of(OWNER,type(OWNER,unused,P,List.of(),null,null),unused,unparsed);
        Limits defaults=Limits.defaults();var limits=new Limits(defaults.maxArchiveBytes(),defaults.maxNestedBytes(),defaults.maxReadBytes(),defaults.maxEntries(),defaults.maxDepth(),defaults.maxNestedArchives(),defaults.maxOwners(),1024,defaults.maxMembers(),defaults.maxSignatureBytes(),defaults.maxMillis(),defaults.javaFeature());
        var a=targeted(direct(STATIC_METHOD),second,List.of("target.jar!/components/first.jar","target.jar!/components/second.jar"),limits);
        assertEquals(Resolution.COMPATIBLE,only(a).resolution());assertTrue(a.complete());assertTrue(a.findings().isEmpty());
    }
    @Test void selectedAncestorIsNotPoisonedByLosingLocalAncestorHintBudget()throws Exception{
        String parent="fixture/runtime/Base",unused="fixture/runtime/OversizedUnusedParent";
        byte[] unparsed=new byte[1025];new Random(19).nextBytes(unparsed);
        var first=Map.of(OWNER,type(OWNER,parent,P,List.of(),null,null),parent,type(parent,unused,P,List.of(),null,null),unused,unparsed);
        var second=Map.of(parent,type(parent,"java/lang/Object",P,List.of(),STATIC_METHOD,7));
        Limits defaults=Limits.defaults();var limits=new Limits(defaults.maxArchiveBytes(),defaults.maxNestedBytes(),defaults.maxReadBytes(),defaults.maxEntries(),defaults.maxDepth(),defaults.maxNestedArchives(),defaults.maxOwners(),1024,defaults.maxMembers(),defaults.maxSignatureBytes(),defaults.maxMillis(),defaults.javaFeature());
        var a=targeted(first,second,List.of("target.jar!/components/second.jar","target.jar!/components/first.jar"),limits);
        assertEquals(Resolution.COMPATIBLE,only(a).resolution());assertTrue(a.complete());assertTrue(a.findings().isEmpty());assertEquals(List.of("target.jar!/components/second.jar!/fixture/runtime/Base.class"),only(a).target().declaringArtifacts());
    }
    @Test void unusedLosingAncestorSignaturesCannotConsumeRequiredProofCache()throws Exception{
        String parent="fixture/runtime/Base",unused="fixture/runtime/UnusedSignatures";
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,P|Opcodes.ACC_SUPER,unused,null,"java/lang/Object",null);
        for(int i=0;i<500;i++)writer.visitField(P|S,"unusedField"+i,"I",null,null).visitEnd();writer.visitEnd();
        var first=Map.of(OWNER,type(OWNER,parent,P,List.of(),null,null),parent,type(parent,unused,P,List.of(),null,null),unused,writer.toByteArray());
        var second=Map.of(parent,type(parent,"java/lang/Object",P,List.of(),STATIC_METHOD,7));
        Limits d=Limits.defaults();var limits=new Limits(d.maxArchiveBytes(),d.maxNestedBytes(),d.maxReadBytes(),d.maxEntries(),d.maxDepth(),d.maxNestedArchives(),d.maxOwners(),d.maxClassBytes(),d.maxMembers(),32768,d.maxMillis(),d.javaFeature());
        var order=List.of("target.jar!/components/second.jar","target.jar!/components/first.jar");
        var ordinary=targeted(first,second,order,limits,false);assertEquals(Resolution.COMPATIBLE,only(ordinary).resolution());assertTrue(ordinary.complete());
        var optimized=targeted(first,second,order,limits,true);assertEquals(Resolution.COMPATIBLE,only(optimized).resolution());assertTrue(optimized.complete());assertTrue(optimized.findings().isEmpty());
    }
}
