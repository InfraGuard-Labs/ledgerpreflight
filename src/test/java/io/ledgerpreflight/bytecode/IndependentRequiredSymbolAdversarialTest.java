package io.ledgerpreflight.bytecode;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

/** Independent linkage checks use executable JVM fixtures as the semantic oracle. */
class IndependentRequiredSymbolAdversarialTest {
    private static final String OWNER="example/runtime/Api",CALLER="example/contract/Caller";
    private static final int PUBLIC=Opcodes.ACC_PUBLIC,STATIC=Opcodes.ACC_STATIC;
    private static ClassInfo info(String name,String parent,int access,List<String> interfaces,Member...members){return new ClassInfo(name,parent,interfaces,access,52,List.of(members),List.of());}
    private static Lookup lookup(ClassInfo...classes){Map<String,ClassInfo> definitions=new HashMap<>();for(var c:classes)definitions.put(c.name(),c);return name->definitions.containsKey(name)?new Result(State.FOUND,definitions.get(name),List.of("runtime.jar!/"+name+".class"),"Independent fixture"):new Result(State.ABSENT,null,List.of(),"Independent complete directory");}
    private static SymbolResult analyze(Reference ref,Lookup before,Lookup after){ClassInfo caller=new ClassInfo(CALLER,"java/lang/Object",List.of(),PUBLIC,52,List.of(),List.of(ref));var app=new JarInventory("cordapps/source-contract.jar","synthetic",Map.of(),Map.of(CALLER,caller),List.of());var result=new RequiredSymbolAnalyzer().analyze(List.of(app),before,after);assertEquals(1,result.symbols().size());return result.symbols().get(0);}
    private static Reference method(int opcode){return new Reference("run()I","METHOD",OWNER,"value","()I",opcode);}
    private static ClassInfo ordinary(Member...members){return info(OWNER,"java/lang/Object",PUBLIC,List.of(),members);}
    private static final Member STATIC_METHOD=new Member("METHOD","value","()I",PUBLIC|STATIC);
    private static byte[] type(String name,String parent,int access,List<String> interfaces,Integer methodAccess,boolean field){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,access,name,null,parent,interfaces.toArray(String[]::new));
        if(field)writer.visitField(PUBLIC|STATIC|Opcodes.ACC_FINAL,"amount","I",null,7).visitEnd();
        if((access&Opcodes.ACC_INTERFACE)==0){var init=writer.visitMethod(PUBLIC,"<init>","()V",null,null);init.visitCode();init.visitVarInsn(Opcodes.ALOAD,0);init.visitMethodInsn(Opcodes.INVOKESPECIAL,parent,"<init>","()V",false);init.visitInsn(Opcodes.RETURN);init.visitMaxs(1,1);init.visitEnd();}
        if(methodAccess!=null){var method=writer.visitMethod(methodAccess,"value","()I",null,null);method.visitCode();method.visitIntInsn(Opcodes.BIPUSH,7);method.visitInsn(Opcodes.IRETURN);method.visitMaxs(1,(methodAccess&STATIC)==0?1:0);method.visitEnd();}
        writer.visitEnd();return writer.toByteArray();
    }
    private static byte[] invocation(Reference reference){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,PUBLIC,CALLER,null,"java/lang/Object",null);var method=writer.visitMethod(PUBLIC|STATIC,"run","()I",null,null);method.visitCode();
        if(reference.kind().equals("FIELD"))method.visitFieldInsn(reference.opcode(),reference.owner(),reference.name(),reference.descriptor());
        else {if(reference.opcode()!=Opcodes.INVOKESTATIC){method.visitTypeInsn(Opcodes.NEW,OWNER);method.visitInsn(Opcodes.DUP);method.visitMethodInsn(Opcodes.INVOKESPECIAL,OWNER,"<init>","()V",false);}method.visitMethodInsn(reference.opcode(),OWNER,"value","()I",reference.opcode()==Opcodes.INVOKEINTERFACE);}
        method.visitInsn(Opcodes.IRETURN);method.visitMaxs(2,0);method.visitEnd();writer.visitEnd();return writer.toByteArray();
    }
    private static Object run(Map<String,byte[]> definitions,Reference reference)throws Exception {
        Map<String,byte[]> bytes=new HashMap<>(definitions);bytes.put(CALLER,invocation(reference));ClassLoader loader=new ClassLoader(IndependentRequiredSymbolAdversarialTest.class.getClassLoader()){@Override protected Class<?> findClass(String binaryName)throws ClassNotFoundException{byte[] body=bytes.get(binaryName.replace('.','/'));if(body==null)throw new ClassNotFoundException(binaryName);return defineClass(binaryName,body,0,body.length);}};
        return loader.loadClass(CALLER.replace('/','.')).getMethod("run").invoke(null);
    }

    @Test void staticFieldInheritedByInterfaceMustRemainCompatible()throws Exception {
        int face=PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT;String parent="example/runtime/Parent";Member field=new Member("FIELD","amount","I",PUBLIC|STATIC|Opcodes.ACC_FINAL);Reference reference=new Reference("run()I","FIELD",OWNER,"amount","I",Opcodes.GETSTATIC);
        assertEquals(7,run(Map.of(OWNER,type(OWNER,"java/lang/Object",face,List.of(parent),null,false),parent,type(parent,"java/lang/Object",face,List.of(),null,true)),reference));
        var proof=analyze(reference,lookup(info(OWNER,"java/lang/Object",face,List.of(),field)),lookup(info(OWNER,"java/lang/Object",face,List.of(parent)),info(parent,"java/lang/Object",face,List.of(),field)));
        assertEquals(Resolution.COMPATIBLE,proof.resolution(),"GETSTATIC must search inherited interface fields");assertEquals(parent,proof.target().declaringClass());
    }

    @Test void unavailableSuperclassCannotBeOverriddenByLaterInterfaceEvidence(){
        String missing="example/runtime/Unavailable",face="example/runtime/Face";Member method=new Member("METHOD","value","()I",PUBLIC);Reference reference=method(Opcodes.INVOKEVIRTUAL);
        var proof=analyze(reference,lookup(ordinary(method)),lookup(info(OWNER,missing,PUBLIC,List.of(face)),info(face,"java/lang/Object",PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT,List.of(),method)));
        assertEquals(Resolution.UNKNOWN,proof.resolution(),"Incomplete higher-priority superclass can change member selection and access");
    }

    @Test void protectedMemberInUnrelatedPackageMustNotBeCompatible()throws Exception {
        Reference reference=method(Opcodes.INVOKESTATIC);var failure=assertThrows(InvocationTargetException.class,()->run(Map.of(OWNER,type(OWNER,"java/lang/Object",PUBLIC,List.of(),Opcodes.ACC_PROTECTED|STATIC,false)),reference));assertInstanceOf(IllegalAccessError.class,failure.getCause());
        var proof=analyze(reference,lookup(ordinary(STATIC_METHOD)),lookup(ordinary(new Member("METHOD","value","()I",Opcodes.ACC_PROTECTED|STATIC))));
        assertNotEquals(Resolution.COMPATIBLE,proof.resolution(),"A protected member is inaccessible to a non-subclass in another package");
    }

    @Test void nonPublicOwnerWithPublicMemberMustNotBeCompatible()throws Exception {
        Reference reference=method(Opcodes.INVOKESTATIC);var failure=assertThrows(InvocationTargetException.class,()->run(Map.of(OWNER,type(OWNER,"java/lang/Object",0,List.of(),PUBLIC|STATIC,false)),reference));assertInstanceOf(IllegalAccessError.class,failure.getCause());
        var proof=analyze(reference,lookup(ordinary(STATIC_METHOD)),lookup(info(OWNER,"java/lang/Object",0,List.of(),STATIC_METHOD)));
        assertNotEquals(Resolution.COMPATIBLE,proof.resolution(),"Public member does not make a package-private owner accessible");
    }

    @Test void conflictingDefaultInterfaceMethodsMustNotBeCompatible()throws Exception {
        String first="example/runtime/First",second="example/runtime/Second";int face=PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT;Reference reference=method(Opcodes.INVOKEVIRTUAL);Member method=new Member("METHOD","value","()I",PUBLIC);
        var failure=assertThrows(InvocationTargetException.class,()->run(Map.of(OWNER,type(OWNER,"java/lang/Object",PUBLIC,List.of(first,second),null,false),first,type(first,"java/lang/Object",face,List.of(),PUBLIC,false),second,type(second,"java/lang/Object",face,List.of(),PUBLIC,false)),reference));assertInstanceOf(IncompatibleClassChangeError.class,failure.getCause());
        var proof=analyze(reference,lookup(ordinary(method)),lookup(info(OWNER,"java/lang/Object",PUBLIC,List.of(first,second)),info(first,"java/lang/Object",face,List.of(),method),info(second,"java/lang/Object",face,List.of(),method)));
        assertNotEquals(Resolution.COMPATIBLE,proof.resolution(),"Neither unrelated default method is uniquely maximally specific");
    }
    @Test void staticMethodClassToInterfaceChangeMustNotBeCompatible()throws Exception {
        Reference reference=method(Opcodes.INVOKESTATIC);int face=PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT;
        var failure=assertThrows(InvocationTargetException.class,()->run(Map.of(OWNER,type(OWNER,"java/lang/Object",face,List.of(),PUBLIC|STATIC,false)),reference));assertInstanceOf(IncompatibleClassChangeError.class,failure.getCause());
        var proof=analyze(reference,lookup(ordinary(STATIC_METHOD)),lookup(info(OWNER,"java/lang/Object",face,List.of(),STATIC_METHOD)));
        assertNotEquals(Resolution.COMPATIBLE,proof.resolution(),"INVOKESTATIC still distinguishes Methodref from InterfaceMethodref");
    }

    @Test void requiredClassTooNewForTargetJvmMustNotProveCompatibility()throws Exception {
        byte[] body=type(OWNER,"java/lang/Object",PUBLIC,List.of(),PUBLIC|STATIC,false);body[6]=0;body[7]=65;
        Reference reference=method(Opcodes.INVOKESTATIC);var failure=assertThrows(InvocationTargetException.class,()->run(Map.of(OWNER,body),reference));assertInstanceOf(UnsupportedClassVersionError.class,failure.getCause());
        var tooNew=new ClassInfo(OWNER,"java/lang/Object",List.of(),PUBLIC,65,List.of(STATIC_METHOD),List.of());
        var proof=analyze(reference,lookup(ordinary(STATIC_METHOD)),lookup(tooNew));assertNotEquals(Resolution.COMPATIBLE,proof.resolution(),"Exact signature in Java 21 class cannot satisfy Java 17 linkage");
    }
    @Test void bytecodeMethodrefKindIsPreservedWhenCurrentProofUnavailable()throws Exception {
        Reference reference=method(Opcodes.INVOKESTATIC);int face=PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT;
        var failure=assertThrows(InvocationTargetException.class,()->run(Map.of(OWNER,type(OWNER,"java/lang/Object",face,List.of(),PUBLIC|STATIC,false)),reference));assertInstanceOf(IncompatibleClassChangeError.class,failure.getCause());
        java.nio.file.Path file=java.nio.file.Files.createTempFile("independent-source-",".jar");
        try {
            try(var zip=new java.util.zip.ZipOutputStream(java.nio.file.Files.newOutputStream(file))){zip.putNextEntry(new java.util.zip.ZipEntry(CALLER+".class"));zip.write(invocation(reference));zip.closeEntry();}
            var source=new BytecodeScanner().scan(file);assertTrue(source.issues().isEmpty());
            var analysis=new RequiredSymbolAnalyzer().analyze(source.jars(),name->new Result(State.INCOMPLETE,null,List.of(),"Current proof unavailable"),lookup(info(OWNER,"java/lang/Object",face,List.of(),STATIC_METHOD)));
            var proof=analysis.symbols().stream().filter(s->s.symbol().owner().equals(OWNER)&&s.symbol().member().equals("value")).findFirst().orElseThrow();
            assertNotEquals(Resolution.COMPATIBLE,proof.resolution(),"Actual Methodref bytecode cannot call static interface method, even if old runtime proof is unavailable");
        } finally {java.nio.file.Files.deleteIfExists(file);}
    }
    @Test void sharedInterfaceHierarchyMustNotCauseExponentialLookupWork(){
        Member method=new Member("METHOD","value","()I",PUBLIC);int face=PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT;String terminal="example/runtime/Base";List<ClassInfo> definitions=new ArrayList<>();definitions.add(info(terminal,"java/lang/Object",face,List.of(),method));
        for(int depth=13;depth>=0;depth--){List<String> parents=depth==13?List.of(terminal):List.of("example/runtime/Left"+(depth+1),"example/runtime/Right"+(depth+1));definitions.add(info("example/runtime/Left"+depth,"java/lang/Object",face,parents));definitions.add(info("example/runtime/Right"+depth,"java/lang/Object",face,parents));}
        definitions.add(info(OWNER,"java/lang/Object",PUBLIC,List.of("example/runtime/Left0","example/runtime/Right0")));Lookup base=lookup(definitions.toArray(ClassInfo[]::new));java.util.concurrent.atomic.AtomicInteger calls=new java.util.concurrent.atomic.AtomicInteger();
        Lookup bounded=name->{assertTrue(calls.incrementAndGet()<=5000,"Thirty supplied classes caused over 5000 hierarchy lookup operations");return base.lookup(name);};
        var proof=analyze(method(Opcodes.INVOKEVIRTUAL),lookup(ordinary(method)),bounded);assertEquals(Resolution.COMPATIBLE,proof.resolution());assertTrue(calls.get()<5000);
    }
}
