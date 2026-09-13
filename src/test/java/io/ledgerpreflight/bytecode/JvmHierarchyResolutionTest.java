package io.ledgerpreflight.bytecode;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

class JvmHierarchyResolutionTest {
    private static final String OWNER="example/PublicFacade",BASE="example/HelperBase",DESC="(Ljava/lang/Iterable;I)I";
    private static Member method(String descriptor,int access){return new Member("METHOD","helper",descriptor,access);}
    private static ClassInfo type(String name,String parent,int access,List<String> interfaces,Member...members){return new ClassInfo(name,parent,interfaces,access,52,List.of(members),List.of());}
    private static ClassInfo cls(String name,String parent,Member...members){return type(name,parent,Opcodes.ACC_PUBLIC,List.of(),members);}
    private static Lookup lookup(ClassInfo...classes){Map<String,ClassInfo> available=new HashMap<>();for(ClassInfo cls:classes)available.put(cls.name(),cls);return owner->available.containsKey(owner)?new Result(State.FOUND,available.get(owner),List.of("runtime.jar!/"+owner+".class"),"Complete context lookup"):new Result(State.ABSENT,null,List.of(),"Complete context lookup");}
    private static Analysis analyze(Lookup current,Lookup target,int opcode,String callerParent,String kind,String member,String descriptor){
        Reference ref=new Reference("verify()V",kind,OWNER,member,descriptor,opcode,opcode==Opcodes.INVOKEINTERFACE);
        ClassInfo caller=new ClassInfo("caller/Contract",callerParent,List.of(),Opcodes.ACC_PUBLIC,52,List.of(),List.of(ref));
        return new RequiredSymbolAnalyzer().analyze(List.of(new JarInventory("source-contract.jar","",Map.of(),Map.of(caller.name(),caller),List.of())),current,target);
    }
    private static Analysis analyze(Lookup current,Lookup target){return analyze(current,target,Opcodes.INVOKESTATIC,"java/lang/Object","METHOD","helper",DESC);}
    private static SymbolResult one(Analysis analysis){assertEquals(1,analysis.symbols().size());return analysis.symbols().get(0);}
    private static Lookup chain(boolean present){return lookup(cls(OWNER,"example/LayerA"),type("example/LayerA","example/LayerB",0,List.of()),type("example/LayerB",BASE,0,List.of()),type(BASE,"java/lang/Object",0,List.of(),present?new Member[]{method(DESC,Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC)}:new Member[0]));}

    @Test void inheritedStaticMethodPreservesPublicFacadeAndDeclaringOrigin(){var result=one(analyze(chain(true),chain(true)));assertEquals(Resolution.COMPATIBLE,result.resolution());assertEquals(BASE,result.target().declaringClass());assertEquals(List.of("runtime.jar!/"+BASE+".class"),result.target().declaringArtifacts());assertEquals(List.of("runtime.jar!/"+OWNER+".class"),result.target().artifacts());}
    @Test void inheritedCompatibleReferencesDoNotRetainIncompleteFinding(){var result=analyze(chain(true),chain(true));assertTrue(result.complete());assertTrue(result.findings().isEmpty());}
    @Test void inheritedCurrentMissingTargetRemainsConfirmed(){var result=one(analyze(chain(true),chain(false)));assertEquals(Resolution.MISSING_METHOD,result.resolution());assertEquals("found",result.current().memberStatus());assertEquals("absent",result.target().memberStatus());}
    @Test void changedAncestorDescriptorIsAnIncompatibility(){var target=lookup(cls(OWNER,BASE),cls(BASE,"java/lang/Object",method("(Ljava/lang/String;)I",Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC)));assertEquals(Resolution.DESCRIPTOR_MISMATCH,one(analyze(chain(true),target)).resolution());}
    @Test void constructorsAreNotInherited(){var current=lookup(cls(OWNER,BASE,new Member("METHOD","<init>","(I)V",Opcodes.ACC_PUBLIC)),cls(BASE,"java/lang/Object"));var target=lookup(cls(OWNER,BASE),cls(BASE,"java/lang/Object",new Member("METHOD","<init>","(I)V",Opcodes.ACC_PUBLIC)));assertEquals(Resolution.MISSING_METHOD,one(analyze(current,target,Opcodes.INVOKESPECIAL,"java/lang/Object","METHOD","<init>","(I)V")).resolution());}
    @Test void inheritedInterfaceMethodResolvesToItsDeclaration(){var runtime=lookup(type(OWNER,"java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(BASE)),type(BASE,"java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(),method(DESC,Opcodes.ACC_PUBLIC|Opcodes.ACC_ABSTRACT)));var result=one(analyze(runtime,runtime,Opcodes.INVOKEINTERFACE,"java/lang/Object","METHOD","helper",DESC));assertEquals(Resolution.COMPATIBLE,result.resolution());assertEquals(BASE,result.target().declaringClass());}
    @Test void conflictingDefaultInterfacesRemainUnknown(){var runtime=lookup(type(OWNER,"java/lang/Object",Opcodes.ACC_PUBLIC,List.of("example/First","example/Second")),type("example/First","java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(),method(DESC,Opcodes.ACC_PUBLIC)),type("example/Second","java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(),method(DESC,Opcodes.ACC_PUBLIC)));assertEquals(Resolution.UNKNOWN,one(analyze(runtime,runtime,Opcodes.INVOKEVIRTUAL,"java/lang/Object","METHOD","helper",DESC)).resolution());}
    @Test void staticInterfaceMethodsAreNotInheritedByClasses(){var target=lookup(type(OWNER,"java/lang/Object",Opcodes.ACC_PUBLIC,List.of(BASE)),type(BASE,"java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(),method(DESC,Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC)));assertEquals(Resolution.MISSING_METHOD,one(analyze(chain(true),target)).resolution());}
    @Test void cyclicSuperclassHierarchyRemainsUnknown(){var cyclic=lookup(cls(OWNER,BASE),cls(BASE,OWNER));assertEquals(Resolution.UNKNOWN,one(analyze(chain(true),cyclic)).resolution());}
    @Test void cyclicInterfaceHierarchyRemainsUnknown(){var cyclic=lookup(type(OWNER,"java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(BASE)),type(BASE,"java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(OWNER)));assertEquals(Resolution.UNKNOWN,one(analyze(cyclic,cyclic,Opcodes.INVOKEINTERFACE,"java/lang/Object","METHOD","helper",DESC)).resolution());}
    @Test void inheritedStaticFieldKeepsInterfaceBeforeSuperclassOrder(){var runtime=lookup(type(OWNER,BASE,Opcodes.ACC_PUBLIC,List.of("example/Fields")),cls(BASE,"java/lang/Object",new Member("FIELD","value","I",Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC)),type("example/Fields","java/lang/Object",Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE,List.of(),new Member("FIELD","value","I",Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC)));var result=one(analyze(runtime,runtime,Opcodes.GETSTATIC,"java/lang/Object","FIELD","value","I"));assertEquals(Resolution.COMPATIBLE,result.resolution());assertEquals("example/Fields",result.target().declaringClass());}
    @Test void specialSuperclassMethodIsValidAndUnrelatedCallerIsUnresolved(){var runtime=lookup(cls(OWNER,BASE),cls(BASE,"java/lang/Object",method(DESC,Opcodes.ACC_PUBLIC)));assertEquals(Resolution.COMPATIBLE,one(analyze(runtime,runtime,Opcodes.INVOKESPECIAL,OWNER,"METHOD","helper",DESC)).resolution());assertEquals(Resolution.UNKNOWN,one(analyze(runtime,runtime,Opcodes.INVOKESPECIAL,"java/lang/Object","METHOD","helper",DESC)).resolution());}
}
