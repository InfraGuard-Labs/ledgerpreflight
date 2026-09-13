package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.AssessmentService;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.objectweb.asm.*;

/** Original generated facade hierarchies; no language-library or vendor binaries. */
public final class HierarchyFixtureFactory {
    public static final String OWNER="org/example/helpers/PublicFacade",METHOD="helper",DESC="(Ljava/lang/Iterable;I)I";
    public static final String CURRENT_DECLARING="org/example/helpers/SourceHelpers",TARGET_DECLARING="org/example/helpers/TargetHelpers";
    public static final String SOURCE="cordapps/example-old-contract.jar",COMPONENT="lib/generated-helpers.jar";
    private static final String VERIFIER="tools/external-verifier.jar";
    private static final int RESOURCE_ENTRIES=40000;
    private HierarchyFixtureFactory(){}

    public static SyntheticFixtureFactory.Fixture create(Path root,String mode,boolean traversalPressure,boolean broadPartial)throws Exception {
        var fixture=ExecutionContextIntegrationTest.fixture(root,mode.equals("blocked")?"blocked":"compatible",true,broadPartial);
        Map<String,byte[]> source=hierarchy(false,"compatible",traversalPressure?16:3,traversalPressure);
        Map<String,byte[]> target=hierarchy(true,mode,traversalPressure?24:4,traversalPressure);
        RunARegressionTest.update(fixture.node().resolve("corda.jar"),Map.of(COMPONENT,archive(source)),false);
        Path targetRuntime=fixture.kit().resolve("renamed-runtime.bin");
        byte[] verifierBytes;try(ZipFile jar=new ZipFile(targetRuntime.toFile());InputStream input=jar.getInputStream(jar.getEntry(VERIFIER))){verifierBytes=input.readAllBytes();}
        Map<String,byte[]> verifier=entries(verifierBytes);verifier.put(COMPONENT,archive(target));
        RunARegressionTest.update(targetRuntime,Map.of(COMPONENT,archive(target),VERIFIER,archive(verifier)),false);
        Map<String,byte[]> callers=new TreeMap<>();
        for(int n=0;n<3;n++){
            String name=n==0?ProductAcceptanceFixture.CONTRACT:"org/example/ledger/Caller"+n;
            ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,"java/lang/Object",new String[]{"net/corda/core/contracts/Contract"});
            MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC,"verify","()V",null,null);method.visitCode();
            method.visitInsn(Opcodes.ACONST_NULL);method.visitIntInsn(Opcodes.BIPUSH,7);method.visitMethodInsn(Opcodes.INVOKESTATIC,OWNER,METHOD,DESC,false);method.visitInsn(Opcodes.POP);
            method.visitInsn(Opcodes.ACONST_NULL);method.visitMethodInsn(Opcodes.INVOKESTATIC,RequiredCompatibilityIntegrationTest.OWNER,RequiredCompatibilityIntegrationTest.METHOD,RequiredCompatibilityIntegrationTest.DESC,false);method.visitInsn(Opcodes.POP);
            method.visitInsn(Opcodes.RETURN);method.visitMaxs(2,1);method.visitEnd();writer.visitEnd();callers.put(name+".class",writer.toByteArray());
        }
        RunARegressionTest.update(fixture.node().resolve(SOURCE),callers,false);
        // A supporting artifact deliberately offers a direct same-owner method. It must not
        // supply a missing member or replace an inherited declaration in the selected runtime.
        byte[] driver=helperClass(OWNER,"java/lang/Object",Opcodes.ACC_PUBLIC,true,DESC);
        for(Path base:List.of(fixture.node(),fixture.kit()))RunARegressionTest.update(base.resolve("drivers/companion-tool.jar"),Map.of(OWNER+".class",driver),false);
        if(mode.equals("blocked"))RequiredCompatibilityIntegrationTest.tvuFailure(fixture);
        return fixture;
    }

    static Map<String,byte[]> hierarchy(boolean target,String mode,int layers,boolean resources){
        String prefix="org/example/helpers/"+(target?"Target":"Source"),declaring=target?TARGET_DECLARING:CURRENT_DECLARING;
        Map<String,byte[]> classes=new TreeMap<>();
        classes.put(OWNER+".class",helperClass(OWNER,prefix+"Layer1",Opcodes.ACC_PUBLIC,false,DESC));
        for(int n=1;n<=layers;n++){
            String name=prefix+"Layer"+n,parent=n==layers?declaring:prefix+"Layer"+(n+1);
            classes.put(name+".class",helperClass(name,parent,0,false,DESC));
        }
        boolean exact=!target||!Set.of("helper-missing","helper-descriptor","helper-cycle","helper-parent-missing").contains(mode);
        String parent=target&&mode.equals("helper-cycle")?prefix+"Layer1":target&&mode.equals("helper-parent-missing")?"org/example/helpers/AbsentParent":"java/lang/Object";
        classes.put(declaring+".class",helperClass(declaring,parent,0,exact||target&&mode.equals("helper-descriptor"),target&&mode.equals("helper-descriptor")?"(Ljava/lang/Iterable;J)I":DESC));
        if(resources)for(int n=0;n<RESOURCE_ENTRIES;n++)classes.put("metadata/unused-entry-"+n,new byte[0]);
        return classes;
    }

    private static byte[] helperClass(String name,String parent,int access,boolean method,String descriptor){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,access|Opcodes.ACC_SUPER,name,null,parent,null);
        if(method){MethodVisitor helper=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,METHOD,descriptor,null,null);helper.visitCode();helper.visitIntInsn(Opcodes.BIPUSH,7);helper.visitInsn(Opcodes.IRETURN);helper.visitMaxs(1,descriptor.equals(DESC)?2:3);helper.visitEnd();}
        writer.visitEnd();return writer.toByteArray();
    }

    static byte[] probe(){
        ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,"org/example/oracle/Probe",null,"java/lang/Object",null);
        MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"call","()I",null,null);method.visitCode();method.visitInsn(Opcodes.ACONST_NULL);method.visitIntInsn(Opcodes.BIPUSH,7);method.visitMethodInsn(Opcodes.INVOKESTATIC,OWNER,METHOD,DESC,false);method.visitInsn(Opcodes.IRETURN);method.visitMaxs(2,0);method.visitEnd();writer.visitEnd();return writer.toByteArray();
    }

    private static byte[] archive(Map<String,byte[]> entries)throws IOException{
        ByteArrayOutputStream output=new ByteArrayOutputStream();try(ZipOutputStream jar=new ZipOutputStream(output)){for(var entry:new TreeMap<>(entries).entrySet()){ZipEntry item=new ZipEntry(entry.getKey());item.setTime(0);jar.putNextEntry(item);jar.write(entry.getValue());jar.closeEntry();}}return output.toByteArray();
    }
    private static Map<String,byte[]> entries(byte[] archive)throws IOException{
        Map<String,byte[]> result=new TreeMap<>();try(ZipInputStream zip=new ZipInputStream(new ByteArrayInputStream(archive))){for(ZipEntry entry;(entry=zip.getNextEntry())!=null;)if(!entry.isDirectory())result.put(entry.getName(),zip.readAllBytes());}return result;
    }
    public static void generate(Path root)throws Exception{
        for(String mode:List.of("blocked","compatible")){
            var fixture=create(root.resolve(mode),mode,true,true);var service=new AssessmentService();
            Reports.write(root.resolve(mode+"-asserted"),Reports.files(service.assess(ProductAcceptanceFixture.options(fixture,false))));
            if(mode.equals("blocked"))Reports.write(root.resolve("blocked-tvu-asserted"),Reports.files(service.assess(ProductAcceptanceFixture.options(fixture,true))));
        }
    }
    public static void main(String[] args)throws Exception{if(args.length!=1)throw new IllegalArgumentException("Supply a workspace fixture directory");generate(Path.of(args[0]));}
}
