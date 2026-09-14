package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.reporting.Reports;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Original synthetic bytecode; no vendor binaries, keys, or customer data. */
public final class SyntheticFixtureFactory {
    public static final String OWNER="net/corda/core/internal/InternalUtils";
    public static final String DESC="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    public record Fixture(Path root,Path node,Path kit,Path log,Path errors,Path classpath) {
        public AssessmentService.Options options(boolean evidence){return new AssessmentService.Options(node,kit,null,null,null,null,null,evidence?List.of(log,errors):List.of(),classpath,null);}
    }
    public static Fixture create(Path root,boolean replay)throws IOException {
        Path node=root.resolve("current-node"),kit=root.resolve("upgrade-kit");Files.createDirectories(node);Files.createDirectories(kit);
        Map<String,byte[]> oldRuntime=new TreeMap<>();oldRuntime.put("net/corda/node/Corda.class",emptyClass("net/corda/node/Corda"));oldRuntime.put(OWNER+".class",utility(true));oldRuntime.put("META-INF/MANIFEST.MF",manifest(Map.of("Main-Class","net.corda.node.Corda","Corda-Release-Version","4.11.9")));
        writeZip(node.resolve("corda.jar"),oldRuntime);
        Map<String,byte[]> targetRuntime=new TreeMap<>(oldRuntime);targetRuntime.put(OWNER+".class",utility(!replay));targetRuntime.put("META-INF/MANIFEST.MF",manifest(Map.of("Main-Class","net.corda.node.Corda","Corda-Release-Version","4.12.11")));writeZip(kit.resolve("corda.jar"),targetRuntime);
        writeZip(kit.resolve("transaction-validator.jar"),Map.of("net/corda/tools/TransactionValidator.class",emptyClass("net/corda/tools/TransactionValidator"),"META-INF/MANIFEST.MF",manifest(Map.of("Main-Class","net.corda.tools.TransactionValidator","Corda-Release-Version","4.12.11"))));
        String schema=replay?"ExampleMixedCaseIssuer":"synthetic_schema";
        Files.writeString(node.resolve("node.conf"),"database.schema = \""+schema+"\"\ndataSourceProperties {\n dataSource.url = \"jdbc:postgresql://synthetic.invalid/example?currentSchema="+schema+"\"\n dataSource.password = \"SyntheticPasswordOnly42\"\n}\n",StandardCharsets.UTF_8);
        if(replay){
            writeZip(node.resolve("cordapps/contracts.jar"),Map.of("example/SyntheticTokenContract.class",contract(true),"META-INF/MANIFEST.MF",manifest(Map.of("Cordapp-Contract-Name","Synthetic Token Contracts","Cordapp-Contract-Version","1","Min-Platform-Version","1"))));
            writeZip(kit.resolve("cordapps/contracts.jar"),Map.of("example/SyntheticTokenContract.class",contract(false),"META-INF/MANIFEST.MF",manifest(Map.of("Cordapp-Contract-Name","Synthetic Token Contracts","Cordapp-Contract-Version","2","Min-Platform-Version","140"))));
            writeZip(kit.resolve("legacy-jars/compatibility-shim.jar"),Map.of(OWNER+".class",utility(true)));
        }
        Path log=root.resolve("tvu.log"),errors=root.resolve("errors.zip"),classpath=root.resolve("classpath.txt");
        Files.writeString(log,"transactions expected: 650\ntransactions processed: 650\nsucceeded: "+(replay?449:650)+"\nverification failed: "+(replay?201:0)+"\n",StandardCharsets.UTF_8);
        Map<String,byte[]> details=new TreeMap<>();if(replay)for(int i=1;i<=3;i++)details.put("failure-"+i+".txt",("java.lang.NoSuchMethodError: 'java.math.BigDecimal net.corda.core.internal.InternalUtils.sum(java.lang.Iterable)'\n at example.SyntheticTokenContract.verify(SyntheticTokenContract.java:10)\n").getBytes(StandardCharsets.UTF_8));writeZip(errors,details);
        Files.writeString(classpath,"java -cp corda.jar:legacy-jars/compatibility-shim.jar net.corda.verifier.Main\n",StandardCharsets.UTF_8);
        return new Fixture(root,node,kit,log,errors,classpath);
    }
    public static byte[] emptyClass(String name){ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,"java/lang/Object",null);writer.visitEnd();return writer.toByteArray();}
    public static byte[] utility(boolean method){ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,OWNER,null,"java/lang/Object",null);if(method){MethodVisitor mv=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"sum",DESC,null,null);mv.visitCode();mv.visitInsn(Opcodes.ACONST_NULL);mv.visitInsn(Opcodes.ARETURN);mv.visitMaxs(1,1);mv.visitEnd();}writer.visitEnd();return writer.toByteArray();}
    public static byte[] contract(boolean call){ClassWriter writer=new ClassWriter(0);writer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,"example/SyntheticTokenContract",null,"java/lang/Object",null);MethodVisitor mv=writer.visitMethod(Opcodes.ACC_PUBLIC,"verifyConsume","()V",null,null);mv.visitCode();if(call){mv.visitInsn(Opcodes.ACONST_NULL);mv.visitMethodInsn(Opcodes.INVOKESTATIC,OWNER,"sum",DESC,false);mv.visitInsn(Opcodes.POP);}mv.visitInsn(Opcodes.RETURN);mv.visitMaxs(1,1);mv.visitEnd();writer.visitEnd();return writer.toByteArray();}
    public static byte[] manifest(Map<String,String> values){StringBuilder text=new StringBuilder("Manifest-Version: 1.0\r\n");new TreeMap<>(values).forEach((key,value)->text.append(key).append(": ").append(value).append("\r\n"));return text.append("\r\n").toString().getBytes(StandardCharsets.UTF_8);}
    public static void writeZip(Path output,Map<String,byte[]> entries)throws IOException {Files.createDirectories(output.toAbsolutePath().getParent());try(ZipOutputStream zip=new ZipOutputStream(Files.newOutputStream(output))){for(var entry:new TreeMap<>(entries).entrySet()){ZipEntry ze=new ZipEntry(entry.getKey());ze.setTime(0);zip.putNextEntry(ze);zip.write(entry.getValue());zip.closeEntry();}}}
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Supply a workspace output directory");Path root=Path.of(args[0]);Fixture fixture=create(root.resolve("replay"),true);Assessment assessment=new AssessmentService().assess(fixture.options(true));Reports.write(root.resolve("example-report"),Reports.files(assessment));System.out.print(Reports.terminal(assessment));create(root.resolve("clean"),false);RealDiscoveryRegressionTest.fixture(root.resolve("discovery-regression"));ProductAcceptanceFixture.generate(root.resolve("product-acceptance"));RunARegressionTest.generate(root.resolve("run-a"));ActiveRuntimeRegressionTest.generate(root.resolve("active-runtime"));RequiredCompatibilityIntegrationTest.generate(root.resolve("required-symbols"));ExecutionContextIntegrationTest.generate(root.resolve("execution-context"));HierarchyFixtureFactory.generate(root.resolve("hierarchy"));BlockerVerifierFixtureFactory.generate(root.resolve("blocker-verifier"));
    }
}
