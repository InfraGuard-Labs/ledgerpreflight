package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.reporting.Reports;
import org.objectweb.asm.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

/** Sanitized acceptance cases. All binaries are generated synthetic bytecode. */
public final class ProductAcceptanceFixture {
    public static final String CONTRACT="org/example/ledger/Agreement",FLOW="org/example/payments/Settlement";
    public static SyntheticFixtureFactory.Fixture create(Path root,boolean blocked,boolean multiSchema)throws IOException {
        var f=SyntheticFixtureFactory.create(root,false);
        Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema="+(multiSchema?"ExampleMixedCaseIssuer":"example_issuer")+"\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema="+(multiSchema?"ExampleMixedCaseIssuer,shared_reference":"example_issuer")+"\"\n");
        for(boolean target:List.of(false,true)) {
            Path base=target?f.kit():f.node();String version=target?"4.12.11":"4.11.6";
            Map<String,byte[]> libs=new TreeMap<>();
            libs.put("net/corda/core/contracts/Contract.class",baseClass("net/corda/core/contracts/Contract",true));
            libs.put("net/corda/core/flows/FlowLogic.class",baseClass("net/corda/core/flows/FlowLogic",false));

            ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(bytes)){for(var entry:libs.entrySet()){zip.putNextEntry(new ZipEntry(entry.getKey()));zip.write(entry.getValue());zip.closeEntry();}}
            SyntheticFixtureFactory.writeZip(base.resolve("corda.jar"),Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-ID","net.corda.node.CordaEnterprise","Application-Class","net.corda.node.Corda","Application-Version",version,"Corda-Release-Version",version,"Corda-Platform-Version",target?"140":"13","Corda-Vendor","Example Enterprise Runtime","Min-Java-Version",target?"17":"1.8")),"lib/runtime-components.jar",bytes.toByteArray(),SyntheticFixtureFactory.OWNER+".class",SyntheticFixtureFactory.utility(!target||!blocked)));
            app(base.resolve("cordapps/"+(target?"example-new-contract.jar":"example-old-contract.jar")),false,target,blocked&&!target);
            app(base.resolve("cordapps/"+(target?"example-new-workflow.jar":"example-old-workflow.jar")),true,target,false);
        }
        Files.move(f.kit().resolve("corda.jar"),f.kit().resolve("renamed-runtime.bin"));
        SyntheticFixtureFactory.writeZip(f.kit().resolve("transaction-validator.jar"),Map.of("net/corda/transactionvalidator/TransactionValidatorKt.class",SyntheticFixtureFactory.emptyClass("net/corda/transactionvalidator/TransactionValidatorKt"),"META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-Version","4.12.11"))));
        Files.move(f.kit().resolve("transaction-validator.jar"),f.kit().resolve("renamed-validator.jar"));
        SyntheticFixtureFactory.writeZip(f.node().resolve("cordapps/migration-helper.jar"),Map.of("org/example/migration/Helper.class",SyntheticFixtureFactory.emptyClass("org/example/migration/Helper")));
        Files.writeString(root.resolve("host.json"),"{\"sourceHostOs\":\"Ubuntu 22.04\",\"currentJava\":\"1.8.0_242\",\"plannedTargetJava\":\"17.0.20\"}");
        Files.writeString(f.log(),"total: 650\nprocessed: 650\npassed: "+(blocked?449:650)+"\nfailed: "+(blocked?201:0)+"\n");
        Map<String,byte[]> errors=new TreeMap<>();if(blocked)for(int i=0;i<201;i++)errors.put("failure-"+i+".txt",("java.lang.NoSuchMethodError: 'java.math.BigDecimal net.corda.core.internal.InternalUtils.sum(java.lang.Iterable)'\n at org.example.ledger.Agreement.verify(Agreement.java:12)\n").getBytes(StandardCharsets.UTF_8));
        SyntheticFixtureFactory.writeZip(f.errors(),errors);
        if(blocked)SyntheticFixtureFactory.writeZip(f.kit().resolve("legacy-jars/compatibility-shim.jar"),Map.of(SyntheticFixtureFactory.OWNER+".class",SyntheticFixtureFactory.utility(true)));
        Files.writeString(f.classpath(),"java -cp renamed-runtime.bin:legacy-jars/compatibility-shim.jar net.corda.verifier.Main\n");
        return f;
    }
    public static AssessmentService.Options options(SyntheticFixtureFactory.Fixture f,boolean tvu){return new AssessmentService.Options(f.node(),f.kit(),null,null,null,null,null,tvu?List.of(f.log(),f.errors()):List.of(),f.classpath(),null,"all-4.12",f.root().resolve("host.json"));}
    private static byte[] baseClass(String name,boolean face){ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC|(face?Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT:0),name,null,"java/lang/Object",null);w.visitEnd();return w.toByteArray();}
    private static void app(Path path,boolean flow,boolean modern,boolean call)throws IOException {
        String name=flow?FLOW:CONTRACT;ClassWriter w=new ClassWriter(0);w.visit(modern?Opcodes.V17:Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,flow?"net/corda/core/flows/FlowLogic":"java/lang/Object",flow?null:new String[]{"net/corda/core/contracts/Contract"});
        if(!flow){MethodVisitor m=w.visitMethod(Opcodes.ACC_PUBLIC,"verify","()V",null,null);m.visitCode();if(call){m.visitInsn(Opcodes.ACONST_NULL);m.visitMethodInsn(Opcodes.INVOKESTATIC,SyntheticFixtureFactory.OWNER,"sum",SyntheticFixtureFactory.DESC,false);m.visitInsn(Opcodes.POP);}m.visitInsn(Opcodes.RETURN);m.visitMaxs(1,1);m.visitEnd();}w.visitEnd();
        Map<String,byte[]> entries=new TreeMap<>();entries.put(name+".class",w.toByteArray());
        entries.put("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(modern?Map.of(flow?"Cordapp-Workflow-Name":"Cordapp-Contract-Name",flow?"Example workflow":"Example contract","Cordapp-Contract-Version","2","Min-Platform-Version","140","Target-Platform-Version","140"):Map.of()));
        SyntheticFixtureFactory.writeZip(path,entries);
    }
    public static void assertIdentity(Assessment a,boolean multi) {
        assertEquals("4.11.6",a.sourceVersion());assertEquals("4.12.11",a.targetVersion());
        Discovery.Model d=(Discovery.Model)a.evidence().get("discovery");
        assertEquals("13",d.sourcePlatform());assertEquals("140",d.targetPlatform());assertEquals("HIGH",d.confidence());assertEquals(2,d.currentCordappJars());assertEquals(2,d.targetCordappJars());assertEquals(1,d.currentOtherJars());assertEquals(a.findings().stream().anyMatch(x->x.category().equals("LEGACY_JARS"))?1:0,d.targetOtherJars());
        var cfg=(io.ledgerpreflight.evidence.ConfigAnalyzer.ConfigEvidence)a.evidence().get("schema-analysis");
        assertEquals("PostgreSQL",cfg.safeSettings().get("databaseVendor"));assertEquals(multi?"ExampleMixedCaseIssuer":"example_issuer",cfg.safeSettings().get("primarySchema"));assertEquals(multi?2:1,((List<?>)cfg.safeSettings().get("schemas")).size());
        assertEquals(1,((List<?>)a.evidence().get("upgrade-kit")).stream().filter(j->((Discovery.Artifact)j).role().equals("TVU")).count());
    }
    public static void generate(Path root)throws Exception {
        for(String kind:List.of("environment","blocked","clean")){
            boolean blocked=kind.equals("blocked"),multi=!kind.equals("clean");var f=create(root.resolve(kind),blocked,multi);var a=new AssessmentService().assess(options(f,blocked));assertIdentity(a,multi);
            assertEquals(blocked||multi?"BLOCKED":"READY FOR TVU",a.status());
            if(blocked){var t=(io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence)a.evidence().get("tvu-summary");assertEquals(201,t.detailedRecords());assertTrue(ProductView.result(a).contains("201 supplied failures match"));assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-LEGACY-001")&&x.severity().equals("BLOCKED")));}
            Reports.write(root.resolve(kind+"-asserted"),Reports.files(a));
            if(kind.equals("clean")){var ready=new AssessmentService().assess(options(f,true));assertIdentity(ready,false);assertEquals("READY TO UPGRADE",ready.status());Reports.write(root.resolve("ready-asserted"),Reports.files(ready));}
        }
    }
}
