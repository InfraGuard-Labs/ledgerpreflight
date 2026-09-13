package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

public class ActiveRuntimeRegressionTest {
    @TempDir Path root;
    static SyntheticFixtureFactory.Fixture base(Path root)throws IOException{
        var f=ProductAcceptanceFixture.create(root,true,false);
        RunARegressionTest.update(f.node().resolve("corda.jar"),Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-ID","net.corda.node.CordaEnterprise","Application-Class","net.corda.node.Corda","Application-Version","4.11.6","Corda-Platform-Version","13","Min-Java-Version","1.8.0","Corda-Vendor","Corda Enterprise Edition"))),false);
        Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=ExampleSchema\"\n");
        return f;
    }
    public static void historical(Path file,String version)throws IOException{
        SyntheticFixtureFactory.writeZip(file,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-Class","net.corda.node.Corda","Application-Version",version,"Corda-Platform-Version","9","Min-Java-Version","1.7","Corda-Vendor","Corda Enterprise Edition")),"org/example/Historical.class",new byte[3*1024*1024]));
    }
    public static SyntheticFixtureFactory.Fixture fixture(Path root)throws IOException{
        var f=base(root);historical(f.node().resolve("corda.jar-old"),"4.10.1");historical(f.node().resolve("corda.jar-older"),"4.9.1");
        SyntheticFixtureFactory.writeZip(f.node().resolve("drivers/unreferenced-driver.jar"),Map.of("org/example/UnusedDriver.class",new byte[3*1024*1024]));
        return f;
    }
    public static void assertActive(Assessment a){
        assertEquals("4.11.6",a.sourceVersion());var d=(Discovery.Model)a.evidence().get("discovery");
        assertEquals("13",d.sourcePlatform());assertEquals("1.8.0",d.sourceMinimumJava());assertEquals("Corda Enterprise Edition",d.sourceVendor());
        assertEquals(2,d.currentCordappJars());assertEquals(2,d.targetCordappJars());assertEquals("4.12.11",d.targetVersion());
    }
    @Test void aCanonicalStrongRuntimeWinsAndHistoryNeverUsesDeepBudget()throws Exception{
        var f=fixture(root);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,true));assertActive(a);
        var selection=(Map<?,?>)a.evidence().get("current-runtime-selection");assertEquals("CANONICAL_ACTIVE_LOCATION",selection.get("origin"));assertEquals(2,selection.get("inactiveRuntimeCount"));
        var coverage=(Map<?,?>)a.evidence().get("analysis-coverage");assertEquals("COMPLETE_WITHIN_LIMITS",coverage.get("status"));
        assertFalse(coverage.get("currentInventory").toString().contains("corda.jar-old"));assertFalse(coverage.get("currentInventory").toString().contains("unreferenced-driver"));
        assertEquals("BLOCKED",a.status());assertTrue(a.findings().stream().anyMatch(finding->finding.id().equals("LP-API-001")));
    }
    @ParameterizedTest @ValueSource(strings={"corda-4.11.jar","corda-4.11.6.jar","runtime.jar","company-node.jar","custom-runtime.bin"})
    void bOneNoncanonicalRuntimeIsSelectedByContents(String name)throws Exception{
        var f=base(root);Files.move(f.node().resolve("corda.jar"),f.node().resolve(name));
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));assertActive(a);
        assertEquals("SINGLE_STRONG_CANDIDATE",((Map<?,?>)a.evidence().get("current-runtime-selection")).get("origin"));
    }
    @Test void cCustomRuntimeJarIsSelected()throws Exception{
        var f=base(root);Files.move(f.node().resolve("corda.jar"),f.node().resolve("custom-runtime.jar"));
        assertActive(new AssessmentService().assess(ProductAcceptanceFixture.options(f,false)));
    }
    @Test void dAmbiguousCurrentRuntimesAreNeverGuessed()throws Exception{
        var f=base(root);Files.move(f.node().resolve("corda.jar"),f.node().resolve("one.jar"));Files.copy(f.node().resolve("one.jar"),f.node().resolve("two.bin"));
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));assertEquals("unknown",a.sourceVersion());assertFalse(a.status().startsWith("READY"));
        assertTrue(a.findings().stream().anyMatch(finding->finding.id().equals("LP-CURRENT-RUNTIME")));
        var coverage=(Map<?,?>)a.evidence().get("analysis-coverage");assertFalse(coverage.get("currentInventory").toString().contains("one.jar"));assertFalse(coverage.get("currentInventory").toString().contains("two.bin"));
    }
    @Test void eInvalidCanonicalNameDoesNotOutrankARealRuntime()throws Exception{
        var f=base(root);Files.move(f.node().resolve("corda.jar"),f.node().resolve("valid.bin"));
        SyntheticFixtureFactory.writeZip(f.node().resolve("corda.jar"),Map.of("org/example/Helper.class",SyntheticFixtureFactory.emptyClass("org/example/Helper")));
        assertActive(new AssessmentService().assess(ProductAcceptanceFixture.options(f,false)));
    }
    @Test void fActiveMetadataPopulatesTheNormalizedModel()throws Exception{
        var f=base(root);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));assertActive(a);
        var d=(Discovery.Model)a.evidence().get("discovery");assertEquals(a.sourceVersion(),d.sourceVersion());
        assertFalse(ProductView.result(a).contains("Corda unknown"));
    }
    @ParameterizedTest @ValueSource(booleans={false,true}) void referencedDriverStillParticipatesInExactApiComparison(boolean explicitTargetApps)throws Exception{
        var f=base(root);String owner="org/example/driver/Support";
        ClassWriter provider=new ClassWriter(0);provider.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,owner,null,"java/lang/Object",null);
        var member=provider.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"run","()V",null,null);member.visitCode();member.visitInsn(Opcodes.RETURN);member.visitMaxs(0,0);member.visitEnd();provider.visitEnd();
        SyntheticFixtureFactory.writeZip(f.kit().resolve("drivers/required.jar"),Map.of(owner+".class",provider.toByteArray()));
        String name="org/example/DriverConsumer";ClassWriter consumer=new ClassWriter(0);consumer.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,"java/lang/Object",null);
        var call=consumer.visitMethod(Opcodes.ACC_PUBLIC,"verify","()V",null,null);call.visitCode();call.visitMethodInsn(Opcodes.INVOKESTATIC,owner,"run","()V",false);call.visitInsn(Opcodes.RETURN);call.visitMaxs(0,1);call.visitEnd();consumer.visitEnd();
        RunARegressionTest.update((explicitTargetApps?f.kit():f.node()).resolve(explicitTargetApps?"cordapps/example-new-contract.jar":"cordapps/example-old-contract.jar"),Map.of(name+".class",consumer.toByteArray()),false);
        var options=ProductAcceptanceFixture.options(f,false);
        if(explicitTargetApps){Path apps=root.resolve("explicit-apps");Files.move(f.kit().resolve("cordapps"),apps);options=new AssessmentService.Options(f.node(),f.kit(),null,null,apps,null,null,List.of(),f.classpath(),null,"all-4.12",root.resolve("host.json"));}
        var a=new AssessmentService().assess(options);
        assertTrue(((Map<?,?>)a.evidence().get("analysis-coverage")).get("targetInventory").toString().contains("drivers/required.jar"));
        assertFalse(a.findings().stream().anyMatch(finding->finding.id().startsWith("LP-API")&&finding.technicalEvidence().toString().contains(owner)));
    }
    public static void generate(Path root)throws Exception{
        var f=fixture(root);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,true));assertActive(a);
        assertEquals("COMPLETE_WITHIN_LIMITS",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
        Reports.write(root.resolve("asserted"),Reports.files(a));
    }
}
