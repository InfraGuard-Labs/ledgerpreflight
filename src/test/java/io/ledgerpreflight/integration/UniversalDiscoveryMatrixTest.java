package io.ledgerpreflight.integration;

import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.ConfigAnalyzer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import org.objectweb.asm.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Independent evidence combinations: filenames, customer namespaces and directory names carry no identity. */
class UniversalDiscoveryMatrixTest {
    @TempDir Path root;
    private Path jar(String name,Map<String,String> manifest,Map<String,byte[]> entries)throws Exception {
        var contents=new TreeMap<>(entries);contents.put("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(manifest));Path p=root.resolve(name);SyntheticFixtureFactory.writeZip(p,contents);return p;
    }
    private BytecodeScanner.JarInventory scan(Path p){var result=new BytecodeScanner().scan(p);assertTrue(result.issues().isEmpty(),result.issues().toString());return Discovery.topLevel(result.jars()).get(0);}
    private static byte[] type(String name,String parent,String... interfaces){var w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,parent,interfaces);w.visitEnd();return w.toByteArray();}
    @ParameterizedTest @CsvSource({"corda.jar,4.11.6,13,1.8","corda-4.11.6.jar,4.11.6,13,1.8","corda-4.12.11.jar,4.12.11,140,17","renamed-corda-target.jar,4.12.11,140,17"})
    void enterpriseManifestIdentifiesRuntimeWithoutClasses(String name,String version,String platform,String java)throws Exception {
        var j=scan(jar(name,Map.of("Application-Version",version,"Corda-Release-Version",version,"Corda-Platform-Version",platform,"Corda-Vendor","Corda Enterprise Edition","Corda-OpenCore-Version","4.11","Application-ID","net.corda.node.CordaEnterprise","Min-Java-Version",java),Map.of()));
        assertEquals("RUNTIME",Discovery.role(j));assertEquals(version,Discovery.version(j));assertEquals(platform,Discovery.platform(j));assertEquals(java,Discovery.attr(j,"Min-Java-Version"));assertEquals("Corda Enterprise Edition",Discovery.attr(j,"Corda-Vendor"));
    }
    @ParameterizedTest @ValueSource(strings={"transaction-validator.jar","renamed-validator.jar"})
    void tvuEntrypointContentsAreSufficient(String filename)throws Exception {
        String cls="net/corda/transactionvalidator/TransactionValidatorKt";var j=scan(jar(filename,Map.of("Application-Version","4.12.11"),Map.of(cls+".class",SyntheticFixtureFactory.emptyClass(cls))));assertEquals("TVU",Discovery.role(j));assertEquals("4.12.11",Discovery.version(j));
    }
    @Test void customerClassAndMisleadingFilenameDoNotProveTvu()throws Exception {
        String cls="org/example/TransactionValidator";assertEquals("UNKNOWN",Discovery.role(scan(jar("transaction-validator.jar",Map.of("Implementation-Version","4.12.11"),Map.of(cls+".class",SyntheticFixtureFactory.emptyClass(cls))))));
    }
    @Test void conflictingApplicationAndReleaseVersionsAreUnknown()throws Exception {
        var j=scan(jar("runtime.jar",Map.of("Application-Class","net.corda.node.Corda","Application-Version","4.11.6","Corda-Release-Version","4.12.11"),Map.of()));assertEquals("unknown",Discovery.version(j));
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void capsuleOwnMetadataIsSeparateFromBundledLibraryReleases(boolean declared)throws Exception {
        Path a=jar("one.jar",Map.of("Corda-Release-Version","4.11","Corda-Platform-Version","12"),Map.of());Path b=jar("two.jar",Map.of("Corda-Release-Version","4.11.5","Corda-Platform-Version","12"),Map.of());
        var metadata=new TreeMap<String,String>();metadata.put("Application-Class","net.corda.node.Corda");if(declared){metadata.put("Application-Version","4.11.6");metadata.put("Corda-Release-Version","4.11.6");metadata.put("Corda-Platform-Version","13");metadata.put("Corda-OpenCore-Version","4.11");}
        var capsule=scan(jar("capsule.jar",metadata,Map.of("lib/one.jar",Files.readAllBytes(a),"lib/two.jar",Files.readAllBytes(b))));assertEquals(declared?"4.11.6":"unknown",Discovery.version(capsule));assertEquals(declared?"13":"12",Discovery.platform(capsule));
    }
    @ParameterizedTest @CsvSource({"payments-core.jar,Cordapp-Contract-Name","ledger-contract.jar,Cordapp-Contract-Name","flows-prod.jar,Cordapp-Workflow-Name","company-app-v7.jar,Cordapp-Workflow-Name"})
    void modernManifestDoesNotDependOnFilename(String filename,String header)throws Exception {
        var j=scan(jar(filename,Map.of(header,"Example application","Target-Platform-Version","140","Min-Platform-Version","140"),Map.of("org/example/Independent.class",SyntheticFixtureFactory.emptyClass("org/example/Independent"))));assertEquals("CORDAPP",Discovery.role(j));
    }
    @ParameterizedTest @CsvSource({"org/example/settlement/Agreement,false","org/example/payments/Transfer,true","com/acme/sample/Entry,false","com/acme/sample/Flow,true"})
    void oldSignedManifestUsesBytecodeNotNamespace(String name,boolean flow)throws Exception {
        byte[] cls=type(name,flow?"net/corda/core/flows/FlowLogic":"java/lang/Object",flow?new String[]{}:new String[]{"net/corda/core/contracts/Contract"});
        Path p=jar("anything.jar",Map.of(),Map.of(name+".class",cls,"META-INF/EXAMPLE.SF","Signature-Version: 1.0\r\n\r\n".getBytes()));
        var j=scan(p);assertFalse(j.manifest().keySet().stream().anyMatch(k->k.startsWith("Cordapp-")));assertEquals("CORDAPP",Discovery.role(j));assertFalse(j.signatureFiles().isEmpty());
    }
    @Test void indirectWorkflowInheritanceIsRecognized()throws Exception {
        var j=scan(jar("inheritance.jar",Map.of(),Map.of("x/Base.class",type("x/Base","net/corda/core/flows/FlowLogic"),"x/Child.class",type("x/Child","x/Base"))));assertEquals("CORDAPP",Discovery.role(j));
    }
    @Test void serviceProviderMetadataNeedsContainedProvider()throws Exception {
        String service="META-INF/services/net.corda.core.contracts.Contract";
        var good=scan(jar("service.jar",Map.of(),Map.of(service,"org.example.ContractProvider\n".getBytes(),"org/example/ContractProvider.class",type("org/example/ContractProvider","java/lang/Object"))));assertEquals("CORDAPP",Discovery.role(good));
        var absent=scan(jar("empty-service.jar",Map.of(),Map.of(service,"org.example.Missing\n".getBytes())));assertEquals("UNKNOWN",Discovery.role(absent));
    }
    @Test void helperInCordappsDirectoryIsNotAutomaticallyAnApplication()throws Exception {
        var helper=scan(jar("cordapps/migration-helper.jar",Map.of("Implementation-Title","Example migration helper","Target-Platform-Version","140"),Map.of("org/example/Helper.class",type("org/example/Helper","java/lang/Object"))));assertEquals("UNKNOWN",Discovery.role(helper));assertEquals(1,Discovery.otherJars(new BytecodeScanner().scan(root)).size());
    }
    @Test void runtimeApiLibraryIsNotItselfACordapp()throws Exception {
        var j=scan(jar("cordapps/library.jar",Map.of(),Map.of("net/corda/core/flows/FlowLogic.class",type("net/corda/core/flows/FlowLogic","java/lang/Object"))));assertEquals("RUNTIME_LIBRARY",Discovery.role(j));
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void explicitOverrideDoesNotTurnUnrelatedBytesIntoRuntimeOrTvu(boolean tvu)throws Exception {
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Path unrelated=jar("unrelated.jar",Map.of("Implementation-Version","4.12.11"),Map.of("org/example/Helper.class",type("org/example/Helper","java/lang/Object")));
        var options=new AssessmentService.Options(f.node(),f.kit(),tvu?null:unrelated,tvu?unrelated:null,null,null,null,List.of(),null,null);var a=new AssessmentService().assess(options);
        assertTrue(a.findings().stream().anyMatch(x->x.id().equals(tvu?"LP-DISCOVERY-002":"LP-DISCOVERY-001")));assertNotEquals("READY FOR TVU",a.status());if(!tvu)assertEquals("unknown",a.targetVersion());
    }
    @Test void acceptanceModelIsHighWithTwoApplicationsAndOneHelper()throws Exception {
        var f=RealDiscoveryRegressionTest.fixture(root);var a=new AssessmentService().assess(f.options(false));var model=(Discovery.Model)a.evidence().get("discovery");
        assertEquals("HIGH",model.confidence());assertTrue(model.confidenceReasons().isEmpty());assertEquals(2,model.currentCordappJars());assertEquals(2,model.targetCordappJars());assertEquals(1,model.currentOtherJars());assertEquals("13",model.sourcePlatform());assertEquals("140",model.targetPlatform());assertEquals("1.8",model.sourceMinimumJava());assertEquals("17",model.targetMinimumJava());
        var cfg=(ConfigAnalyzer.ConfigEvidence)a.evidence().get("schema-analysis");assertEquals("Unknown",cfg.safeSettings().get("businessRole"));assertEquals("ExampleMixedCaseIssuer",cfg.safeSettings().get("effectiveSchema"));
    }
    @ParameterizedTest @ValueSource(strings={"runtime","tvu","schema","database"})
    void confidenceReflectsMissingCoreAndSupportingEvidence(String missing)throws Exception {
        var f=RealDiscoveryRegressionTest.fixture(root);
        switch(missing){case "runtime"->Files.delete(f.kit().resolve("renamed-corda-target.jar"));case "tvu"->Files.delete(f.kit().resolve("renamed-validator.jar"));case "schema"->Files.writeString(f.node().resolve("node.conf"),"dataSource.url=\"jdbc:postgresql://example.net/example\"");case "database"->Files.writeString(f.node().resolve("node.conf"),"database.schema=example\nhibernate.default_schema=example");}
        var model=(Discovery.Model)new AssessmentService().assess(f.options(false)).evidence().get("discovery");assertEquals(missing.equals("runtime")?"UNKNOWN":"MEDIUM",model.confidence());assertFalse(model.confidenceReasons().isEmpty());
    }
    @ParameterizedTest @ValueSource(strings={"runtime","tvu"})
    void duplicateSameVersionArtifactsAreStillAmbiguous(String kind)throws Exception {
        var f=RealDiscoveryRegressionTest.fixture(root);Files.copy(f.kit().resolve(kind.equals("runtime")?"renamed-corda-target.jar":"renamed-validator.jar"),f.kit().resolve("second.jar"));var a=new AssessmentService().assess(f.options(false));
        assertTrue(a.findings().stream().anyMatch(x->x.id().equals(kind.equals("runtime")?"LP-DISCOVERY-006":"LP-DISCOVERY-007")));if(kind.equals("runtime"))assertEquals("unknown",a.targetVersion());assertNotEquals("HIGH",((Discovery.Model)a.evidence().get("discovery")).confidence());
    }
    @ParameterizedTest @CsvSource({"database.schema=example,example,MEDIUM","database.schema=MixedCase,MixedCase,MEDIUM","database.schema=${LP_MISSING_MATRIX_SCHEMA},Unknown,UNKNOWN"})
    void singleSchemaAndUnresolvedValuesStayHonest(String declaration,String expected,String confidence)throws Exception {
        Path p=Files.writeString(root.resolve("node.conf"),declaration);var cfg=new ConfigAnalyzer().analyze(p);assertEquals(expected,cfg.safeSettings().get("effectiveSchema"));assertEquals(confidence,cfg.safeSettings().get("schemaConfidence"));
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void jdbcOnlyAndMatchingSchemaAreConsistentInFindings(boolean conflict)throws Exception {
        var f=SyntheticFixtureFactory.create(root,false);Files.writeString(f.node().resolve("node.conf"),"dataSource.url=\"jdbc:postgresql://example.net/example?currentSchema=ExampleMixedCaseIssuer\"\n"+(conflict?"database.schema=other":""));
        var a=new AssessmentService().assess(f.options(false));var cfg=(ConfigAnalyzer.ConfigEvidence)a.evidence().get("schema-analysis");var finding=a.findings().stream().filter(x->x.id().equals("LP-DB-001")).findFirst().orElseThrow();
        assertEquals(conflict?"Ambiguous":"ExampleMixedCaseIssuer",cfg.safeSettings().get("effectiveSchema"));assertEquals(conflict,finding.title().contains("unresolved"));assertTrue(finding.technicalEvidence().toString().contains("ExampleMixedCaseIssuer"));
        if(conflict)assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-DB-002")&&x.confidence().equals("UNKNOWN")));
    }
    @Test void unsupportedSearchPathDoesNotClaimAnEffectiveSchema()throws Exception {
        var cfg=new ConfigAnalyzer().analyze(Files.writeString(root.resolve("node.conf"),"database.schema=example\nconnectionInitSql=\"SET search_path TO ${example}, public\""));assertEquals("Unknown",cfg.safeSettings().get("effectiveSchema"));assertEquals("UNKNOWN",cfg.safeSettings().get("schemaConfidence"));
    }
    @ParameterizedTest @ValueSource(strings={"usr/local/node","opt/service","srv/ledger","custom/path with spaces"})
    void acceptanceFixtureIsIndependentOfInstallationPath(String path)throws Exception {
        var f=RealDiscoveryRegressionTest.fixture(root.resolve("source"));Path moved=root.resolve(path);Files.createDirectories(moved.getParent());Files.move(f.node(),moved);
        var a=new AssessmentService().assess(new AssessmentService.Options(moved,f.kit(),null,null,null,null,null,List.of(),null,null));assertEquals("ExampleIssuer",((Map<?,?>)a.evidence().get("environment")).get("nodeName"));assertEquals(2,((Discovery.Model)a.evidence().get("discovery")).currentCordappJars());
    }
}
