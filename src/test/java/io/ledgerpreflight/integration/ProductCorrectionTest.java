package io.ledgerpreflight.integration;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import java.io.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import static org.junit.jupiter.api.Assertions.*;
class ProductCorrectionTest {
    @TempDir Path root;
    @Test void assertedAcceptanceCoversAllResultStates()throws Exception{ProductAcceptanceFixture.generate(root);}
    @Test void partialDeepAnalysisCannotErasePhysicalIdentity()throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,true);
        addEntry(f.node().resolve("corda.jar"),"large-runtime-data",new byte[20000]);
        addEntry(f.kit().resolve("renamed-runtime.bin"),"large-runtime-data",new byte[20000]);
        var limits=new BytecodeScanner.Limits(1000000,8192,100000,100,2,100,100);
        var a=new AssessmentService(limits).assess(ProductAcceptanceFixture.options(f,false));
        ProductAcceptanceFixture.assertIdentity(a,true);
        assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
        assertEquals("WARNING",a.status());assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-INPUT-001")));
        assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-DISCOVERY-002")||x.id().equals("LP-CORDAPP-004")));
    }
    @Test void perArtifactDeepBudgetDoesNotStarveLaterLegacyApps()throws Exception {
        for(String name:List.of("a","z"))SyntheticFixtureFactory.writeZip(root.resolve(name+".jar"),Map.of("example/"+name+".class",SyntheticFixtureFactory.emptyClass("example/"+name)));
        var result=new BytecodeScanner(new BytecodeScanner.Limits(100000,10000,10000,20,1,1,10)).scan(root);
        assertEquals(2,result.jars().size());assertTrue(result.issues().isEmpty());
        assertEquals(2,result.jars().stream().mapToInt(j->j.classes().size()).sum());
    }
    @ParameterizedTest @ValueSource(strings={"corda.jar","corda-4.12.11.jar","unrelated.jar","renamed-runtime.bin"})
    void physicalIdentityDoesNotDependOnFilename(String name)throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,false);Path source=f.kit().resolve("renamed-runtime.bin");Path renamed=f.kit().resolve(name);if(!source.equals(renamed))Files.move(source,renamed);
        var runtime=Discovery.select(new ArtifactDiscovery().scan(f.kit()),"RUNTIME");assertEquals(1,runtime.size());assertEquals("4.12.11",Discovery.version(runtime.get(0)));assertEquals("140",Discovery.platform(runtime.get(0)));
    }
    @Test void renamedTvuUsesEntriesWithoutParsingMalformedClassBody()throws Exception {
        Path p=root.resolve("arbitrary.jar");SyntheticFixtureFactory.writeZip(p,Map.of("net/corda/transactionvalidator/TransactionValidatorKt.class",new byte[]{1,2,3},"META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-Version","4.12.11"))));
        var identity=new ArtifactDiscovery().scan(p);assertEquals(1,Discovery.select(identity,"TVU").size());assertTrue(identity.issues().isEmpty());assertFalse(new BytecodeScanner().scan(p).issues().isEmpty());
    }
    @ParameterizedTest @ValueSource(strings={"Cordapp-Contract-Name","Cordapp-Workflow-Name"})
    void modernManifestIdentitySurvivesInvalidClassBodies(String header)throws Exception {
        Path p=root.resolve("anything.jar");SyntheticFixtureFactory.writeZip(p,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of(header,"Example App")),"random/Entry.class",new byte[]{1,2}));
        assertEquals(1,Discovery.select(new ArtifactDiscovery().scan(p),"CORDAPP").size());assertFalse(new BytecodeScanner().scan(p).issues().isEmpty());
    }
    @Test void fullFailureCorrelationAndLimitedEvidenceHaveDifferentClaims()throws Exception {
        var full=ProductAcceptanceFixture.create(root.resolve("full"),true,true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(full,true));String text=ProductView.result(a);
        assertEquals(1,ProductView.issues(a).stream().filter(i->i.title().equals("CorDapp compatibility")).count());assertEquals(1,ProductView.issues(a).stream().filter(i->i.title().equals("TVU validation")).count());
        assertTrue(text.contains("201 supplied failures match"));assertTrue(text.contains("449 passed"));assertFalse(text.contains("NoSuchMethodError"));assertFalse(text.contains(SyntheticFixtureFactory.DESC));
        var limited=SyntheticFixtureFactory.create(root.resolve("limited"),true);String partial=ProductView.result(new AssessmentService().assess(limited.options(true)));assertTrue(partial.contains("3 supplied failure details"));assertFalse(partial.contains("201 supplied failures match"));
    }
    @Test void correlationRequiresExactOwnerAndOverload() {
        var f=Finding.of("LP-API-001","Missing method","BLOCKED","API_COMPATIBILITY","HIGH","BYTECODE","app.jar",List.of("owner: org/example/RuntimeApi","member: convert","descriptor: (Ljava/lang/String;)I"),"Impact","Action");
        var a=new Assessment("1","0.1.0","BLOCKED","4.11","4.12",List.of(f),Map.of());
        for(String cause:List.of("java.lang.NoSuchMethodError: int org.example.OtherApi.convert(java.lang.String)","java.lang.NoSuchMethodError: int org.example.RuntimeApi.convert(int)"))assertEquals("",ProductView.correlation(a,new TvuAnalyzer.TvuEvidence(1L,1L,0L,1L,1,Map.of(cause,1),false,true,false,List.of())));
        assertTrue(ProductView.correlation(a,new TvuAnalyzer.TvuEvidence(1L,1L,0L,1L,1,Map.of("java.lang.NoSuchMethodError: int org.example.RuntimeApi.convert(java.lang.String)",1),false,true,false,List.of())).contains("1 supplied failures match"));
    }
    @ParameterizedTest @CsvSource(delimiter='|',textBlock="""
        database.schema=public | public | 1 | CONFIGURED
        database.schema=MixedCase | MixedCase | 1 | CONFIGURED
        dataSource.url="jdbc:postgresql://db.example/db?currentSchema=public" | public | 1 | CONFIGURED
        dataSource.url="jdbc:postgresql://db.example/db?currentSchema=primary,shared,reporting" | primary | 3 | CONFIGURED
        database.schema=primary,dataSource.url="jdbc:postgresql://db.example/db?currentSchema=primary,shared" | primary | 2 | CONFIGURED
        database.schema=primary,dataSource.url="jdbc:postgresql://db.example/db?currentSchema=other,shared" | Ambiguous | 3 | AMBIGUOUS
        hibernate.default_schema=MixedCase | MixedCase | 1 | CONFIGURED
        database.schema=primary,hibernate.default_schema=primary | primary | 1 | CONFIGURED
        database.schema=primary,hibernate.default_schema=other | Ambiguous | 2 | AMBIGUOUS
        connectionInitSql="SET search_path TO MAIN,shared" | main | 2 | CONFIGURED
        database.schema=$VALUE_PLACEHOLDER | Unknown | 0 | UNRESOLVED
        myLegalName="O=Example Company,L=London,C=GB" | Default (not independently established) | 0 | DEFAULT_UNVERIFIED
        """)
    void orderedSchemaMatrix(String config,String effective,int count,String resolution)throws Exception {
        config=config.replace("$VALUE_PLACEHOLDER","$"+"{MISSING_REQUIRED_PRODUCT_SCHEMA}");
        Path p=Files.writeString(root.resolve("node.conf"),config);var s=new ConfigAnalyzer().analyze(p).safeSettings();assertEquals(effective,s.get("effectiveSchema"));assertEquals(count,((List<?>)s.get("schemas")).size());assertEquals(resolution,s.get("schemaResolution"));
    }
    @Test void quotedCommasAndEncodedIdentifiersPreserveOrderedPath()throws Exception {
        Path p=Files.writeString(root.resolve("node.conf"),"dataSource.url=\"jdbc:postgresql://db.example/db?currentSchema=%22Mixed%2CCase%22,shared\"\n");var s=new ConfigAnalyzer().analyze(p).safeSettings();assertEquals("Mixed,Case",s.get("primarySchema"));assertEquals(List.of("Mixed,Case","shared"),s.get("jdbcSchemaPath"));
    }
    @Test void sqlQuotedSchemaMatchesPrimaryWithoutFolding()throws Exception {
        Path p=Files.writeString(root.resolve("node.conf"),"database.schema=MixedCase\nconnectionInitSql=\"SET search_path TO \\\"MixedCase\\\",SHARED\"\n");
        var s=new ConfigAnalyzer().analyze(p).safeSettings();assertEquals("MixedCase",s.get("primarySchema"));assertEquals(List.of("shared"),s.get("additionalSchemas"));assertEquals("HIGH",s.get("schemaConfidence"));
    }
    @Test void userDependentOrMultipleSearchPathAssignmentsStayUnresolved()throws Exception {
        for(String sql:List.of("SET search_path TO $user,public","SET search_path TO a; SET search_path TO b")){Path p=Files.writeString(root.resolve("node.conf"),"connectionInitSql="+Reports.JSON.writeValueAsString(sql));assertEquals("UNRESOLVED",new ConfigAnalyzer().analyze(p).safeSettings().get("schemaResolution"));}
    }
    @Test void readonlyIdentityRejectsTraversalAndArchiveBombResources()throws Exception {
        Path p=root.resolve("unsafe.jar");SyntheticFixtureFactory.writeZip(p,Map.of("../escape",new byte[1]));assertTrue(new ArtifactDiscovery().scan(p).jars().isEmpty());assertFalse(Files.exists(root.resolve("escape")));
        SyntheticFixtureFactory.writeZip(p,Map.of("META-INF/MANIFEST.MF",new byte[1000000]));assertTrue(new ArtifactDiscovery().scan(p).jars().isEmpty());
    }
    @Test void partialTargetCannotFabricateConfirmedRemovedClasses()throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,false);
        addEntry(f.kit().resolve("renamed-runtime.bin"),"large-data",new byte[20000]);
        var a=new AssessmentService(new BytecodeScanner.Limits(1000000,8192,100000,100,2,100,100)).assess(ProductAcceptanceFixture.options(f,false));
        ProductAcceptanceFixture.assertIdentity(a,false);assertEquals("READY FOR TVU",a.status());
        assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-API-006")&&x.severity().equals("BLOCKED")));
    }
    @ParameterizedTest @CsvSource({"org/example/runtime/ValueOps,compute,()I","org/example/runtime/Converters,translate,()Ljava/lang/String;","org/example/runtime/Sequence,next,()J"})
    void arbitraryRemovedMembersAndDuplicateShims(String owner,String member,String descriptor)throws Exception {
        var consumer=new org.objectweb.asm.ClassWriter(0);consumer.visit(52,1,"org/example/apps/Consumer",null,"java/lang/Object",null);
        var call=consumer.visitMethod(1,"verify","()V",null,null);call.visitCode();call.visitMethodInsn(184,owner,member,descriptor,false);call.visitInsn(descriptor.equals("()J")?88:87);call.visitInsn(177);call.visitMaxs(2,1);call.visitEnd();consumer.visitEnd();
        Path app=root.resolve("app.jar"),runtime=root.resolve("runtime.jar"),shim=root.resolve("shim.jar");
        SyntheticFixtureFactory.writeZip(app,Map.of("org/example/apps/Consumer.class",consumer.toByteArray()));
        SyntheticFixtureFactory.writeZip(runtime,Map.of(owner+".class",SyntheticFixtureFactory.emptyClass(owner)));
        var restored=new org.objectweb.asm.ClassWriter(0);restored.visit(61,1,owner,null,"java/lang/Object",null);var method=restored.visitMethod(9,member,descriptor,null,null);method.visitCode();method.visitInsn(descriptor.equals("()J")?9:descriptor.equals("()I")?3:1);method.visitInsn(descriptor.equals("()J")?173:descriptor.equals("()I")?172:176);method.visitMaxs(2,0);method.visitEnd();restored.visitEnd();
        SyntheticFixtureFactory.writeZip(shim,Map.of(owner+".class",restored.toByteArray()));
        var scanner=new BytecodeScanner();var analyzer=new io.ledgerpreflight.bytecode.CompatibilityAnalyzer();
        var findings=analyzer.analyze(scanner.scan(app).jars(),scanner.scan(runtime).jars(),scanner.scan(shim).jars(),true);
        assertTrue(findings.stream().anyMatch(i->i.id().equals("LP-API-001")&&i.severity().equals("BLOCKED")&&owner.equals(i.evidence().get("owner"))&&descriptor.equals(i.evidence().get("descriptor"))));
        assertTrue(findings.stream().anyMatch(i->i.id().equals("LP-LEGACY-001")&&i.severity().equals("BLOCKED")));
        assertFalse(analyzer.analyze(scanner.scan(app).jars(),scanner.scan(shim).jars(),List.of(),false).stream().anyMatch(i->i.id().equals("LP-API-001")));
    }
    @Test void nestedLibraryPlatformDoesNotOverrideRuntimeUpgradeRules()throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,false);Path nested=root.resolve("component.jar");
        SyntheticFixtureFactory.writeZip(nested,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Corda-Release-Version","4.11.6","Corda-Platform-Version","13")),"org/example/RuntimeHelper.class",SyntheticFixtureFactory.emptyClass("org/example/RuntimeHelper")));
        addEntry(f.kit().resolve("renamed-runtime.bin"),"lib/older-component.jar",Files.readAllBytes(nested));
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));ProductAcceptanceFixture.assertIdentity(a,false);assertEquals("READY FOR TVU",a.status());
    }
    @Test void literalSchemaContainingCommaAgreesWithQuotedJdbcPath()throws Exception {
        Path p=Files.writeString(root.resolve("node.conf"),"database.schema=\"Mixed,Case\"\ndataSource.url=\"jdbc:postgresql://db.example/db?currentSchema=%22Mixed%2CCase%22,shared\"");
        var cfg=new ConfigAnalyzer().analyze(p);assertFalse(cfg.contradictory());assertEquals("Mixed,Case",cfg.safeSettings().get("primarySchema"));assertEquals("HIGH",cfg.safeSettings().get("schemaConfidence"));
    }
    @Test void emptyExplicitSchemaDoesNotBecomeConfiguredPrimary()throws Exception {
        Path p=Files.writeString(root.resolve("node.conf"),"database.schema=\"\"");
        assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(p));
    }
    @Test void deeplyNestedAnnotationCannotCrashIdentityDiscovery()throws Exception {
        var writer=new org.objectweb.asm.ClassWriter(0);writer.visit(52,1,"org/example/Annotated",null,"java/lang/Object",null);
        var annotation=writer.visitAnnotation("Lorg/example/Marker;",true);var array=annotation.visitArray("value");List<org.objectweb.asm.AnnotationVisitor> arrays=new ArrayList<>();arrays.add(array);
        for(int i=0;i<20000;i++){array=array.visitArray(null);arrays.add(array);}array.visit(null,"bounded synthetic data");Collections.reverse(arrays);arrays.forEach(org.objectweb.asm.AnnotationVisitor::visitEnd);annotation.visitEnd();writer.visitEnd();
        Path p=root.resolve("nested-annotation.jar");SyntheticFixtureFactory.writeZip(p,Map.of("org/example/Annotated.class",writer.toByteArray()));
        var identity=new ArtifactDiscovery().scan(p);assertFalse(identity.issues().isEmpty());assertTrue(identity.issues().stream().anyMatch(x->x.message().contains("stack capacity")));
        assertFalse(new BytecodeScanner().scan(p).issues().isEmpty());
    }
    private static void addEntry(Path jar,String name,byte[] bytes)throws IOException {Map<String,byte[]> entries=new TreeMap<>();try(ZipFile z=new ZipFile(jar.toFile())){for(var en=z.entries();en.hasMoreElements();){var e=en.nextElement();try(var in=z.getInputStream(e)){entries.put(e.getName(),in.readAllBytes());}}}entries.put(name,bytes);SyntheticFixtureFactory.writeZip(jar,entries);}
}
