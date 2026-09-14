package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.objectweb.asm.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;

/** Generic synthetic APIs exercise the complete physical discovery and context-resolution path. */
public class ExecutionContextIntegrationTest {
    @TempDir Path root;
    private static final String OWNER=RequiredCompatibilityIntegrationTest.OWNER;
    private static final String VERIFIER="tools/external-verifier.jar";
    public static SyntheticFixtureFactory.Fixture fixture(Path root,String mode,boolean nested,boolean partial)throws Exception {
        var initial=RequiredCompatibilityIntegrationTest.fixture(root,mode.equals("blocked")?"method":"compatible",partial);
        Files.move(initial.node(),root.resolve("node"));Files.move(initial.kit(),root.resolve("kit"));
        var f=new SyntheticFixtureFactory.Fixture(root,root.resolve("node"),root.resolve("kit"),initial.log(),initial.errors(),initial.classpath());
        Map<String,byte[]> callers=new TreeMap<>();
        for(int i=1;i<3;i++){
            String name="org/example/ledger/Caller"+i;ClassWriter w=new ClassWriter(0);
            w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,"java/lang/Object",new String[]{"net/corda/core/contracts/Contract"});
            var m=w.visitMethod(Opcodes.ACC_PUBLIC,"verify","()V",null,null);m.visitCode();m.visitInsn(Opcodes.ACONST_NULL);
            m.visitMethodInsn(Opcodes.INVOKESTATIC,OWNER,"total",RequiredCompatibilityIntegrationTest.DESC,false);m.visitInsn(Opcodes.POP);m.visitInsn(Opcodes.RETURN);m.visitMaxs(1,1);m.visitEnd();w.visitEnd();callers.put(name+".class",w.toByteArray());
        }
        RunARegressionTest.update(f.node().resolve("cordapps/example-old-contract.jar"),callers,false);
        Map<String,byte[]> driver=Map.of(OWNER+".class",RequiredCompatibilityIntegrationTest.api(false,true,false),"net/corda/core/contracts/Contract.class",contractType());
        SyntheticFixtureFactory.writeZip(f.node().resolve("drivers/companion-tool.jar"),driver);
        SyntheticFixtureFactory.writeZip(f.kit().resolve("drivers/companion-tool.jar"),driver);
        Path verifier=root.resolve("verifier-component.jar");verifier(verifier,mode.equals("compatible"));
        if(nested){RunARegressionTest.update(f.kit().resolve("renamed-runtime.bin"),Map.of(VERIFIER,Files.readAllBytes(verifier)),false);Files.delete(verifier);}
        else Files.move(verifier,f.kit().resolve("external-verifier.jar"));
        Files.writeString(f.classpath(),"java -cp "+(nested?VERIFIER:"external-verifier.jar")+" net.corda.verifier.Main\n");
        String schema=mode.equals("compatible")?"example_issuer":"ExampleSchema";
        Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema="+schema+"\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema="+schema+"\"\n");
        return f;
    }
    private static byte[] contractType(){ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC|Opcodes.ACC_INTERFACE|Opcodes.ACC_ABSTRACT,"net/corda/core/contracts/Contract",null,"java/lang/Object",null);w.visitEnd();return w.toByteArray();}
    private static void verifier(Path path,boolean exact)throws Exception{
        SyntheticFixtureFactory.writeZip(path,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class","net.corda.verifier.Main","Corda-Release-Version","4.12.11")),"net/corda/verifier/Main.class",SyntheticFixtureFactory.emptyClass("net/corda/verifier/Main"),OWNER+".class",RequiredCompatibilityIntegrationTest.api(false,exact,false),"net/corda/core/contracts/Contract.class",contractType()));
    }
    private static ContextResult context(SymbolResult p,ExecutionContext context){return p.contexts().stream().filter(c->c.context()==context).findFirst().orElseThrow();}
    private static Assessment assess(SyntheticFixtureFactory.Fixture f)throws Exception{return new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));}
    @ParameterizedTest @ValueSource(booleans={true,false})
    void realShapeResolvesEachContextWithoutDriverOrVerifierAmbiguity(boolean nested)throws Exception{
        var f=fixture(root,"blocked",nested,false);var a=assess(f);var p=RequiredCompatibilityIntegrationTest.required(a);
        assertEquals("BLOCKED",a.status());assertEquals(Resolution.MISSING_METHOD,p.resolution());assertEquals(3,p.contexts().size());
        assertEquals("found",p.current().memberStatus());assertTrue(p.current().artifacts().get(0).startsWith("corda.jar!/lib/required-component.jar"));
        for(var c:List.of(ExecutionContext.TARGET_NODE_RUNTIME,ExecutionContext.TARGET_VERIFIER)){
            assertEquals("found",context(p,c).proof().classStatus());assertEquals("absent",context(p,c).proof().memberStatus());assertEquals(Resolution.MISSING_METHOD,context(p,c).resolution());
        }
        assertFalse(p.target().artifacts().get(0).contains("verifier"));assertTrue(context(p,ExecutionContext.TARGET_VERIFIER).proof().artifacts().get(0).contains("external-verifier.jar"));
        assertEquals(Set.of("cordapps/example-old-contract.jar"),p.sources().stream().map(Source::sourceArtifact).collect(java.util.stream.Collectors.toSet()));
        assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-API-003")||x.id().equals("LP-API-004")));
        Discovery.Model discovery=(Discovery.Model)a.evidence().get("discovery");assertEquals(2,discovery.currentCordappJars());assertEquals(2,discovery.targetCordappJars());assertEquals("13",discovery.sourcePlatform());assertEquals("140",discovery.targetPlatform());
    }
    @Test void nodeCompatibleVerifierMissingIsAConfirmedVerifierBlocker()throws Exception{
        var f=fixture(root,"verifier-only",true,false);var a=assess(f);var p=RequiredCompatibilityIntegrationTest.required(a);
        assertEquals("BLOCKED",a.status());assertEquals(Resolution.COMPATIBLE,context(p,ExecutionContext.TARGET_NODE_RUNTIME).resolution());assertEquals(Resolution.MISSING_METHOD,context(p,ExecutionContext.TARGET_VERIFIER).resolution());
        assertTrue(ProductView.result(a).toLowerCase(Locale.ROOT).contains("verifier"));
    }
    @Test void compatibleStandardClassesAndWorkflowOnlyApisStayQuiet()throws Exception{
        var f=fixture(root,"compatible",true,false);var a=assess(f);assertEquals("READY FOR TVU",a.status());
        assertTrue(a.findings().stream().noneMatch(x->x.category().equals("API_COMPATIBILITY")||x.category().equals("LEGACY_JARS")));
        var symbols=Reports.JSON.valueToTree(a.evidence().get("required-symbol-resolution")).path("symbols");
        boolean flow=false;for(var symbol:symbols)if(symbol.path("symbol").path("owner").asText().equals("net/corda/core/flows/FlowLogic")){flow=true;assertEquals(2,symbol.path("contexts").size());}
        assertTrue(flow,"Workflow API is checked in node contexts without fabricating a verifier dependency");
        assertEquals("READY TO UPGRADE",new AssessmentService().assess(ProductAcceptanceFixture.options(f,true)).status());
    }
    @Test void targetPairingUnresolvedDoesNotDowngradeRuntimeProof()throws Exception{
        var f=fixture(root,"blocked",true,false);
        Files.copy(f.kit().resolve("cordapps/example-new-contract.jar"),f.kit().resolve("cordapps/example-new-workflow.jar"),StandardCopyOption.REPLACE_EXISTING);
        var a=assess(f);assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-CORDAPP-005")));assertEquals("BLOCKED",a.status());assertEquals(Resolution.MISSING_METHOD,RequiredCompatibilityIntegrationTest.required(a).resolution());
        assertTrue(ProductView.issues(a).stream().anyMatch(i->i.title().equals("Target CorDapp mapping")));
    }
    @ParameterizedTest @ValueSource(strings={"verifier-first","shim-first","unproven","contradictory"})
    void verifierLegacySelectionUsesProvenOrderOnly(String mode)throws Exception{
        var f=fixture(root,"verifier-only",true,false);String shim="legacy-jars/compatibility-shim.jar";
        SyntheticFixtureFactory.writeZip(f.kit().resolve(shim),Map.of(OWNER+".class",RequiredCompatibilityIntegrationTest.api(false,true,false)));
        String order=mode.equals("shim-first")?shim+":"+VERIFIER:VERIFIER+":"+shim;
        Files.writeString(f.classpath(),mode.equals("unproven")?"No launch evidence supplied\n":"java -cp "+order+" net.corda.verifier.Main\n"+(mode.equals("contradictory")?OWNER.replace('/','.')+" source: file:/validation/"+shim+"\n":""));
        var a=assess(f);var p=RequiredCompatibilityIntegrationTest.required(a);assertEquals(Resolution.COMPATIBLE,context(p,ExecutionContext.TARGET_NODE_RUNTIME).resolution());
        Resolution expected=mode.equals("verifier-first")?Resolution.MISSING_METHOD:mode.equals("shim-first")?Resolution.COMPATIBLE:Resolution.UNKNOWN;
        assertEquals(expected,context(p,ExecutionContext.TARGET_VERIFIER).resolution());
        assertEquals(mode.equals("verifier-first"),a.findings().stream().anyMatch(x->x.id().equals("LP-LEGACY-001")&&x.severity().equals("BLOCKED")));
        if(mode.equals("verifier-first"))assertFalse(context(p,ExecutionContext.TARGET_VERIFIER).proof().shadowedArtifacts().isEmpty());
        if(mode.equals("shim-first"))assertFalse(a.findings().stream().anyMatch(x->x.category().equals("API_COMPATIBILITY")||x.category().equals("LEGACY_JARS")));
    }
    @Test void unorderedSameContextDoesNotMakeOtherContextsUnknown()throws Exception{
        var f=fixture(root,"verifier-only",false,false);verifier(f.kit().resolve("second-verifier.jar"),true);Files.writeString(f.classpath(),"No launch evidence supplied\n");
        var a=assess(f);var p=RequiredCompatibilityIntegrationTest.required(a);
        assertEquals(Resolution.COMPATIBLE,context(p,ExecutionContext.CURRENT_NODE_RUNTIME).resolution());assertEquals(Resolution.COMPATIBLE,context(p,ExecutionContext.TARGET_NODE_RUNTIME).resolution());assertEquals(Resolution.UNKNOWN,context(p,ExecutionContext.TARGET_VERIFIER).resolution());assertEquals("BLOCKED",a.status());assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-DB-001")&&x.severity().equals("BLOCKED")));
    }
    @Test void broadPartialDoesNotDowngradeSuccessfulExactContexts()throws Exception{
        var f=fixture(root,"blocked",true,true);var a=assess(f);
        assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));assertEquals("BLOCKED",a.status());assertEquals(Resolution.MISSING_METHOD,RequiredCompatibilityIntegrationTest.required(a).resolution());assertFalse(ProductView.result(a).contains("Compatibility analysis incomplete"));
    }
    @Test void exportsContainIndependentProofWithoutAbsoluteInputPaths()throws Exception{
        var f=fixture(root,"blocked",true,false);var a=assess(f);var files=Reports.files(a);
        assertTrue(files.containsKey("execution-contexts.json"));String contexts=Reports.JSON.writeValueAsString(a.evidence().get("execution-contexts"));assertFalse(contexts.contains(root.toString()));
        var p=RequiredCompatibilityIntegrationTest.required(a);assertEquals(3,p.contexts().size());assertTrue(Reports.JSON.writeValueAsString(p).contains("TARGET_VERIFIER"));
    }
    public static void generate(Path root)throws Exception{
        for(String mode:List.of("blocked","verifier-only","compatible")){
            var f=fixture(root.resolve(mode),mode,true,true);var a=assess(f);assertEquals(mode.equals("compatible")?"READY FOR TVU":"BLOCKED",a.status());
            Reports.write(root.resolve(mode+"-asserted"),Reports.files(a));
        }
    }
}
