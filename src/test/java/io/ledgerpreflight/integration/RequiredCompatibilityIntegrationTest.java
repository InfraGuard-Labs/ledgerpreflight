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
import java.io.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

/** Full assessment integration: generic required APIs inside selected synthetic runtime capsules. */
public class RequiredCompatibilityIntegrationTest {
    @TempDir Path root;
    static final String OWNER="org/example/runtime/Amounts",METHOD="total",DESC="(Ljava/lang/Iterable;)Ljava/math/BigDecimal;";
    public static SyntheticFixtureFactory.Fixture fixture(Path root,String mode,boolean broadPartial)throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,false);
        boolean field=mode.startsWith("field");
        Map<String,byte[]> consumers=new TreeMap<>();
        for(int n=0;n<3;n++){
            String name=n==0?ProductAcceptanceFixture.CONTRACT:"org/example/ledger/Caller"+n;
            ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,name,null,"java/lang/Object",n==0?new String[]{"net/corda/core/contracts/Contract"}:null);
            var m=w.visitMethod(Opcodes.ACC_PUBLIC,"verify","()V",null,null);m.visitCode();
            if(field)m.visitFieldInsn(Opcodes.GETSTATIC,OWNER,"balance","Ljava/math/BigDecimal;");
            else{m.visitInsn(Opcodes.ACONST_NULL);m.visitMethodInsn(Opcodes.INVOKESTATIC,OWNER,METHOD,DESC,false);}
            m.visitInsn(Opcodes.POP);m.visitInsn(Opcodes.RETURN);m.visitMaxs(1,1);m.visitEnd();w.visitEnd();consumers.put(name+".class",w.toByteArray());
        }
        RunARegressionTest.update(f.node().resolve("cordapps/example-old-contract.jar"),consumers,false);
        Map<String,byte[]> rebuilt=new TreeMap<>();
        for(int n=1;n<3;n++){String name="org/example/ledger/Caller"+n;rebuilt.put(name+".class",SyntheticFixtureFactory.emptyClass(name));}
        RunARegressionTest.update(f.kit().resolve("cordapps/example-new-contract.jar"),rebuilt,false);
        for(boolean target:List.of(false,true)){
            Path component=root.resolve(target?"target-component.jar":"current-component.jar");
            byte[] cls=mode.equals("malformed")&&target?new byte[]{0,1,2}:api(field,!target||mode.equals("compatible"),target&&mode.endsWith("descriptor"));
            Map<String,byte[]> entries=mode.equals("class")&&target?Map.of("org/example/runtime/Unrelated.class",SyntheticFixtureFactory.emptyClass("org/example/runtime/Unrelated")):Map.of(OWNER+".class",cls);
            SyntheticFixtureFactory.writeZip(component,entries);
            Path runtime=(target?f.kit():f.node()).resolve(target?"renamed-runtime.bin":"corda.jar");
            RunARegressionTest.update(runtime,Map.of("lib/required-component.jar",Files.readAllBytes(component)),false);
            Files.delete(component);
        }
        if(broadPartial){
            Path runtime=f.kit().resolve("renamed-runtime.bin"),next=runtime.resolveSibling("next.jar");
            try(ZipFile old=new ZipFile(runtime.toFile());ZipOutputStream out=new ZipOutputStream(Files.newOutputStream(next))){
                for(var all=old.entries();all.hasMoreElements();){var e=all.nextElement();out.putNextEntry(new ZipEntry(e.getName()));try(InputStream in=old.getInputStream(e)){in.transferTo(out);}out.closeEntry();}
                out.putNextEntry(new ZipEntry("unrelated-runtime-resource"));byte[] chunk=new byte[1024*1024];for(int i=0;i<33;i++)out.write(chunk);out.closeEntry();
            }Files.move(next,runtime,StandardCopyOption.REPLACE_EXISTING);
        }
        return f;
    }
    static byte[] api(boolean field,boolean exact,boolean descriptor){
        ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC,OWNER,null,"java/lang/Object",null);
        if(field){if(exact||descriptor)w.visitField(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"balance",descriptor?"Ljava/lang/Number;":"Ljava/math/BigDecimal;",null,null).visitEnd();}
        else if(exact||descriptor){var m=w.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,METHOD,descriptor?"(Ljava/lang/String;)Ljava/math/BigDecimal;":DESC,null,null);m.visitCode();m.visitInsn(Opcodes.ACONST_NULL);m.visitInsn(Opcodes.ARETURN);m.visitMaxs(1,1);m.visitEnd();}
        w.visitEnd();return w.toByteArray();
    }
    static RequiredSymbolAnalyzer.SymbolResult required(Assessment a)throws Exception{
        Object value=a.evidence().get("required-symbol-resolution");
        var json=Reports.JSON.valueToTree(value);
        return Reports.JSON.treeToValue(java.util.stream.StreamSupport.stream(json.path("symbols").spliterator(),false).filter(n->n.path("symbol").path("owner").asText().equals(OWNER)&&!n.path("symbol").path("kind").asText().equals("CLASS")).findFirst().orElseThrow(),RequiredSymbolAnalyzer.SymbolResult.class);
    }
    @ParameterizedTest @ValueSource(strings={"method","class","descriptor","field","field-descriptor"})
    void exactRuntimeProofHasOneRootAndOnlyHistoricalSource(String mode)throws Exception{
        var f=fixture(root,mode,false);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));var proof=required(a);
        assertEquals("BLOCKED",a.status());assertEquals("found",proof.current().classStatus());assertEquals("found",proof.current().memberStatus());
        assertEquals(mode.equals("class")?"absent":"found",proof.target().classStatus());
        assertEquals(mode.endsWith("descriptor")?RequiredSymbolAnalyzer.Resolution.DESCRIPTOR_MISMATCH:mode.equals("class")?RequiredSymbolAnalyzer.Resolution.MISSING_CLASS:mode.equals("field")?RequiredSymbolAnalyzer.Resolution.MISSING_FIELD:RequiredSymbolAnalyzer.Resolution.MISSING_METHOD,proof.resolution());
        assertEquals(3,proof.sources().stream().map(RequiredSymbolAnalyzer.Source::sourceClass).distinct().count());
        assertEquals(Set.of("cordapps/example-old-contract.jar"),proof.sources().stream().map(RequiredSymbolAnalyzer.Source::sourceArtifact).collect(java.util.stream.Collectors.toSet()));
        var roots=a.findings().stream().filter(x->x.category().equals("API_COMPATIBILITY")&&x.technicalEvidence().stream().anyMatch(e->e.equals("owner: "+OWNER))).toList();
        assertEquals(1,roots.size());assertEquals("current/historical/cordapps/example-old-contract.jar",roots.get(0).affectedArtifact());
        assertTrue(proof.current().artifacts().stream().anyMatch(p->p.contains("!/lib/required-component.jar")));
    }
    @Test void broadPartialCannotDowngradeConfirmedMissingMethod()throws Exception{
        var f=fixture(root,"method",true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));
        assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
        assertEquals("BLOCKED",a.status());assertEquals(RequiredSymbolAnalyzer.Resolution.MISSING_METHOD,required(a).resolution());
        assertFalse(ProductView.result(a).contains("Compatibility analysis incomplete"));
        assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-API-003")||x.id().equals("LP-INPUT-001")));
    }
    @Test void broadPartialDoesNotPreventReadinessWhenRequiredSymbolsResolved()throws Exception{
        var f=fixture(root,"compatible",true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));
        assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));assertEquals("READY FOR TVU",a.status());
        assertEquals(RequiredSymbolAnalyzer.Resolution.COMPATIBLE,required(a).resolution());
        assertEquals("READY TO UPGRADE",new AssessmentService().assess(ProductAcceptanceFixture.options(f,true)).status());
    }
    @Test void targetedLimitNeverClaimsRemoval()throws Exception{
        var f=fixture(root,"method",false);var d=TargetedRuntimeLookup.Limits.defaults();
        var limited=new TargetedRuntimeLookup.Limits(d.maxArchiveBytes(),d.maxNestedBytes(),d.maxReadBytes(),1,d.maxDepth(),d.maxNestedArchives(),d.maxOwners(),d.maxClassBytes(),d.maxMembers(),d.maxSignatureBytes(),d.maxMillis(),d.javaFeature());
        var a=new AssessmentService(BytecodeScanner.Limits.defaults(),limited).assess(ProductAcceptanceFixture.options(f,false));
        assertEquals("UNKNOWN",a.status());assertEquals(RequiredSymbolAnalyzer.Resolution.UNKNOWN,required(a).resolution());
        assertFalse(a.findings().stream().anyMatch(x->x.category().equals("API_COMPATIBILITY")&&x.severity().equals("BLOCKED")));
    }
    @Test void malformedRequiredClassNeverClaimsRemoval()throws Exception{
        var f=fixture(root,"malformed",false);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));
        assertEquals("UNKNOWN",a.status());assertEquals(RequiredSymbolAnalyzer.Resolution.UNKNOWN,required(a).resolution());
    }
    @Test void repeatedTvuFailuresCorrelateToOneGroupedMissingMethod()throws Exception{
        var f=fixture(root,"method",true);tvuFailure(f);
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,true));
        assertTrue(ProductView.result(a).contains("201 supplied failures match"));
        assertEquals(1,a.findings().stream().filter(x->x.id().equals("LP-TVU-002")).count());
        assertEquals(1,a.findings().stream().filter(x->x.category().equals("API_COMPATIBILITY")&&x.severity().equals("BLOCKED")).count());
    }
    static void tvuFailure(SyntheticFixtureFactory.Fixture f)throws IOException{
        Files.writeString(f.log(),"total: 650\nprocessed: 650\npassed: 449\nfailed: 201\n");
        Map<String,byte[]> errors=new TreeMap<>();for(int n=0;n<201;n++)errors.put("failure-"+n+".txt",("java.lang.NoSuchMethodError: 'java.math.BigDecimal "+OWNER.replace('/','.')+"."+METHOD+"(java.lang.Iterable)'\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        SyntheticFixtureFactory.writeZip(f.errors(),errors);
    }
    public static void generate(Path root)throws Exception{
        for(String name:List.of("blocked","compatible")){
            var f=fixture(root.resolve(name),name.equals("blocked")?"method":"compatible",true);
            Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=ExampleSchema\"\n");
            if(name.equals("blocked"))tvuFailure(f);
            var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
            assertEquals(name.equals("blocked")?RequiredSymbolAnalyzer.Resolution.MISSING_METHOD:RequiredSymbolAnalyzer.Resolution.COMPATIBLE,required(a).resolution());
            Reports.write(root.resolve(name+"-asserted"),Reports.files(a));
        }
    }
}
