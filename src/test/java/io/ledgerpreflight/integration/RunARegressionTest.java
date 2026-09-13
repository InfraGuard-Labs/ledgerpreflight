package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.reporting.Reports;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real filesystem shape, synthetic bytes only. Also generates the packaged-process acceptance inputs. */
public class RunARegressionTest {
    @TempDir Path root;
    static byte[] largeManifest(Map<String,String> identity)throws IOException {
        Manifest m=new Manifest();m.getMainAttributes().putValue("Manifest-Version","1.0");
        identity.forEach((k,v)->m.getMainAttributes().putValue(k,v));
        for(int i=0;i<2000;i++)m.getMainAttributes().putValue("Unrelated-"+i,"synthetic dependency description ".repeat(5));
        for(int i=0;i<2000;i++){Attributes a=new Attributes();a.putValue("SHA-256-Digest","SyntheticDigestForParserCoverageOnly");m.getEntries().put("synthetic/Entry"+i+".class",a);}
        ByteArrayOutputStream b=new ByteArrayOutputStream();m.write(b);return b.toByteArray();
    }
    static void update(Path jar,Map<String,byte[]> replacements,boolean large)throws IOException {
        Path next=jar.resolveSibling(jar.getFileName()+".new");
        try(ZipFile old=new ZipFile(jar.toFile());ZipOutputStream out=new ZipOutputStream(Files.newOutputStream(next))){
            for(var entries=old.entries();entries.hasMoreElements();){ZipEntry e=entries.nextElement();if(replacements.containsKey(e.getName()))continue;out.putNextEntry(new ZipEntry(e.getName()));try(InputStream in=old.getInputStream(e)){in.transferTo(out);}out.closeEntry();}
            for(var e:new TreeMap<>(replacements).entrySet()){out.putNextEntry(new ZipEntry(e.getKey()));out.write(e.getValue());out.closeEntry();}
            if(large)for(int i=0;i<2000;i++){
                String name="org/example/load/Generated"+i;ClassWriter w=new ClassWriter(0);w.visit(Opcodes.V1_8,Opcodes.ACC_PUBLIC|Opcodes.ACC_ABSTRACT,name,null,"java/lang/Object",null);
                for(int n=0;n<200;n++)w.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_ABSTRACT,"method"+n+"x".repeat(512),"()V",null,null).visitEnd();w.visitEnd();
                out.putNextEntry(new ZipEntry(name+".class"));out.write(w.toByteArray());out.closeEntry();
            }
        }
        Files.move(next,jar,StandardCopyOption.REPLACE_EXISTING);
    }
    public static SyntheticFixtureFactory.Fixture fixture(Path root,boolean large)throws IOException {
        var f=ProductAcceptanceFixture.create(root,true,false);
        Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=ExampleSchema\"\n");
        Map<String,byte[]> additions=new TreeMap<>();
        additions.put("META-INF/MANIFEST.MF",largeManifest(Map.of("Application-ID","net.corda.node.CordaEnterprise","Application-Class","net.corda.node.Corda","Application-Version","4.11.6","Corda-Release-Version","4.11.6","Corda-Platform-Version","13","Corda-Vendor","Corda Enterprise Edition","Corda-OpenCore-Version","4.11.6","Min-Java-Version","1.8.0")));
        for(int i=0;i<40;i++){
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ZipOutputStream z=new ZipOutputStream(bytes)){
                z.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));z.write(SyntheticFixtureFactory.manifest(Map.of("Corda-Release-Version","4.99."+i,"Corda-Platform-Version","999")));z.closeEntry();
                z.putNextEntry(new ZipEntry("org/example/library/Library"+i+".class"));z.write(SyntheticFixtureFactory.emptyClass("org/example/library/Library"+i));z.closeEntry();
                byte[] payload=new byte[64*1024];new Random(i).nextBytes(payload);z.putNextEntry(new ZipEntry("payload"));for(int n=0;n<8;n++)z.write(payload);z.closeEntry();
            }additions.put("lib/corda-component-4.99."+i+".jar",bytes.toByteArray());
        }
        update(f.node().resolve("corda.jar"),additions,false);
        update(f.kit().resolve("cordapps/example-new-workflow.jar"),Map.of("META-INF/MANIFEST.MF",largeManifest(Map.of("Cordapp-Workflow-Name","Example workflow","Cordapp-Workflow-Version","2","Cordapp-Workflow-Vendor","Example","Target-Platform-Version","140","Min-Platform-Version","140")),"net/corda/transactionvalidator/BundledUtility.class",SyntheticFixtureFactory.emptyClass("net/corda/transactionvalidator/BundledUtility")),false);
        for(String dir:List.of("cordapps-backup","cordapps-old-date","archive-applications","drivers","cordapps/subdirectory")){
            Files.createDirectories(f.node().resolve(dir));
            for(int i=0;i<6;i++)Files.copy(f.node().resolve("cordapps/example-old-contract.jar"),f.node().resolve(dir+"/copy"+i+".jar"));
        }
        Files.createDirectories(f.kit().resolve("unselected"));Files.copy(f.kit().resolve("cordapps/example-new-contract.jar"),f.kit().resolve("unselected/ignored.jar"));
        if(large){update(f.node().resolve("cordapps/example-old-contract.jar"),Map.of(),true);update(f.node().resolve("cordapps/example-old-workflow.jar"),Map.of(),true);}
        return f;
    }
    static void identity(Assessment a){
        assertEquals("4.11.6",a.sourceVersion());assertEquals("4.12.11",a.targetVersion());
        Discovery.Model d=(Discovery.Model)a.evidence().get("discovery");assertEquals("13",d.sourcePlatform());assertEquals("140",d.targetPlatform());assertEquals(2,d.currentCordappJars());assertEquals(2,d.targetCordappJars());
        var current=(List<?>)a.evidence().get("cordapps-current");assertEquals(2,current.size());assertTrue(current.stream().noneMatch(x->x.toString().contains("backup")||x.toString().contains("drivers")));
    }
    @Test void rootManifestAndSemanticFilesystemBoundaries()throws Exception {
        var f=fixture(root,false);var scan=new ArtifactDiscovery().scanLayout(f.node());
        var runtimes=Discovery.select(scan,"RUNTIME");assertEquals(1,runtimes.size());assertEquals("4.11.6",Discovery.version(runtimes.get(0)));assertEquals("13",Discovery.platform(runtimes.get(0)));assertEquals("Corda Enterprise Edition",Discovery.attr(runtimes.get(0),"Corda-Vendor"));
        assertEquals(3,scan.jars().stream().filter(j->j.path().startsWith("cordapps/")).count());assertEquals(2,Discovery.select(scan,"CORDAPP").size());assertEquals(6,Discovery.select(scan,"DRIVER").size());
        assertTrue(scan.jars().stream().noneMatch(j->j.path().contains("backup")||j.path().contains("old-date")||j.path().contains("!/")||j.path().contains("subdirectory")));
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));identity(a);assertEquals("BLOCKED",a.status());assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-API-001")));
    }
    @Test void symbolPressureStopsSafelyWithoutIdentityStarvation()throws Exception {
        var f=fixture(root,true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));identity(a);
        assertFalse(a.status().startsWith("READY"));assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
        assertTrue(a.findings().stream().anyMatch(x->x.technicalEvidence().toString().contains("symbol memory")));
        assertTrue(ProductView.result(a).contains("Compatibility analysis incomplete"));
    }
    @Test void wrappedManifestValuesAreJoinedAndSignedSectionsIgnored()throws Exception {
        byte[] b=("Manifest-Version: 1.0\r\nApplication-ID: net.corda.node.\r\n CordaEnterprise\r\nCorda-Release-Version: 4.11.\r\n 6\r\nCorda-Platform-Version: 13\r\n\r\nName: arbitrary\r\nCorda-Release-Version: 4.99.0\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var m=ManifestMetadata.read(new ByteArrayInputStream(b));assertEquals("net.corda.node.CordaEnterprise",m.get("Application-ID"));assertEquals("4.11.6",m.get("Corda-Release-Version"));
    }
    @Test void truncatedRuntimeComparisonCannotClaimCompleteCoverage()throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,false);Map<String,byte[]> additions=new TreeMap<>();
        for(int i=0;i<600;i++){String name="org/example/retired/Api"+i;additions.put(name+".class",SyntheticFixtureFactory.emptyClass(name));}
        update(f.node().resolve("corda.jar"),additions,false);
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));
        assertEquals("READY FOR TVU",a.status());assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
        assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-ANALYSIS-LIMIT")));
    }
    @Test void excessiveSignatureMetadataDoesNotErasePhysicalIdentity()throws Exception {
        var f=ProductAcceptanceFixture.create(root,false,false);Map<String,byte[]> additions=new TreeMap<>();
        for(int i=0;i<400;i++)additions.put("META-INF/SIGNER"+i+".SF",new byte[0]);
        update(f.node().resolve("corda.jar"),additions,false);
        var identity=new ArtifactDiscovery().scanLayout(f.node());var runtime=Discovery.select(identity,"RUNTIME").get(0);
        assertEquals("4.11.6",Discovery.version(runtime));assertTrue(runtime.signatureFiles().size()<400);
        assertTrue(identity.issues().stream().anyMatch(i->i.message().contains("Signature inventory retention limit")));
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));assertEquals("READY FOR TVU",a.status());assertEquals("PARTIAL",((Map<?,?>)a.evidence().get("analysis-coverage")).get("status"));
    }
    public static void generate(Path root)throws Exception {
        for(boolean large:List.of(false,true)){String name=large?"large":"normal";var f=fixture(root.resolve(name),large);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(f,false));identity(a);assertFalse(a.status().startsWith("READY"));Reports.write(root.resolve(name+"-asserted"),Reports.files(a));}
    }
}
