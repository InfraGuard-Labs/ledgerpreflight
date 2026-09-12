package io.ledgerpreflight.integration;

import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.ConfigAnalyzer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.io.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic capsule metadata and filesystem layout; no vendor artifacts. */
public class RealDiscoveryRegressionTest {
    @TempDir Path root;
    public static SyntheticFixtureFactory.Fixture fixture(Path root)throws IOException {
        var f=SyntheticFixtureFactory.create(root,false);
        Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema=\"ExampleMixedCaseIssuer\"\ndataSource.url=\"jdbc:postgresql://example.net/example?currentSchema=\\\"ExampleMixedCaseIssuer\\\"\"\n");
        capsule(f.node().resolve("corda.jar"),"4.11.6","13",false);
        capsule(f.kit().resolve("corda.jar"),"4.12.11","140",false);
        capsule(f.kit().resolve("transaction-validator.jar"),"4.12.11","140",true);
        Files.move(f.kit().resolve("corda.jar"),f.kit().resolve("prepared-runtime.jar"));
        Files.move(f.kit().resolve("transaction-validator.jar"),f.kit().resolve("validation-tool.jar"));
        for(String name:List.of("contracts","workflows","migration")) app(f.node().resolve("cordapps/"+name+".jar"),name);
        app(f.kit().resolve("cordapps/renamed-one.jar"),"contracts");app(f.kit().resolve("cordapps/renamed-two.jar"),"workflows");
        Files.createDirectories(f.node().resolve("drivers"));Files.createDirectories(f.node().resolve("djvm"));
        Path outside=root.resolve("external-dependency");Files.writeString(outside,"Synthetic excluded dependency");
        for(int i=0;i<47;i++)Files.createSymbolicLink(f.node().resolve("djvm/link-"+i),Path.of("../../external-dependency"));
        return f;
    }
    private static void app(Path path,String kind)throws IOException {
        SyntheticFixtureFactory.writeZip(path,Map.of("com/example/"+kind+"/Entry.class",SyntheticFixtureFactory.emptyClass("com/example/"+kind+"/Entry"),"META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Cordapp-Workflow-Name","Example "+kind))));
    }
    private static void capsule(Path path,String version,String platform,boolean tvu)throws IOException {
        String main=tvu?"net.corda.tools.transactionvalidator.Main":"net.corda.node.Corda";
        String props="releaseVersion="+version+"\nplatformVersion="+platform+"\nvendor=Corda Enterprise Edition\n";
        Map<String,byte[]> nested=Map.of(main.replace('.','/')+".class",SyntheticFixtureFactory.emptyClass(main.replace('.','/')),"net/corda/common/corda-version.properties",props.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(bytes)){for(var e:nested.entrySet()){zip.putNextEntry(new ZipEntry(e.getKey()));zip.write(e.getValue());zip.closeEntry();}}
        Map<String,byte[]> contents=new TreeMap<>(Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class","CordaCaplet","Application-Class",main,"Application-Version",version)),"lib/application.jar",bytes.toByteArray()));
        if(tvu){ByteArrayOutputStream dependency=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(dependency)){zip.putNextEntry(new ZipEntry("net/corda/node/Corda.class"));zip.write(SyntheticFixtureFactory.emptyClass("net/corda/node/Corda"));zip.closeEntry();}contents.put("lib/node-dependency.jar",dependency.toByteArray());}SyntheticFixtureFactory.writeZip(path,contents);
    }
    @Test void capsuleIdentityAndArtifactCountsAreDerived()throws Exception {
        var f=fixture(root);var scanner=new BytecodeScanner();var current=scanner.scan(f.node());var target=scanner.scan(f.kit());
        var old=Discovery.topLevel(Discovery.select(current,"RUNTIME"));var next=Discovery.topLevel(Discovery.select(target,"RUNTIME"));
        assertEquals(1,old.size());assertEquals(1,next.size());assertEquals("4.11.6",Discovery.version(old.get(0)));assertEquals("13",Discovery.platform(old.get(0)));
        assertEquals("4.12.11",Discovery.version(next.get(0)));assertEquals("140",Discovery.platform(next.get(0)));assertEquals("Corda Enterprise Edition",Discovery.attr(next.get(0),"Corda-Vendor"));
        assertEquals(1,Discovery.topLevel(Discovery.select(target,"TVU")).size());assertEquals(3,Discovery.topLevel(Discovery.select(current,"CORDAPP")).size());assertEquals(2,Discovery.topLevel(Discovery.select(target,"CORDAPP")).size());
        assertEquals(47,NodeDiscovery.discover(f.node()).issues().size());
    }
    @Test void matchingQuotedSchemaRemainsHighConfidence()throws Exception {
        var f=fixture(root);var cfg=new ConfigAnalyzer().analyze(f.node().resolve("node.conf"));
        assertEquals("ExampleMixedCaseIssuer",cfg.safeSettings().get("effectiveSchema"));assertEquals("HIGH",cfg.safeSettings().get("schemaConfidence"));assertTrue(cfg.postgresql());assertTrue(cfg.mixedCase());assertFalse(cfg.contradictory());
        assertEquals("ExampleIssuer",Discovery.displayName(cfg.safeSettings(),"current-node"));
    }
    @Test void percentEncodedQuotedSchemaAlsoMatches()throws Exception {
        Path conf=root.resolve("node.conf");Files.writeString(conf,"database.schema=ExampleMixedCaseIssuer\ndataSource.url=\"jdbc:postgresql://example.net/example?currentSchema=%22ExampleMixedCaseIssuer%22\"");
        assertEquals("HIGH",new ConfigAnalyzer().analyze(conf).safeSettings().get("schemaConfidence"));
    }
    @Test void conflictingSchemaRemainsAmbiguous()throws Exception {
        Path conf=root.resolve("node.conf");Files.writeString(conf,"database.schema=ExampleMixedCaseIssuer\ndataSource.url=\"jdbc:postgresql://example.net/example?currentSchema=other\"");
        var cfg=new ConfigAnalyzer().analyze(conf);assertTrue(cfg.contradictory());assertEquals("Unknown",cfg.safeSettings().get("effectiveSchema"));assertEquals("Explicit schema declarations disagree",cfg.safeSettings().get("schemaExplanation"));
    }
    @Test void assessmentPreservesIdentityAndMixedCaseFinding()throws Exception {
        var f=fixture(root);var a=new AssessmentService().assess(f.options(false));assertEquals("4.11.6",a.sourceVersion());assertEquals("4.12.11",a.targetVersion());
        assertTrue(a.findings().stream().anyMatch(x->x.category().equals("DATABASE_SCHEMA")&&x.title().toLowerCase().contains("case")));
        assertEquals("ExampleIssuer",((Map<?,?>)a.evidence().get("environment")).get("nodeName"));
        assertEquals(3,((List<?>)a.evidence().get("cordapps-current")).size());assertEquals(2,((List<?>)a.evidence().get("cordapps-target")).size());
    }
    @Test void conflictingResourceMetadataIsNotSilentlyAccepted()throws Exception {
        Path jar=root.resolve("corda.jar");SyntheticFixtureFactory.writeZip(jar,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class","net.corda.node.Corda","Corda-Release-Version","4.11.6")),"net/corda/corda-version.properties","releaseVersion=4.12.11\n".getBytes()));
        assertEquals("unknown",Discovery.version(new BytecodeScanner().scan(jar).jars().get(0)));
    }
    @Test void genericDependencyVersionDoesNotEstablishRuntimeIdentity()throws Exception {
        Path jar=root.resolve("corda-4.12.11.jar");SyntheticFixtureFactory.writeZip(jar,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Implementation-Version","4.12.11"))));
        assertTrue(Discovery.select(new BytecodeScanner().scan(jar),"RUNTIME").isEmpty());
    }
    @Test void limitedArchiveDoesNotHideLaterArtifactMetadata()throws Exception {
        Path node=root.resolve("node");Files.createDirectories(node);SyntheticFixtureFactory.writeZip(node.resolve("a.jar"),Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-Class","net.corda.node.Corda","Application-Version","4.11.6")),"large.txt",new byte[5000]));app(node.resolve("cordapps/later.jar"),"workflow");
        var scan=new BytecodeScanner(new BytecodeScanner.Limits(100000,1024,2000,100,2,100,100)).scan(node);assertFalse(scan.issues().isEmpty());assertEquals(1,Discovery.select(scan,"RUNTIME").size());assertEquals(1,Discovery.select(scan,"CORDAPP").size());
    }
    @Test void vendorLabelsDoNotEraseMatchingReleaseMetadata()throws Exception {
        Path jar=root.resolve("corda.jar");SyntheticFixtureFactory.writeZip(jar,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class","net.corda.node.Corda","Corda-Release-Version","4.11.6","Corda-Vendor","Example runtime vendor")),"net/corda/corda-version.properties","releaseVersion=4.11.6\nvendor=Example dependency vendor\n".getBytes()));assertEquals("4.11.6",Discovery.version(new BytecodeScanner().scan(jar).jars().get(0)));
    }
    @Test void metadataFallbackStillHonorsCompressedSizeLimit()throws Exception {
        Path jar=root.resolve("corda.jar");SyntheticFixtureFactory.writeZip(jar,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Application-Class","net.corda.node.Corda","Application-Version","4.11.6"))));var scan=new BytecodeScanner(new BytecodeScanner.Limits(16,1024,2000,100,2,100,100)).scan(jar);assertTrue(scan.jars().isEmpty());assertFalse(scan.issues().isEmpty());
    }
    @Test void nestedToolLibraryIsNotAStandaloneTvuArtifact()throws Exception {
        Path jar=root.resolve("corda.jar");ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(bytes)){zip.putNextEntry(new ZipEntry("net/corda/tools/TransactionValidator.class"));zip.write(SyntheticFixtureFactory.emptyClass("net/corda/tools/TransactionValidator"));zip.closeEntry();}SyntheticFixtureFactory.writeZip(jar,Map.of("META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class","net.corda.node.Corda","Corda-Release-Version","4.11.6")),"lib/helper.jar",bytes.toByteArray()));assertTrue(Discovery.select(new BytecodeScanner().scan(jar),"TVU").isEmpty());
    }
    @Test void explicitCapsulesRemainSingleRuntimeAndTvuArtifacts()throws Exception {
        var f=fixture(root);var options=new AssessmentService.Options(f.node(),f.kit(),f.kit().resolve("prepared-runtime.jar"),f.kit().resolve("validation-tool.jar"),null,null,null,List.of(),null,null);var a=new AssessmentService().assess(options);assertEquals("4.12.11",a.targetVersion());assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-DISCOVERY-007")));
    }
    public static void main(String[] args)throws Exception {fixture(Path.of(args[0]).toAbsolutePath());}
}
