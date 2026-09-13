package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.AssessmentService;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Real child-process acceptance inputs, assembled from original generated classes only. */
public final class GuidedTvuFixtureFactory {
    public static final String SECRET="SyntheticGuidedCredential42";
    public record Fixture(SyntheticFixtureFactory.Fixture assessment,Path control,Path reports,Path validator) {
        public AssessmentService.Options options(){return ProductAcceptanceFixture.options(assessment,false);}
    }
    private GuidedTvuFixtureFactory(){}
    public static Fixture create(Path root,String mode,boolean missingApi)throws Exception {
        if(!Set.of("success","failed","mixedZip","driver","secrets","cancel","orphan","dbfail","abort","schemafail","unsafeZip","corruptZip","fileLog","fileConflict").contains(mode))throw new IllegalArgumentException("Unknown synthetic process mode");
        var fixture=BlockerVerifierFixtureFactory.create(root,missingApi?"blocked":"compatible",false);
        Path control=root.resolve("process-observations"),reports=root.resolve("reports");Files.createDirectories(control);
        String conf="myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/isolated_copy?currentSchema=ExampleSchema\"\ndataSource.password=\""+SECRET+"\"\n";
        Files.writeString(fixture.node().resolve("node.conf"),conf);
        if(mode.equals("driver"))SyntheticFixtureFactory.writeZip(fixture.node().resolve("drivers/database-driver.jar"),Map.of("org/postgresql/Driver.class",SyntheticFixtureFactory.emptyClass("org/postgresql/Driver")));
        String program=SyntheticGuidedTvuProgram.class.getName().replace('.','/')+".class";byte[] bytes;
        try(InputStream in=SyntheticGuidedTvuProgram.class.getResourceAsStream("/"+program)){bytes=Objects.requireNonNull(in).readAllBytes();}
        Path jar=fixture.kit().resolve("renamed-validator.jar");
        String metadata="mode="+mode+"\ncontrol="+control.toAbsolutePath().toString().replace("\\","\\\\")+"\n";
        SyntheticFixtureFactory.writeZip(jar,Map.of(program,bytes,"synthetic-run.properties",metadata.getBytes(StandardCharsets.UTF_8),"net/corda/tools/TransactionValidator.class",SyntheticFixtureFactory.emptyClass("net/corda/tools/TransactionValidator"),"META-INF/MANIFEST.MF",SyntheticFixtureFactory.manifest(Map.of("Main-Class",SyntheticGuidedTvuProgram.class.getName(),"Corda-Release-Version","4.12.11","Min-Java-Version","17"))));
        return new Fixture(fixture,control,reports,jar);
    }
    public static Map<String,String> hashes(Path root)throws Exception {
        Map<String,String> result=new TreeMap<>();try(var paths=Files.walk(root)){for(Path path:paths.filter(Files::isRegularFile).sorted().toList())result.put(root.relativize(path).toString(),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))));}return result;
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Supply a synthetic output directory");Path root=Path.of(args[0]);
        for(String mode:List.of("failed","success","secrets","cancel","orphan","dbfail","schemafail","abort","unsafeZip","corruptZip","driver","mixedZip","fileLog","fileConflict"))create(root.resolve(mode),mode,mode.equals("failed")||mode.equals("mixedZip"));
    }
}
