package io.ledgerpreflight.evidence;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import io.ledgerpreflight.reporting.Reports;
import static org.junit.jupiter.api.Assertions.*;

/** New required-symbol exports must pass the same publication gate as existing evidence. */
class IndependentRequiredSymbolSupportTest {
    @TempDir Path root;
    @Test void requiredProofExportRedactsStructuredAndEmbeddedCredentials()throws Exception {
        String evidence=Reports.json(Map.of("sourceArtifact","cordapps/source-contract.jar","sourceClass","example/contract/Caller","descriptor","(Ljava/lang/Iterable;)Ljava/math/BigDecimal;","current",Map.of("classStatus","found","memberStatus","found"),"target",Map.of("classStatus","found","memberStatus","absent"),"connection","jdbc:postgresql://fixture:FixtureCredential81@localhost/example","password","FixtureCredential82","detail","authorization: Bearer FixtureCredential83"));
        Path bundle=new SupportBundle().create(root.resolve("support.zip"),Map.of("required-symbol-resolution.json",evidence));
        try(ZipFile zip=new ZipFile(bundle.toFile())){String safe=new String(zip.getInputStream(zip.getEntry("required-symbol-resolution.json")).readAllBytes(),StandardCharsets.UTF_8);assertFalse(safe.contains("FixtureCredential"));assertTrue(safe.contains("source-contract.jar"));assertTrue(safe.contains("(Ljava/lang/Iterable;)Ljava/math/BigDecimal;"));assertEquals("absent",Reports.JSON.readTree(safe).path("target").path("memberStatus").asText());assertNotNull(zip.getEntry("checksums.sha256"));}
    }
    @Test void secretInNewProofMustPreventAnyPublishedZip()throws Exception {
        String suspicious="gh"+"p_"+"X".repeat(30);Path output=root.resolve("rejected.zip");
        assertThrows(java.io.IOException.class,()->new SupportBundle().create(output,Map.of("required-symbol-resolution.json",Reports.json(Map.of("sourceClass",suspicious)))));
        assertFalse(Files.exists(output));try(var files=Files.list(root)){assertEquals(0,files.count());}
    }
    @Test void requiredProofCannotAuthorizePrivateMaterialEntries(){
        Path output=root.resolve("rejected.zip");assertThrows(java.io.IOException.class,()->new SupportBundle().create(output,Map.of("required-symbol-resolution.json","{}","source-contract.pem","private material")));assertFalse(Files.exists(output));
    }
}