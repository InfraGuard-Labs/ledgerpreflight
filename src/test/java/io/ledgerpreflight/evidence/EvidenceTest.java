package io.ledgerpreflight.evidence;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

class EvidenceTest {
    @TempDir Path temp;
    Path text(String name,String data) throws IOException { return Files.writeString(temp.resolve(name),data); }
    Path zip(String name, Map<String,String> data) throws IOException {
        Path path=temp.resolve(name);
        try(ZipOutputStream out=new ZipOutputStream(Files.newOutputStream(path))) {
            for(var entry:data.entrySet()) { out.putNextEntry(new ZipEntry(entry.getKey())); out.write(entry.getValue().getBytes(StandardCharsets.UTF_8)); out.closeEntry(); }
        }
        return path;
    }
    @Test void mixedCaseAndContradictorySchemaPreserveSignalsWithoutPasswords() throws Exception {
        var c=new ConfigAnalyzer().analyze(text("node.conf","database.schema=ExampleMixedCaseIssuer\ndataSourceProperties.\"dataSource.url\"=\"jdbc:postgresql://db/db?currentSchema=other&password=FakePassword123\"\npassword=superFakeSecret\nhibernate.default_schema=ExampleMixedCaseIssuer"));
        assertTrue(c.mixedCase()); assertTrue(c.contradictory()); assertTrue(c.postgresql());
        assertEquals("other",c.jdbcCurrentSchema()); assertEquals("ExampleMixedCaseIssuer",c.hibernateDefaultSchema());
        assertFalse(c.toString().contains("FakePassword")); assertFalse(c.toString().contains("superFakeSecret"));
    }
    @Test void localSubstitutionWorksWithoutReadingExternalConfiguration() throws Exception {
        var c=new ConfigAnalyzer().analyze(text("node.conf","localSchema=lowercase\ndatabase.schema=${localSchema}"));
        assertEquals("lowercase",c.schema()); assertFalse(c.mixedCase());
    }
    @Test void unresolvedCredentialPlaceholderDoesNotBlockLiteralSchemaAnalysis() throws Exception {
        var c=new ConfigAnalyzer().analyze(text("node.conf","database.schema=public\ndataSourceProperties.\"dataSource.password\"=${EXTERNAL_SECRET}"));
        assertEquals("public",c.schema()); assertFalse(c.toString().contains("EXTERNAL_SECRET"));
    }
    @Test void sqlQuotedSchemaIsPreservedAndUnquotedIsFolded() throws Exception {
        var good=new ConfigAnalyzer().analyze(text("quoted.conf","database.schema=MixedCase\ndataSourceProperties.connectionInitSql=\"SET search_path TO \\\"MixedCase\\\", public;\""));
        assertFalse(good.contradictory()); assertEquals(List.of("MixedCase","public"),good.safeSettings().get("searchPath"));
        var bad=new ConfigAnalyzer().analyze(text("unquoted.conf","database.schema=MixedCase\ndataSourceProperties.connectionInitSql=\"SET search_path TO MixedCase;\""));
        assertTrue(bad.contradictory()); assertEquals(List.of("mixedcase"),bad.safeSettings().get("searchPath"));
    }
    @Test void hoconIncludesAreRejected() throws Exception {
        assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(text("node.conf","include url(\"https://invalid.test/leak\")")));
    }
    @Test void hoconFileIncludesAreRejected() throws Exception {
        Path secret=text("secret.conf","password=FAKE_ONLY");
        assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(text("node.conf","include file(\""+secret.toString().replace("\\","/")+"\")")));
    }
    @Test void malformedHoconDoesNotEchoSecrets() throws Exception {
        IOException e=assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(text("node.conf","password=\"fake-private-value\n{")));
        assertFalse(e.getMessage().contains("fake-private-value"));
    }
    @Test void pathologicalHoconNestingIsRejected() throws Exception {
        assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(text("node.conf","a="+"[".repeat(100)+"]".repeat(100))));
    }
    @Test void parsesLimitedDetailedEvidenceWithoutExtrapolation() throws Exception {
        Path summary=text("tvu.log","transactions expected: 650\ntransactions processed: 650\nsucceeded: 449\nverification failed: 201");
        Path details=zip("errors.zip",Map.of("1.txt","java.lang.NoSuchMethodError: InternalUtils.sum(Iterable)","2.txt","java.lang.NoSuchMethodError: InternalUtils.sum(Iterable)","3.txt","java.lang.NoSuchMethodError: InternalUtils.sum(Iterable)"));
        var result=new TvuAnalyzer().analyze(List.of(summary,details));
        assertEquals(650L,result.processed()); assertEquals(449L,result.succeeded()); assertEquals(201L,result.failed());
        assertEquals(3,result.detailedRecords()); assertEquals(3,result.rootCauses().values().iterator().next());
        assertFalse(result.completeSuccess()); assertTrue(result.consistent());
    }
    @Test void repeatedArchiveEvidenceDoesNotInflateDetailedCounts() throws Exception {
        Path z=zip("errors.zip",Map.of("1.txt","java.lang.NoSuchMethodError: missing"));
        assertEquals(1,new TvuAnalyzer().analyze(List.of(z,z)).detailedRecords());
    }
    @Test void completeSuccessfulSummaryIsRequired() throws Exception {
        assertFalse(new TvuAnalyzer().analyze(List.of()).completeSuccess());
        assertFalse(new TvuAnalyzer().analyze(List.of(text("partial.log","succeeded: 650\nfailed: 0"))).completeSuccess());
        assertTrue(new TvuAnalyzer().analyze(List.of(text("full.log","expected: 650\nprocessed: 650\nsucceeded: 650\nfailed: 0"))).completeSuccess());
    }
    @Test void inconsistentCountersNeverPass() throws Exception {
        var result=new TvuAnalyzer().analyze(List.of(text("bad.log","expected: 650\nprocessed: 650\nsucceeded: 449\nfailed: 0")));
        assertFalse(result.consistent()); assertFalse(result.completeSuccess());
    }
    @Test void schemaFailureRemainsDistinctFromActualMissingTable() throws Exception {
        var result=new TvuAnalyzer().analyze(List.of(text("schema.log","Schema-validation: missing table [node_aes_encryption_keys]")));
        assertTrue(result.schemaValidationFailure()); assertFalse(result.completeSuccess());
    }
    @Test void zipTraversalRejected() throws Exception { assertThrows(IOException.class,()->new TvuAnalyzer().analyze(List.of(zip("evil.zip",Map.of("../escape.txt","x"))))); }
    @Test void windowsZipTraversalRejected() throws Exception { assertThrows(IOException.class,()->new TvuAnalyzer().analyze(List.of(zip("evil.zip",Map.of("C:\\escape.txt","x"))))); }
    @Test void compressedBombRejected() throws Exception { assertThrows(IOException.class,()->new TvuAnalyzer().analyze(List.of(zip("bomb.zip",Map.of("big.txt","x".repeat(2*1024*1024)))))); }
    @Test void malformedZipRejectedClearly() throws Exception { assertThrows(IOException.class,()->new TvuAnalyzer().analyze(List.of(text("broken.zip","not a zip")))); }
    @Test void secretsInLogsAndJdbcAreRedacted() {
        String data="password=FakePass\npasswd: 'FakePass2'\nclient_secret=FakeClient\nauthorization: Bearer fake.jwt.signature\njdbc:postgresql://user:FakeJdbc@db/db?password=FakeQuery&currentSchema=Example\napi-key=FakeApi";
        String safe=Sanitizer.redact(data);
        assertFalse(safe.contains("Fake")); assertFalse(safe.contains("fake.jwt.signature"));
    }
    @Test void longUntrustedIdentifiersAreHandledWithinBoundedTime() {
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(5),()->assertEquals(1_000_000,Sanitizer.redact("x".repeat(1_000_000)).length()));
    }
    @Test void longQuotedCredentialDoesNotExhaustRegexStack() {
        assertEquals("password=\"[REDACTED]\"",Sanitizer.redact("password=\""+"x".repeat(100_000)+"\""));
    }
    @Test void bundleOnlyIncludesGeneratedAllowlistAndChecksums() throws Exception {
        text("private.key","fake key"); text("private.jks","fake store"); text("private.pem","fake PEM");
        Path bundle=new SupportBundle().create(temp.resolve("safe.zip"),Map.of("summary.txt","password=FakePassword", "assessment.json","{}"));
        try(ZipFile z=new ZipFile(bundle.toFile())) {
            assertEquals(3,z.size()); assertNotNull(z.getEntry("checksums.sha256")); assertNull(z.getEntry("private.key"));
            assertFalse(new String(z.getInputStream(z.getEntry("summary.txt")).readAllBytes(),StandardCharsets.UTF_8).contains("FakePassword"));
        }
    }
    @Test void bundleRejectsUnapprovedEntry() { assertThrows(IOException.class,()->new SupportBundle().create(temp.resolve("bad.zip"),Map.of("secret.pem","fake"))); }
    @Test void structuredSecretValuesRedactedWithoutBreakingJson() throws Exception {
        Path bundle=new SupportBundle().create(temp.resolve("structured.zip"),Map.of("assessment.json","{\"password\": {\"nested\": \"FakeSecret\"}, \"public\": true}"));
        try(ZipFile z=new ZipFile(bundle.toFile())) {
            String content=new String(z.getInputStream(z.getEntry("assessment.json")).readAllBytes(),StandardCharsets.UTF_8);
            var parsed=new com.fasterxml.jackson.databind.ObjectMapper().readTree(content);
            assertEquals("[REDACTED]",parsed.get("password").asText()); assertFalse(content.contains("FakeSecret"));
        }
    }
    @Test void finalScannerFailsClosedAndProducesNoZip() {
        Path output=temp.resolve("bad.zip");
        assertThrows(IOException.class,()->new SupportBundle().create(output,Map.of("summary.txt","Unlabelled credential: " + "AKIA" + "ABCDEFGHIJKLMNOP")));
        assertFalse(Files.exists(output));
    }
    @Test void symlinkEvidenceRejected() throws Exception {
        Path real=text("real.log","expected: 1"); Path link=temp.resolve("link.log");
        Files.createSymbolicLink(link,real);
        assertThrows(IOException.class,()->new TvuAnalyzer().analyze(List.of(link)));
    }
}
