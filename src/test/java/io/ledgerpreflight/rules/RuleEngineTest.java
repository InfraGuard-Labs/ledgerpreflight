package io.ledgerpreflight.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {
    @TempDir Path temp;
    final RuleEngine engine = new RuleEngine();
    private List<RuleFinding> evaluate(String... pairs) {
        Map<String,String> facts = new HashMap<>(Map.of("target.version","4.12.11", "source.version","4.11.6"));
        for(int i=0;i<pairs.length;i+=2) facts.put(pairs[i],pairs[i+1]);
        return engine.evaluate(facts);
    }
    private RuleFinding finding(String id, String... pairs) {
        return evaluate(pairs).stream().filter(f -> f.id().equals(id)).findFirst().orElseThrow();
    }
    @Test void detectsJava17AndPlatform140WithoutInventingInstalledRuntime() {
        assertTrue(finding("LP-JAVA-001").explanation().contains("Java 17"));
        assertTrue(finding("LP-PLATFORM-001").explanation().contains("140"));
        assertTrue(evaluate().stream().noneMatch(f -> f.severity().equals("BLOCKED")));
    }
    @Test void rejectsDirectUpgradeFrom410() {
        assertEquals("BLOCKED",finding("LP-UPGRADE-001","source.version","4.10.7").severity());
    }
    @Test void unknownTargetDoesNotBecomeReady() {
        assertEquals("UNKNOWN",finding("LP-UPGRADE-002","target.version","UNKNOWN").severity());
    }
    @Test void unsupportedTargetHasExplicitUnknownCoverage() {
        assertEquals("UNKNOWN",finding("LP-UPGRADE-003","target.version","4.13.1").severity());
    }
    @Test void absentValuesDoNotSatisfyInequality() {
        assertTrue(evaluate().stream().noneMatch(f -> f.id().equals("LP-JAVA-002")));
        assertEquals("BLOCKED",finding("LP-JAVA-002","target.java","21").severity());
    }
    @Test void hashReferencesWarnRatherThanClaimingPersistedConstraints() {
        RuleFinding f=finding("LP-CONSTRAINT-001","constraints.hashDetected","true");
        assertEquals("WARNING",f.severity());
        assertTrue(f.explanation().contains("persisted"));
        assertTrue(evaluate("constraints.hashDetected","false").stream().noneMatch(v -> v.id().equals(f.id())));
    }
    @Test void legacyVerifyPatternHasDocumentedAlternative() {
        assertTrue(finding("LP-VERIFY-001","verification.legacyPattern","true").nextAction().contains("SignedTransaction.verify()"));
    }
    @Test void signerMetadataMismatchDoesNotClaimSignatureVerification() {
        RuleFinding f=finding("LP-SIGNING-001","signing.continuity","different");
        assertEquals("WARNING",f.severity());
        assertTrue(f.explanation().contains("not cryptographic"));
    }
    @Test void mixedNetworkNeedsLegacyContractsButFullyUpgradedDoesNot() {
        assertEquals("BLOCKED",finding("LP-LEGACY-003","network.mode","mixed","legacyContracts.present","false").severity());
        assertTrue(evaluate("network.mode","all-4.12","legacyContracts.present","false").stream().noneMatch(f -> f.id().equals("LP-LEGACY-003")));
    }
    @Test void tvuArtifactIsRequired() {
        assertEquals("BLOCKED",finding("LP-TVU-001","tvu.present","false").severity());
    }
    @Test void exactVersionFamilyDoesNotMatch4120() {
        assertEquals("4.120",RuleEngine.family("4.120.1"));
        assertEquals("",RuleEngine.family("file4.12.1.jar"));
        assertTrue(evaluate("target.version","4.120.1").stream().noneMatch(f -> f.id().equals("LP-JAVA-001")));
    }
    @Test void orderAndContentAreDeterministic() {
        assertEquals(evaluate("signing.continuity","different","target.java","21"),evaluate("target.java","21","signing.continuity","different"));
        List<String> ids=evaluate().stream().map(RuleFinding::id).toList();
        assertEquals(ids.stream().sorted().toList(),ids);
    }
    private Path pack(RuleDefinition definition) throws Exception {
        Path file=temp.resolve("pack.json");
        new ObjectMapper().writeValue(file.toFile(), new RuleEngine.RulePack("1","local-1",List.of(definition)));
        return file;
    }
    private RuleDefinition user(String id,String op) {
        return new RuleDefinition(id,"Local review","WARNING","UPGRADE_PATH","MEDIUM","USER_RULE","Review needed","Local evidence","Review evidence",null,
            List.of(new RuleDefinition.Condition("target.version",op,"4.12")));
    }
    @Test void userPackIsAdditiveAndVersioned() throws Exception {
        RuleEngine loaded=engine.load(pack(user("USR-REVIEW","VERSION_FAMILY")));
        assertTrue(loaded.evaluate(Map.of("target.version","4.12.11")).stream().anyMatch(f -> f.id().equals("USR-REVIEW")));
        assertEquals(engine.catalog().size()+1,loaded.catalog().size());
    }
    @Test void cannotReplaceVendorRule() throws Exception {
        assertThrows(java.io.IOException.class,() -> engine.load(pack(user("LP-JAVA-001","EQUALS"))));
    }
    @Test void rejectsExecutableOperators() throws Exception {
        assertThrows(java.io.IOException.class,() -> engine.load(pack(user("USR-EXEC","EXEC"))));
    }
    @Test void rejectsDuplicateJsonKeys() throws Exception {
        Path p=temp.resolve("bad.json"); Files.writeString(p,"{\"schemaVersion\":\"1\",\"schemaVersion\":\"2\",\"version\":\"1\",\"rules\":[]}");
        assertThrows(java.io.IOException.class,() -> engine.load(p));
    }
    @Test void rejectsTrailingJson() throws Exception {
        Path p=temp.resolve("bad.json"); Files.writeString(p,"{\"schemaVersion\":\"1\",\"version\":\"1\",\"rules\":[]} {}");
        assertThrows(java.io.IOException.class,() -> engine.load(p));
    }
    @Test void rejectsOversizedPack() throws Exception {
        Path p=temp.resolve("huge.json"); Files.write(p,new byte[1_048_577]);
        assertThrows(java.io.IOException.class,() -> engine.load(p));
    }
    @Test void rejectsUnknownFields() throws Exception {
        Path p=temp.resolve("bad.json"); Files.writeString(p,"{\"schemaVersion\":\"1\",\"version\":\"1\",\"rules\":[],\"script\":\"x\"}");
        assertThrows(java.io.IOException.class,() -> engine.load(p));
    }
}
