package io.ledgerpreflight.evidence;

import com.typesafe.config.ConfigRenderOptions;
import com.typesafe.config.ConfigValueFactory;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.ProductAcceptanceFixture;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SchemaReadinessTest {
    @TempDir Path root;
    private ConfigAnalyzer.ConfigEvidence analyze(String declarations) throws IOException {
        Path path=root.resolve("selected-node.conf");
        Files.writeString(path,"dataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=ExampleSchema\"\n"+declarations);
        return new ConfigAnalyzer().analyze(path);
    }
    private static String schema(String identifier) {
        return "database.schema="+ConfigValueFactory.fromAnyRef(identifier).render(ConfigRenderOptions.concise())+"\n";
    }
    private static ConfigAnalyzer.TvuSchemaReadiness readiness(ConfigAnalyzer.ConfigEvidence config) {
        return ConfigAnalyzer.tvuSchemaReadiness(config,"4.12.11");
    }
    @Test void unquotedMatchingSchemaRequiresConfigurationBeforeTvu() throws Exception {
        var proof=readiness(analyze(schema("ExampleSchema")));
        assertTrue(proof.applicable());assertFalse(proof.proven());assertEquals("REQUIRED_UNPROVEN",proof.status());
    }
    @Test void explicitQuotedSelectedDatabaseSchemaProvidesOnlyStaticConfigurationProof() throws Exception {
        var config=analyze(schema("\"ExampleSchema\""));var proof=readiness(config);
        assertTrue(proof.applicable());assertTrue(proof.proven());assertEquals("CONFIGURATION_PROVEN",proof.status());
        assertEquals("ExampleSchema",proof.effectiveSchema());assertEquals("selected-node.conf",proof.configurationSource());
        assertEquals("hibernate.default_schema",proof.mappedProperty());assertEquals("\"ExampleSchema\"",proof.configuredValue());
        assertTrue(proof.evidence().stream().anyMatch(x->x.contains("only when TVU uses this selected configuration")&&x.contains("successful TVU execution")));
        assertEquals("ExampleSchema",config.safeSettings().get("primarySchema"));
    }
    @ParameterizedTest @ValueSource(strings={"hibernate.default_schema","database.hibernate.default_schema","\"hibernate.default_schema\""})
    void undocumentedHibernateAliasCannotProveTheRequiredTvuMapping(String key) throws Exception {
        assertFalse(readiness(analyze(key+"=\"\\\"ExampleSchema\\\"\"\n")).proven());
    }
    @Test void everyHibernateAliasMustAgreeEvenWhenAnEarlierAliasMatches() throws Exception {
        var config=analyze(schema("\"ExampleSchema\"")+"hibernate.default_schema=ExampleSchema\ndatabase.hibernate.default_schema=OtherSchema\n");
        assertTrue(config.contradictory());assertFalse(readiness(config).proven());
        assertEquals(2,((Map<?,?>)config.safeSettings().get("hibernateSchemaDeclarations")).size());
    }
    @Test void literalAndObjectHibernateAliasesCannotHideAConflict() throws Exception {
        var config=analyze(schema("\"ExampleSchema\"")+"hibernate.default_schema=ExampleSchema\n\"hibernate.default_schema\"=OtherSchema\n");
        assertTrue(config.contradictory());assertFalse(readiness(config).proven());
    }
    @Test void unresolvedSchemaAliasCannotClearTheBlocker() throws Exception {
        var config=analyze(schema("\"ExampleSchema\"")+"hibernate.default_schema=${LP_SYNTHETIC_UNSET_SCHEMA}\n");
        assertEquals("UNRESOLVED",config.safeSettings().get("schemaResolution"));assertFalse(readiness(config).proven());
    }
    @Test void jdbcAndSearchPathAgreementDoesNotEstablishHibernateQuoting() throws Exception {
        var config=analyze("connectionInitSql=\"SET search_path TO \\\"ExampleSchema\\\"\"\n");
        assertTrue(readiness(config).applicable());assertFalse(readiness(config).proven());
    }
    @Test void nodeJvmPropertiesAreNotTvuConfigurationProof() throws Exception {
        assertFalse(readiness(analyze(schema("ExampleSchema")+"systemProperties { hibernate.default_schema=\"\\\"ExampleSchema\\\"\" }\n")).proven());
    }
    @ParameterizedTest @ValueSource(strings={"\"ExampleSchema\"junk","\"ExampleSchema","\"\"","\" \"","\"ExampleSchema\" extra\""})
    void malformedWholeQuotedIdentifiersFailClosed(String value) {
        assertThrows(IOException.class,()->analyze(schema(value)));
    }
    @ParameterizedTest @ValueSource(strings={"Unknown","4.11.6","4.13.0","5.0","4.12.11-preview","4.120.1"})
    void unrelatedOrUnprovenTargetFamiliesDoNotReceiveTheKnownTvuBlocker(String target) throws Exception {
        assertFalse(ConfigAnalyzer.tvuSchemaReadiness(analyze(schema("ExampleSchema")),target).applicable());
    }
    @Test void additionalMixedCaseSchemaDoesNotMakeALowercasePrimaryApplicable() throws Exception {
        Path path=root.resolve("node.conf");Files.writeString(path,"database.schema=example_issuer\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=example_issuer,SharedSchema\"\n");
        var config=new ConfigAnalyzer().analyze(path);assertTrue(config.mixedCase());assertFalse(readiness(config).applicable());
    }
    @Test void nonPostgresqlMixedCaseSchemaDoesNotReceiveThePostgresqlBlocker() throws Exception {
        Path path=root.resolve("node.conf");Files.writeString(path,schema("ExampleSchema")+"database.url=\"jdbc:oracle:thin:example\"\n");
        assertFalse(readiness(new ConfigAnalyzer().analyze(path)).applicable());
    }
    @Test void proofUsesTheSelectedConfigurationIncludingItsBoundedLocalInclude() throws Exception {
        Files.writeString(root.resolve("schema.conf"),schema("\"ExampleSchema\""));
        assertTrue(readiness(analyze("include \"schema.conf\"\n")).proven());
    }
    @Test void unresolvedMixedCaseSchemaBlocksStaticAssessment() throws Exception {
        var fixture=ProductAcceptanceFixture.create(root,false,true);
        Files.delete(fixture.kit().resolve("renamed-validator.jar")); // Automatic setup cannot be promised without a selected TVU.
        var assessment=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,false));
        assertEquals("BLOCKED",assessment.status());
        assertEquals(1,assessment.findings().stream().filter(f->f.id().equals("LP-DB-001")&&f.severity().equals("BLOCKED")).count());
        var config=(ConfigAnalyzer.ConfigEvidence)assessment.evidence().get("schema-analysis");
        assertEquals("REQUIRED_UNPROVEN",((ConfigAnalyzer.TvuSchemaReadiness)config.safeSettings().get("tvuSchemaReadiness")).status());
    }
    @Test void provenConfigurationClearsSchemaBlockerWithoutClaimingTvuSuccess() throws Exception {
        var fixture=ProductAcceptanceFixture.create(root,false,true);quoteFixtureSchema(fixture.node());
        var assessment=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,false));
        assertEquals("READY FOR TVU",assessment.status());assertFalse(assessment.findings().stream().anyMatch(f->f.id().equals("LP-DB-001")));
        ProductAcceptanceFixture.assertIdentity(assessment,true);
    }
    @Test void provenConfigurationAndSuccessfulTvuCanReachReadyToUpgrade() throws Exception {
        var fixture=ProductAcceptanceFixture.create(root,false,true);quoteFixtureSchema(fixture.node());
        Files.writeString(fixture.log(),"HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema=\"ExampleMixedCaseIssuer\"}\n",StandardOpenOption.APPEND);
        assertEquals("READY TO UPGRADE",new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,true)).status());
    }
    @Test void actualTvuSchemaFailureStillBlocksWithMatchingStaticConfiguration() throws Exception {
        var fixture=ProductAcceptanceFixture.create(root,false,true);quoteFixtureSchema(fixture.node());
        Files.writeString(fixture.log(),"total: 650\nprocessed: 650\npassed: 650\nfailed: 0\norg.hibernate.tool.schema.spi.SchemaManagementException: Schema-validation: missing table [ExampleMixedCaseIssuer.vault_states]\n");
        var assessment=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,true));
        assertEquals("BLOCKED",assessment.status());assertTrue(assessment.findings().stream().anyMatch(f->f.id().equals("LP-DB-003")&&f.severity().equals("BLOCKED")));
        assertEquals("FAILED",io.ledgerpreflight.core.ProductView.schemaSetupStatus(assessment));
    }
    private static void quoteFixtureSchema(Path node) throws IOException {
        Path path=node.resolve("node.conf");Files.writeString(path,Files.readString(path).replace("database.schema=ExampleMixedCaseIssuer",schema("\"ExampleMixedCaseIssuer\"").strip()));
    }
}
