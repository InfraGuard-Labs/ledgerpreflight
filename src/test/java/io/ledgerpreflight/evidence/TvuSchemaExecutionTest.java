package io.ledgerpreflight.evidence;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.integration.ProductAcceptanceFixture;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
class TvuSchemaExecutionTest {
    @TempDir Path root;
    static String loaded(String schema)throws Exception{return "INFO org.hibernate.cfg.Environment - HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema="+ConfigAnalyzer.quotedTvuSchema(schema)+", hibernate.connection.password=CredentialNotForReports}\n";}
    TvuSchemaEvidence.Proof proof(String text,String expected)throws Exception{Path log=root.resolve("tvu.log");Files.writeString(log,text);return TvuSchemaEvidence.analyze(List.of(log),expected);}
    @ParameterizedTest @ValueSource(strings={"ExampleSchema","Issuer_2","Schema,Shared","Quoted\"Name","Σchema"})
    void exactLoadedQuotedSchemaIsExecutionEvidence(String schema)throws Exception{
        var result=proof(loaded(schema),schema);assertTrue(result.handled());assertFalse(result.mismatch());assertEquals("HANDLED",result.status());
        assertFalse(result.toString().contains("CredentialNotForReports"));
    }
    @ParameterizedTest @ValueSource(strings={"hibernate.default_schema=\"ExampleSchema\"","Wrote hibernate.properties with schema ExampleSchema","Could not load hibernate.properties","HHH000206: hibernate.properties not found","HHH000205: Loaded properties from resource other.properties: {hibernate.default_schema=\"ExampleSchema\"}"})
    void preparationOrUnrelatedTextCannotProveExecution(String text)throws Exception{assertFalse(proof(text,"ExampleSchema").handled());}
    @Test void mismatchedOrUnquotedSchemaRemainsUnproven()throws Exception{
        assertTrue(proof(loaded("OtherSchema"),"ExampleSchema").mismatch());
        assertTrue(proof("HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema=ExampleSchema}","ExampleSchema").mismatch());
    }
    @Test void conflictingLoadedDefaultsCannotBeHandled()throws Exception{assertTrue(proof(loaded("ExampleSchema")+loaded("OtherSchema"),"ExampleSchema").mismatch());}
    @Test void repeatedMatchingStartupEvidenceIsConsistent()throws Exception{assertTrue(proof(loaded("ExampleSchema")+loaded("ExampleSchema"),"ExampleSchema").handled());}
    @Test void escapedEvidenceSymlinkIsRejected()throws Exception{Path outside=root.resolve("outside.log");Files.writeString(outside,loaded("ExampleSchema"));Path link=root.resolve("linked.log");Files.createSymbolicLink(link,outside);assertThrows(java.io.IOException.class,()->TvuSchemaEvidence.analyze(List.of(link),"ExampleSchema"));}
    @Test void safePreparationDoesNotDependOnUnrelatedUnresolvedConfiguration()throws Exception{
        Path config=root.resolve("node.conf");Files.writeString(config,"database.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/example\"\nnotary.validating=$"+"{LP_UNSET_GUIDED_NOTARY}\n");
        var evidence=new ConfigAnalyzer().analyze(config);assertEquals("CONFIGURED",evidence.safeSettings().get("schemaResolution"));assertTrue(ConfigAnalyzer.canPrepareTvuSchema(evidence,"4.12.11"));
    }
    @Test void primaryIsUsedAndExplicitUnknownSelectionIsRejected()throws Exception{
        Path config=root.resolve("node.conf");Files.writeString(config,"database.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=ExampleSchema,shared\"\n");
        var evidence=new ConfigAnalyzer().analyze(config);assertEquals("ExampleSchema",ConfigAnalyzer.selectTvuSchema(evidence,null));
        assertThrows(java.io.IOException.class,()->ConfigAnalyzer.selectTvuSchema(evidence,"shared"));assertThrows(java.io.IOException.class,()->ConfigAnalyzer.selectTvuSchema(evidence,"UndiscoveredSchema"));
    }
    @Test void noTvuCanPrepareSchemaWithoutCountingItAsABlocker()throws Exception{
        var fixture=ProductAcceptanceFixture.create(root,false,true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,false));
        assertEquals("READY FOR TVU",a.status());assertFalse(a.findings().stream().anyMatch(f->f.id().equals("LP-DB-001")));
        assertEquals("AUTO_CONFIGURABLE",ProductView.schemaSetupStatus(a));assertTrue(ProductView.result(a).contains("automatically"));
    }
    @Test void importedResultsNeedActualLoadedProofEvenWithQuotedNodeConfiguration()throws Exception{
        var fixture=ProductAcceptanceFixture.create(root,false,true);
        Path config=fixture.node().resolve("node.conf");Files.writeString(config,Files.readString(config).replace("database.schema=ExampleMixedCaseIssuer","database.schema=\"\\\"ExampleMixedCaseIssuer\\\"\""));
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,true));
        assertEquals("BLOCKED",a.status());assertTrue(a.findings().stream().anyMatch(f->f.id().equals("LP-DB-001")&&f.severity().equals("BLOCKED")));
    }
    @Test void importedActualLoadedProofAndSuccessCanEstablishReadiness()throws Exception{
        var fixture=ProductAcceptanceFixture.create(root,false,true);Files.writeString(fixture.log(),loaded("ExampleMixedCaseIssuer"),StandardOpenOption.APPEND);
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,true));assertEquals("READY TO UPGRADE",a.status());assertEquals("HANDLED",ProductView.schemaSetupStatus(a));
    }
    @Test void schemaValidationFailureOverridesMatchingLoadedProof()throws Exception{
        var fixture=ProductAcceptanceFixture.create(root,false,true);Files.writeString(fixture.log(),loaded("ExampleMixedCaseIssuer")+"org.hibernate.tool.schema.spi.SchemaManagementException: Schema-validation: missing table [ExampleMixedCaseIssuer.vault_states]\n",StandardOpenOption.APPEND);
        var a=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,true));assertEquals("BLOCKED",a.status());assertEquals("FAILED",ProductView.schemaSetupStatus(a));
        assertFalse(((TvuSchemaEvidence.Proof)a.evidence().get("tvu-schema-execution")).handled());
    }
    @Test void explicitGuidedCandidateBindsRunProofWithoutErasingOriginalAmbiguity()throws Exception{
        var fixture=ProductAcceptanceFixture.create(root,false,true);
        Files.writeString(fixture.node().resolve("node.conf"),"database.schema=FirstSchema\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=SecondSchema\"\n");
        Files.writeString(fixture.log(),loaded("SecondSchema"),StandardOpenOption.APPEND);
        var options=ProductAcceptanceFixture.options(fixture,true);var base=new AssessmentService().assess(options);
        var selected=AssessmentService.withGuidedSchemaProof(options,base,"SecondSchema");
        assertEquals("HANDLED",ProductView.schemaSetupStatus(selected));assertEquals("UNKNOWN",selected.status());
        assertTrue(selected.findings().stream().anyMatch(f->f.id().equals("LP-DB-002")));
        assertFalse(selected.findings().stream().anyMatch(f->f.id().equals("LP-DB-001")));
        assertThrows(java.io.IOException.class,()->AssessmentService.withGuidedSchemaProof(options,base,"UndiscoveredSchema"));
        var wrong=AssessmentService.withGuidedSchemaProof(options,base,"FirstSchema");assertEquals("BLOCKED",wrong.status());
        assertTrue(wrong.findings().stream().anyMatch(f->f.id().equals("LP-DB-004")));
    }
}
