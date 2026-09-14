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
    @Test void unprovenMixedCaseSchemaRequiresReviewWithoutAutomaticPreparation()throws Exception{
        var fixture=ProductAcceptanceFixture.create(root,false,true);var a=new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,false));
        assertEquals("BLOCKED",a.status());assertTrue(a.findings().stream().anyMatch(f->f.id().equals("LP-DB-001")&&f.severity().equals("BLOCKED")));
        assertEquals("REQUIRED_UNPROVEN",ProductView.schemaSetupStatus(a));assertFalse(ProductView.result(a).contains("automatically"));
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
}
