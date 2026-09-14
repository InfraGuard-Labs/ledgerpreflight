package io.ledgerpreflight.evidence;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** An applied file is not proof that the selected TVU run loaded the intended schema. */
class IndependentImportedSchemaEvidenceTest {
    @TempDir Path root;
    private static final String LOADED="HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema=\"ExampleSchema\"}\n";
    private TvuSchemaEvidence.Proof proof(String text)throws Exception {Path log=root.resolve("validator.log");Files.writeString(log,text);return TvuSchemaEvidence.analyze(List.of(log),"ExampleSchema");}
    @Test void configurationAndWorkspaceCreationAloneCannotProveExecution()throws Exception {
        assertFalse(proof("hibernate.default_schema=\"ExampleSchema\"\nCreated hibernate.properties\nSchema configuration applied\n").handled());
    }
    @Test void actualExpectedQuotedLoadedPropertyProvesOnlyTheSuppliedSchema()throws Exception {
        var p=proof(LOADED);assertTrue(p.handled());assertFalse(p.mismatch());assertEquals("ExampleSchema",p.expectedSchema());
    }
    @Test void unquotedOrDifferentLoadedSchemaRemainsUnresolved()throws Exception {
        assertFalse(proof(LOADED.replace("\"ExampleSchema\"","ExampleSchema")).handled());assertFalse(proof(LOADED.replace("ExampleSchema","OtherSchema")).handled());
    }
    @Test void conflictingRunsCannotBeMergedIntoHandledEvidence()throws Exception {
        var p=proof(LOADED+LOADED.replace("ExampleSchema","OtherSchema"));assertFalse(p.handled());assertTrue(p.mismatch());
    }
    @Test void schemaValidationFailureOverridesAnEarlierCorrectStartupProperty()throws Exception {
        assertFalse(proof(LOADED+"org.hibernate.tool.schema.spi.SchemaManagementException: Schema-validation: missing table [OtherSchema.vault_states]\n").handled());
    }
    @Test void corruptArchiveCrcCannotCertifyLoadedSchema()throws Exception {
        Path zip=root.resolve("errors.zip");byte[] bytes=archive("validator.log",LOADED);boolean changed=false;
        for(int i=0;i+46<=bytes.length;i++)if(bytes[i]==0x50&&bytes[i+1]==0x4b&&bytes[i+2]==0x01&&bytes[i+3]==0x02){bytes[i+16]^=0x20;changed=true;break;}
        assertTrue(changed);Files.write(zip,bytes);assertThrows(IOException.class,()->TvuSchemaEvidence.analyze(List.of(zip),"ExampleSchema"));
    }
    @Test void archiveTraversalCannotBecomeSchemaProof()throws Exception {
        Path zip=root.resolve("errors.zip");Files.write(zip,archive("../validator.log",LOADED));assertThrows(IOException.class,()->TvuSchemaEvidence.analyze(List.of(zip),"ExampleSchema"));assertFalse(Files.exists(root.getParent().resolve("validator.log")));
    }
    @Test void symlinkedSchemaEvidenceIsRejectedWithoutFollowingIt()throws Exception {
        Path outside=root.resolve("source.log");Files.writeString(outside,LOADED);Path link=root.resolve("validator.log");Files.createSymbolicLink(link,outside);assertThrows(IOException.class,()->TvuSchemaEvidence.analyze(List.of(link),"ExampleSchema"));
    }
    private static byte[] archive(String name,String text)throws IOException {var bytes=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(bytes)){zip.putNextEntry(new ZipEntry(name));zip.write(text.getBytes(StandardCharsets.UTF_8));zip.closeEntry();}return bytes.toByteArray();}
}
