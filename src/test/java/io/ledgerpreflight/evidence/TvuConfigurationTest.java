package io.ledgerpreflight.evidence;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class TvuConfigurationTest {
    @TempDir Path root;
    private Path config(String extra)throws IOException{return Files.writeString(root.resolve("node.conf"),"database.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/copy?currentSchema=ExampleSchema\"\n"+extra);}
    @Test void resolvedLocalIncludesAreCopiedPrivatelyWithoutChangingInputs()throws Exception {
        Files.writeString(root.resolve("database.conf"),"dataSource.password=\"SyntheticPrivateValue42\"\n");Path input=config("include \"database.conf\"\n");String before=Files.readString(input);var selected=TvuConfiguration.read(input);Path copy=root.resolve("execution.conf");selected.writePrivate(copy);
        assertEquals("rw-------",PosixFilePermissions.toString(Files.getPosixFilePermissions(copy)));assertTrue(Files.readString(copy).contains("SyntheticPrivateValue42"));assertFalse(Files.readString(copy).contains("include"));assertEquals(before,Files.readString(input));assertFalse(selected.redact("Unexpected diagnostic SyntheticPrivateValue42").contains("SyntheticPrivateValue42"));
    }
    @Test void unresolvedExecutionCredentialsFailBeforeAnyCopy()throws Exception {Path input=config("dataSource.password=${MISSING_PASSWORD_FOR_SYNTHETIC_TEST}\n");assertThrows(IOException.class,()->TvuConfiguration.read(input));assertFalse(Files.exists(root.resolve("execution.conf")));}
    @Test void multilineCredentialsAndUserAssignmentsAreRedacted()throws Exception {
        var selected=TvuConfiguration.read(config("dataSource.password=\"SyntheticLineOne\\nSyntheticLineTwo\"\n"));String redacted=selected.redact("SyntheticLineOne\nSyntheticLineTwo\nusername=ExampleDatabaseUser\n");assertFalse(redacted.contains("SyntheticLine"));assertFalse(redacted.contains("ExampleDatabaseUser"));
    }
    @Test void configurationChangesInvalidateTheApprovedSnapshot()throws Exception {Path input=config("dataSource.password=\"SyntheticSecretOne\"\n");var selected=TvuConfiguration.read(input);Files.writeString(input,Files.readString(input).replace("SyntheticSecretOne","SyntheticSecretTwo"));assertThrows(IOException.class,selected::verifyUnchanged);}
    @Test void sensitiveVerifierJvmArgumentsAreRejected()throws Exception {Path input=config("dataSource.password=\"SyntheticHiddenValue42\"\nexternalVerifier.jvmArgs=[\"-Dunrelated=SyntheticHiddenValue42\"]\n");assertThrows(IOException.class,()->TvuConfiguration.read(input));}
    @Test void exportedFingerprintExcludesPasswordAndRetainsSelectedDatabaseIdentity()throws Exception {
        Path input=config("dataSource.password=\"SyntheticSecretOne\"\n");var first=TvuConfiguration.read(input);
        Files.writeString(input,Files.readString(input).replace("SyntheticSecretOne","SyntheticSecretTwo"));var second=TvuConfiguration.read(input);
        assertNotEquals(first.fingerprint(),second.fingerprint());assertEquals(first.sanitizedFingerprint(),second.sanitizedFingerprint());assertNotEquals(first.fingerprint(),first.sanitizedFingerprint());
        Files.writeString(input,Files.readString(input).replace("database.example/copy","database.example/alternate_copy"));var alternate=TvuConfiguration.read(input);
        assertNotEquals(second.sanitizedFingerprint(),alternate.sanitizedFingerprint());assertEquals("jdbc:postgresql://database.example/alternate_copy",alternate.databaseTarget());assertTrue(alternate.sanitizedFingerprint().matches("[0-9a-f]{64}"));
    }
}
