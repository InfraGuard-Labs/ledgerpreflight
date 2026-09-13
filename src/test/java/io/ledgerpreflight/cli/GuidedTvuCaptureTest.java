package io.ledgerpreflight.cli;

import io.ledgerpreflight.evidence.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class GuidedTvuCaptureTest {
    @TempDir Path root;
    private GuidedTvuCapture capture()throws Exception {Path conf=Files.writeString(root.resolve("node.conf"),"database.schema=ExampleSchema\ndataSource.url=\"jdbc:postgresql://database.example/copy?currentSchema=ExampleSchema\"\ndataSource.password=\"SyntheticCaptureSecret42\"\n");return new GuidedTvuCapture(root,TvuConfiguration.read(conf));}
    @Test void finalMonotonicSummaryIsDerivedWithoutVerifierRetryNoise()throws Exception {
        var capture=capture();String text="total: 650\nprocessed: 72\nfailed: 18\nExternal verifier process started\njava.lang.RuntimeException: retrying transient verifier connection\nprocessed: 650\npassed: 449\nfailed: 201\n";
        capture.read(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));capture.close();Path analysis=capture.analysis("TRANSACTION_VERIFICATION_FAILURE");var result=new TvuAnalyzer().analyze(List.of(analysis));assertEquals(650,result.processed());assertEquals(449,result.succeeded());assertEquals(201,result.failed());assertTrue(result.consistent());assertFalse(Files.readString(analysis).contains("retrying"));assertTrue(Files.readString(root.resolve("tvu.log")).contains("retrying"));
    }
    @Test void counterResetCannotBecomeSuccessfulValidation()throws Exception {var capture=capture();capture.read(new ByteArrayInputStream("total: 650\nprocessed: 600\nprocessed: 10\nprocessed: 650\npassed: 650\nfailed: 0\n".getBytes(StandardCharsets.UTF_8)));capture.close();assertFalse(new TvuAnalyzer().analyze(List.of(capture.analysis("EXECUTION_FAILURE"))).completeSuccess());}
    @Test void longOutputLineFailsWithinCaptureBoundAndDoesNotExposePassword()throws Exception {var capture=capture();byte[] input=("diagnostic SyntheticCaptureSecret42\n"+"a".repeat(65537)).getBytes(StandardCharsets.UTF_8);assertThrows(IOException.class,()->capture.read(new ByteArrayInputStream(input)));capture.close();assertFalse(Files.readString(root.resolve("tvu.log")).contains("SyntheticCaptureSecret42"));}
    @Test void privateKeyBlocksAreExcludedAcrossOutputLines()throws Exception {var capture=capture();capture.read(new ByteArrayInputStream("-----BEGIN PRIVATE KEY-----\nSyntheticPrivateKeyMaterial42\n-----END PRIVATE KEY-----\n".getBytes(StandardCharsets.UTF_8)));capture.close();assertFalse(Files.readString(root.resolve("tvu.log")).contains("SyntheticPrivateKeyMaterial42"));}
}
