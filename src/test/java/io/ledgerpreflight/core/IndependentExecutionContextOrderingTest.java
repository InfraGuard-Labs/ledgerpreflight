package io.ledgerpreflight.core;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class IndependentExecutionContextOrderingTest {
    @TempDir Path temp;
    private ClasspathEvidence.Ordering bind(String text,String... labels)throws Exception{
        Path file=Files.writeString(temp.resolve("verifier-command.txt"),text);
        return ClasspathEvidence.bind(file,List.of(labels));
    }
    @Test void exactExtractedVerifierAndShimPathsBindWithoutFlatteningNodeCapsule()throws Exception{
        var result=bind("java -cp /validation/tools/verifier.jar:/validation/legacy-jars/shim.jar example.Verify", "target.jar", "target.jar!/tools/verifier.jar", "legacy-jars/shim.jar");
        assertEquals(List.of("target.jar!/tools/verifier.jar","legacy-jars/shim.jar"),result.components());
    }
    @Test void ambiguousNestedBasenameCannotProveOrder()throws Exception{
        var result=bind("java -cp verifier.jar:shim.jar example.Verify","one.jar!/tools/verifier.jar","two.jar!/tools/verifier.jar","shim.jar");
        assertTrue(result.components().isEmpty());
    }
    @Test void repeatedResolvedComponentCannotProveOrder()throws Exception{
        var result=bind("java -cp /first/verifier.jar:/second/verifier.jar:shim.jar example.Verify","verifier.jar","shim.jar");
        assertTrue(result.components().isEmpty());
    }
    @Test void wildcardDoesNotResolveToInventedComponentOrder()throws Exception{
        assertTrue(bind("java -cp '/validation/*:shim.jar' example.Verify","verifier.jar","shim.jar").components().isEmpty());
    }
    @Test void emptyClasspathElementDoesNotSilentlyDisappear()throws Exception{
        assertTrue(bind("java -cp verifier.jar::shim.jar example.Verify","verifier.jar","shim.jar").components().isEmpty());
    }
    @Test void traversalAliasDoesNotBindToSuppliedArtifact()throws Exception{
        assertTrue(bind("java -cp ../verifier.jar:shim.jar example.Verify","verifier.jar","shim.jar").components().isEmpty());
    }
    @Test void conflictingClassLoadOriginsRetainExplicitUnknown()throws Exception{
        var result=bind("example.runtime.Api source: file:/validation/verifier.jar\nexample.runtime.Api source: file:/validation/shim.jar\n", "verifier.jar","shim.jar");
        assertTrue(result.components().isEmpty());assertEquals("",result.selectedClassSources().get("example/runtime/Api"));
    }
    @Test void multipleCommandsNeverBecomeOneOrdering()throws Exception{
        var result=bind("java -cp verifier.jar:shim.jar example.Verify\njava -cp shim.jar:verifier.jar example.Verify\n", "verifier.jar","shim.jar");
        assertTrue(result.components().isEmpty());
    }
    @Test void multipleCommandsCannotSupplyPositiveClassLoadSelection()throws Exception{
        var result=bind("java -cp verifier.jar:shim.jar example.Verify\nexample.runtime.Api source: file:/validation/shim.jar\njava -cp shim.jar:verifier.jar example.Verify\n", "verifier.jar","shim.jar");
        assertTrue(result.components().isEmpty());assertEquals("",result.selectedClassSources().get("example/runtime/Api"),"The supplying launch context is ambiguous across multiple commands");
    }
    @Test void unresolvedClassLoadSourceIsRetainedAsUnknown()throws Exception{
        var result=bind("example.runtime.Api source: file:/unavailable/missing.jar\n", "verifier.jar");
        assertEquals("",result.selectedClassSources().get("example/runtime/Api"));
    }
}
