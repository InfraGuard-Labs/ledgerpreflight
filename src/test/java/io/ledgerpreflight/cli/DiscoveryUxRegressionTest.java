package io.ledgerpreflight.cli;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import org.junit.jupiter.api.io.TempDir;
import io.ledgerpreflight.integration.RealDiscoveryRegressionTest;
class DiscoveryUxRegressionTest {
 @TempDir Path root;
 @Test void skippedPathsAreSummarized(){var paths=java.util.stream.IntStream.range(0,47).mapToObj(i->"Symbolic link outside supplied root skipped: djvm/link-"+i).toList();String text=DiscoverySession.concerns(paths);assertTrue(text.contains("External symlinks skipped: 47"));assertFalse(text.contains("djvm/link"));}
 @Test void cursorUsesAsciiWhenUnicodeIsNotSupported(){assertEquals(">",SessionTerminal.cursor(Map.of("LANG","C","TERM","xterm"),StandardCharsets.US_ASCII));assertEquals(">",SessionTerminal.cursor(Map.of("LANG","en_US.UTF-8","TERM","linux"),StandardCharsets.UTF_8));assertEquals("❯",SessionTerminal.cursor(Map.of("LANG","en_US.UTF-8","TERM","xterm-256color"),StandardCharsets.UTF_8));}
 @Test void discoverySummaryAndDrilldownUseObservedMetadata()throws Exception {
  var f=RealDiscoveryRegressionTest.fixture(root);StringWriter output=new StringWriter();var terminal=new SessionTerminal(new StringReader("2\n2\n1\n3\n"),new PrintWriter(output),false,100);
  assertNull(DiscoverySession.prepare(f.options(false),terminal));String text=output.toString();
  for(String expected:List.of("ExampleIssuer","4.11.6","4.12.11","ExampleMixedCaseIssuer","3 current → 2 target CorDapp JARs","platform 13","platform 140","External symlinks skipped: 47","View skipped paths","Discovery confidence: HIGH"))assertTrue(text.contains(expected),expected+"\n"+text);
  assertTrue(text.contains("djvm/link-0"));
 }
}
