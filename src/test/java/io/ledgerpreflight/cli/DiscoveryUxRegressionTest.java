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
 @Test void cursorUsesAsciiWhenUnicodeIsNotSupported(){assertEquals(">",SessionTerminal.cursor(Map.of("LANG","C","TERM","xterm"),StandardCharsets.US_ASCII));assertEquals(">",SessionTerminal.cursor(Map.of("LANG","en_US.UTF-8","TERM","linux"),StandardCharsets.UTF_8));assertEquals(">",SessionTerminal.cursor(Map.of("LANG","en_US.UTF-8","TERM","xterm-256color"),StandardCharsets.UTF_8));}
 @Test void discoverySummaryAndDrilldownUseObservedMetadata()throws Exception {
  var f=RealDiscoveryRegressionTest.fixture(root);StringWriter output=new StringWriter();var terminal=new SessionTerminal(new StringReader("2\n"),new PrintWriter(output),false,100);
  assertNull(DiscoverySession.prepare(f.options(false),terminal));String text=output.toString();
  for(String expected:List.of("ExampleIssuer","4.11.6","4.12.11","ExampleMixedCaseIssuer","2 current → 2 target","Platform 13","Platform 140","TVU          Found","1. Continue","2. Exit"))assertTrue(text.contains(expected),expected+"\n"+text);
  for(String hidden:List.of("djvm/link","confidence","Role","Other JARs","Bytecode","Review discovered"))assertFalse(text.contains(hidden),hidden);
 }
 @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans={false,true})
 void ambiguousArtifactsRequireSelection(boolean tvu)throws Exception {
  var f=RealDiscoveryRegressionTest.fixture(root);Files.copy(f.kit().resolve(tvu?"renamed-validator.jar":"renamed-corda-target.jar"),f.kit().resolve("second.jar"));StringWriter output=new StringWriter();
  var selected=DiscoverySession.prepare(f.options(false),new SessionTerminal(new StringReader("2\n1\n"),new PrintWriter(output),false,100));assertNotNull(selected);assertEquals("second.jar",(tvu?selected.tvuJar():selected.targetCorda()).getFileName().toString());assertTrue(output.toString().contains(tvu?"Select target TVU artifact":"Select target Corda runtime"));
 }
 @Test void coverageConcernsExplainTheirImpactWithoutAnUnexplainedCounter(){
  var issues=java.util.stream.IntStream.range(0,1015).mapToObj(i->new io.ledgerpreflight.bytecode.BytecodeScanner.ScanIssue("LP-INPUT-001","artifact-"+i,"Malformed class")).toList();var scan=new io.ledgerpreflight.bytecode.BytecodeScanner.ScanResult(List.of(),issues);
  String text=DiscoverySession.coverage(scan,scan);assertTrue(text.contains("Bytecode scan incomplete"));assertTrue(text.contains("Readiness requires reviewing"));assertFalse(text.contains("1015"));
 }
}
