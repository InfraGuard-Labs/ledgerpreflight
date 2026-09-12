package io.ledgerpreflight.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.ledgerpreflight.cli.Main;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import io.ledgerpreflight.rules.RuleEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

class BoundarySecurityTest {
    @TempDir Path temp;
    @Test void jsonRedactsSecretKeysAndNestedObjects() throws Exception {
        String json=Reports.json(Map.of("password",Map.of("value","FakePassword"),"api_key","FakeApi","public","safe"));
        var parsed=new ObjectMapper().readTree(json);
        assertEquals("[REDACTED]",parsed.get("password").asText()); assertFalse(json.contains("Fake")); assertEquals("safe",parsed.get("public").asText());
    }
    @Test void htmlEscapesUntrustedEvidenceAndHasNoExecutableScript() {
        Finding finding=Finding.of("USR-XSS","<script>alert(1)</script>","WARNING","TEST","HIGH","USER_RULE","test",List.of("<img src=x onerror=alert(1)>","password=FakePassword"),"test","test");
        Assessment assessment=new Assessment("1","0.1.0","WARNING","4.11","4.12",List.of(finding),Map.of());
        String html=Reports.html(assessment);
        assertFalse(html.contains("<script>")); assertFalse(html.contains("<img")); assertFalse(html.contains("FakePassword"));
        assertTrue(html.contains("&lt;script&gt;")); assertTrue(html.contains("Content-Security-Policy"));
    }
    @Test void reportTraversalAndSymlinkCannotOverwriteOutsideReportRoot() throws Exception {
        Path outside=Files.writeString(temp.resolve("outside.txt"),"unchanged"); Path out=Files.createDirectory(temp.resolve("reports"));
        assertThrows(IOException.class,()->Reports.write(out,Map.of("../outside.txt","changed")));
        Files.createSymbolicLink(out.resolve("linked.txt"),outside);
        assertThrows(IOException.class,()->Reports.write(out,Map.of("linked.txt","changed")));
        assertEquals("unchanged",Files.readString(outside));
    }
    @Test void assessmentOutputWithinNodeRejectedBeforeWriting() throws Exception {
        Path node=Files.createDirectory(temp.resolve("node")),kit=Files.createDirectory(temp.resolve("kit"));
        var command=Main.command(); command.setOut(new PrintWriter(new StringWriter())); command.setErr(new PrintWriter(new StringWriter()));
        assertEquals(3,command.execute("assess","--node",node.toString(),"--upgrade-kit",kit.toString(),"--output",node.resolve("reports").toString()));
        assertFalse(Files.exists(node.resolve("reports")));
    }
    @Test void unknownEvidenceAndMissingTvuNeverPassReadiness() {
        var unknown=Finding.of("USR-UNKNOWN","Unknown","UNKNOWN","TEST","LOW","USER_RULE","test",List.of("unknown"),"unknown","inspect");
        assertEquals("UNKNOWN",Assessment.readiness(List.of(unknown),true,true));
        assertEquals("READY FOR TVU",Assessment.readiness(List.of(),false,false));
        assertEquals("UNKNOWN",Assessment.readiness(List.of(),false,true));
    }
    @Test void malformedRulepackDoesNotEchoPrivateValue() throws Exception {
        Path rules=Files.writeString(temp.resolve("rules.json"),"{\"schemaVersion\": \"1\", \"version\": \"fakeSecretValue\", BROKEN}");
        IOException error=assertThrows(IOException.class,()->new RuleEngine().load(rules));
        assertFalse(error.getMessage().contains("fakeSecretValue"));
    }
    @Test void rulePackSymlinkAncestorRejected() throws Exception {
        Path actual=Files.createDirectory(temp.resolve("actual")); Files.writeString(actual.resolve("rules.json"),"{\"schemaVersion\":\"1\",\"version\":\"1\",\"rules\":[]}");
        Path link=Files.createSymbolicLink(temp.resolve("linked"),actual);
        assertThrows(IOException.class,()->new RuleEngine().load(link.resolve("rules.json")));
    }
    @Test void tvuDirectoryCollectsAllObservedStdoutRoots() throws Exception {
        Path logs=Files.createDirectory(temp.resolve("logs"));
        Files.writeString(logs.resolve("tvu.log"),"java.lang.NoSuchMethodError: missingA\njava.lang.NoClassDefFoundError: missingB");
        var evidence=new TvuAnalyzer().analyze(List.of(logs));
        assertEquals(2,evidence.rootCauses().size()); assertEquals(0,evidence.detailedRecords()); assertFalse(evidence.completeSuccess());
    }
    @Test void unknownErrorZipCannotBeMaskedBySuccessSummary() throws Exception {
        Path log=Files.writeString(temp.resolve("success.log"),"expected: 1\nprocessed: 1\nsucceeded: 1\nfailed: 0");
        Path errors=temp.resolve("errors.zip");
        try(ZipOutputStream zip=new ZipOutputStream(Files.newOutputStream(errors))) { zip.putNextEntry(new ZipEntry("error.txt"));zip.write("unrecognized failure format".getBytes(java.nio.charset.StandardCharsets.UTF_8));zip.closeEntry(); }
        assertFalse(new TvuAnalyzer().analyze(List.of(log,errors)).completeSuccess());
    }
    @Test void tvuDirectorySymlinkEscapeRejected() throws Exception {
        Path outside=Files.writeString(temp.resolve("outside.log"),"private fixture"); Path logs=Files.createDirectory(temp.resolve("logs"));
        Files.createSymbolicLink(logs.resolve("outside.log"),outside);
        assertThrows(IOException.class,()->new TvuAnalyzer().analyze(List.of(logs)));
    }
}
