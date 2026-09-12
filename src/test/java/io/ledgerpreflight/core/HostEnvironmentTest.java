package io.ledgerpreflight.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class HostEnvironmentTest {
    @TempDir Path temp;
    private HostEnvironment inspect(Path evidence,Map<String,String> environment,String release)throws IOException{return HostEnvironment.inspect(evidence,environment,release,"Linux","amd64","17.0.12");}
    private Path evidence(String json)throws IOException{Path path=temp.resolve("host.json");Files.writeString(path,json);return path;}
    @Test void java17AnalyzerDoesNotImplyJava17OnCurrentNodeOrPlannedTarget()throws IOException {
        var result=inspect(null,Map.of(),"PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n");assertEquals("17.0.12",result.analyzerJava());assertEquals("UNKNOWN",result.currentJava());assertEquals("UNKNOWN",result.sourceHostOs());assertEquals("UNVERIFIED",result.targetJavaReadiness());assertEquals("Ubuntu 22.04.5 LTS",result.executionOs());
    }
    @Test void bundledAnalyzerPreservesDistinctAmbientJava8Evidence()throws IOException {
        var result=inspect(null,Map.of("LP_HOST_JAVA_VERSION","1.8.0_442"),"PRETTY_NAME=\"Ubuntu 18.04.6 LTS\"\n");assertEquals("1.8.0_442",result.currentJava());assertEquals("LAUNCHER_ENVIRONMENT",result.currentJavaSource());assertEquals("17.0.12",result.analyzerJava());assertEquals("UNVERIFIED",result.targetJavaReadiness());assertEquals("UNKNOWN",result.sourceHostOs());
    }
    @Test void containerOsIsNotSubstitutedForSourceHostOs()throws IOException {
        var result=inspect(evidence("{\"sourceHostOs\":\"Ubuntu 20.04.6 LTS\",\"currentJava\":\"1.8.0_442\",\"plannedTargetJava\":\"17.0.12\"}"),Map.of(),"PRETTY_NAME=\"Debian GNU/Linux 12\"\n");assertEquals("Debian GNU/Linux 12",result.executionOs());assertEquals("Ubuntu 20.04.6 LTS",result.sourceHostOs());assertEquals("USER_SUPPLIED_SOURCE_HOST",result.currentJavaSource());assertEquals("USER_REPORTED_COMPATIBLE",result.targetJavaReadiness());assertEquals("USER_SUPPLIED",result.confidence());
    }
    @Test void targetJava8EvidenceIsIncompatible()throws IOException {assertEquals("INCOMPATIBLE",inspect(evidence("{\"plannedTargetJava\":\"1.8.0_442\"}"),Map.of(),"").targetJavaReadiness());}
    @Test void targetJava21IsNotAcceptedAsSupportedJava17()throws IOException {assertEquals("INCOMPATIBLE",inspect(evidence("{\"plannedTargetJava\":\"21.0.2\"}"),Map.of(),"").targetJavaReadiness());}
    @Test void java17WithoutPatchRemainsUnverified()throws IOException {assertEquals("JAVA_17_REPORTED_PATCH_UNVERIFIED",inspect(evidence("{\"plannedTargetJava\":\"17\"}"),Map.of(),"").targetJavaReadiness());}
    @Test void java17BeforeDocumentedPatchIsIncompatible()throws IOException {assertEquals("INCOMPATIBLE",inspect(evidence("{\"plannedTargetJava\":\"17.0.8\"}"),Map.of(),"").targetJavaReadiness());}
    @Test void supportedMinimumJavaPatchIsAcceptedAsReportedOnly()throws IOException {assertEquals("USER_REPORTED_COMPATIBLE",inspect(evidence("{\"plannedTargetJava\":\"17.0.9+9\"}"),Map.of(),"").targetJavaReadiness());}
    @Test void earlyAccessBuildDoesNotEstablishTargetReadiness()throws IOException {assertEquals("UNVERIFIED",inspect(evidence("{\"plannedTargetJava\":\"17.0.12-ea\"}"),Map.of(),"").targetJavaReadiness());}
    @Test void unknownAndDuplicateFieldsAreRejected()throws IOException {
        assertThrows(IOException.class,()->inspect(evidence("{\"password\":\"synthetic\"}"),Map.of(),""));assertThrows(IOException.class,()->inspect(evidence("{\"currentJava\":\"8\",\"currentJava\":\"17\"}"),Map.of(),""));
    }
    @Test void malformedOrOversizedEvidenceIsRejected()throws IOException {
        assertThrows(IOException.class,()->inspect(evidence("{"),Map.of(),""));assertThrows(IOException.class,()->inspect(evidence(" ".repeat(20000)),Map.of(),""));assertThrows(IOException.class,()->inspect(evidence("{\"currentJava\":17}"),Map.of(),""));
    }
    @Test void fallbackOsDoesNotExecuteOsReleaseContents()throws IOException {
        var result=inspect(null,Map.of(),"PRETTY_NAME=\"$(synthetic-command)\"\n");assertEquals("$(synthetic-command)",result.executionOs());assertEquals("Linux",inspect(null,Map.of(),"").executionOs());
    }
    @Test void explicitEvidenceOverridesAmbientLauncherForSourceJava()throws IOException {
        var result=inspect(evidence("{\"currentJava\":\"1.8.0_442\"}"),Map.of("LP_HOST_JAVA_VERSION","17.0.12"),"");assertEquals("1.8.0_442",result.currentJava());assertEquals("USER_SUPPLIED_SOURCE_HOST",result.currentJavaSource());
    }
}
