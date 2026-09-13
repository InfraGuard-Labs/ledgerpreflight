package io.ledgerpreflight.core;
import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class CoreBoundaryTest {
    @TempDir Path temp;
    private JarInventory jar(String name){return new JarInventory(name,"hash",Map.of(),Map.of("net/corda/core/internal/Thing",new ClassInfo("net/corda/core/internal/Thing","java/lang/Object",List.of(),1,61,List.of(),List.of())),List.of());}
    @Test void commandAndClassLoadingTogetherConfirmSelection()throws Exception {
        Path f=Files.writeString(temp.resolve("evidence.txt"),"java -cp corda.jar:legacy-jars/shim.jar net.corda.verifier.Main\n[0.1s][info][class,load] net.corda.core.internal.Thing source: file:/kit/corda.jar\n");
        var r=ClasspathEvidence.read(f,List.of(jar("corda.jar")),List.of(jar("legacy-jars/shim.jar")));
        assertTrue(r.runtimePrecedenceProven());assertEquals("CONFIRMED",r.confidence());assertEquals(1,r.selectedClassSources().size());
    }
    @Test void contradictoryClassLoadingCannotConfirmShadowing()throws Exception {
        Path f=Files.writeString(temp.resolve("evidence.txt"),"java -cp corda.jar:legacy-jars/shim.jar Main\nnet.corda.core.internal.Thing source: file:/kit/legacy-jars/shim.jar\n");
        assertFalse(ClasspathEvidence.read(f,List.of(jar("corda.jar")),List.of(jar("legacy-jars/shim.jar"))).runtimePrecedenceProven());
    }
    @Test void quotedWindowsClasspathWithSpacesIsHandled()throws Exception {
        Path f=Files.writeString(temp.resolve("evidence.txt"),"java -cp \"C:\\kit with spaces\\corda.jar;C:\\kit with spaces\\legacy-jars\\shim.jar\" Main");
        assertTrue(ClasspathEvidence.read(f,List.of(jar("corda.jar")),List.of(jar("legacy-jars/shim.jar"))).runtimePrecedenceProven());
    }
    @Test void readinessExitCodesCannotBypassTvu(){
        assertEquals(0,new Assessment("1","0.1.0","READY TO UPGRADE","4.11","4.12",List.of(),Map.of()).exitCode());
        assertEquals(1,new Assessment("1","0.1.0","READY FOR TVU","4.11","4.12",List.of(),Map.of()).exitCode());
        assertEquals(4,new Assessment("1","0.1.0","UNKNOWN","4.11","4.12",List.of(),Map.of()).exitCode());
    }
    @Test void successfulTvuGateRemainsSeparateFromStaticBlockers(){
        var tvu=new io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence(1L,1L,1L,0L,0,Map.of(),false,true,true,List.of());
        var blocker=Finding.of("LP-API-001","missing","BLOCKED","API_COMPATIBILITY","HIGH","RUNTIME_DISCOVERY","test",List.of(),"risk","fix");
        var a=new Assessment("1","0.1.0","BLOCKED","4.11","4.12",List.of(blocker),Map.of("tvu-summary",tvu));
        assertEquals("PASS",((Map<?,?>)a.gates()).get("tvu"));assertEquals("REVIEW_REQUIRED",((Map<?,?>)a.gates()).get("static"));
    }
    @Test void successfulCountersCannotOverrideIncompleteGuidedExecution(){
        var tvu=new io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence(650L,650L,650L,0L,0,Map.of(),false,true,true,List.of());
        Map<String,Object> complete=new HashMap<>(Map.of("failureKind","NONE","exitCode",0,"cancelled",false,"workspaceCleaned",true));
        assertEquals("PASS",((Map<?,?>)new Assessment("1","0.1.0","READY TO UPGRADE","4.11","4.12",List.of(),Map.of("tvu-summary",tvu,"tvu-run",complete)).gates()).get("tvu"));
        for(var changed:List.of(Map.entry("failureKind",(Object)"EXECUTION_FAILURE"),Map.entry("exitCode",(Object)1),Map.entry("cancelled",(Object)true),Map.entry("workspaceCleaned",(Object)false),Map.entry("manifestWriteFailure",(Object)true))){
            Map<String,Object> run=new HashMap<>(complete);run.put(changed.getKey(),changed.getValue());
            assertEquals("REQUIRED_OR_UNRESOLVED",((Map<?,?>)new Assessment("1","0.1.0","UNKNOWN","4.11","4.12",List.of(),Map.of("tvu-summary",tvu,"tvu-run",run)).gates()).get("tvu"),changed.getKey());
        }
    }
    @Test void prereleaseQualifierIsPreserved(){
        var j=new JarInventory("corda.jar","hash",Map.of("Corda-Release-Version","4.12.11-RC1"),Map.of(),List.of());assertEquals("4.12.11-RC1",Discovery.version(j));
    }
}
