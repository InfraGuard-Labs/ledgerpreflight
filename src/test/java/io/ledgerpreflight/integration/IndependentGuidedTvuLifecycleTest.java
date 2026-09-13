package io.ledgerpreflight.integration;

import io.ledgerpreflight.cli.GuidedTvuExecution;
import io.ledgerpreflight.core.AssessmentService;
import java.io.*;
import java.net.URLClassLoader;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Cancellation or a dead validator parent must not orphan the real synthetic verifier tree. */
class IndependentGuidedTvuLifecycleTest {
    @TempDir Path root;
    private static GuidedTvuExecution.Plan plan(GuidedTvuFixtureFactory.Fixture f)throws Exception {
        return GuidedTvuExecution.inspect(f.options(),new AssessmentService().assess(f.options()),null,null,f.reports());
    }
    private static List<Long> pids(Path control)throws IOException {
        List<Long> result=new ArrayList<>();for(String name:List.of("started.pid","child.pid","grandchild.pid")){Path path=control.resolve(name);if(Files.exists(path))result.add(Long.parseLong(Files.readString(path).strip()));}return result;
    }
    private static boolean active(long pid){return ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);}
    private static void noOrphans(Path control)throws Exception {
        List<Long> ids=pids(control);long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(6);while(ids.stream().anyMatch(IndependentGuidedTvuLifecycleTest::active)&&System.nanoTime()<end)Thread.sleep(30);
        assertTrue(ids.stream().noneMatch(IndependentGuidedTvuLifecycleTest::active),"Synthetic process IDs still alive: "+ids.stream().filter(IndependentGuidedTvuLifecycleTest::active).toList());
    }
    private static void emergencyCleanup(Path control)throws IOException {for(long pid:pids(control))ProcessHandle.of(pid).ifPresent(p->{p.descendants().forEach(ProcessHandle::destroyForcibly);p.destroyForcibly();});}
    @Test void explicitCancellationStopsParentChildGrandchildAndRemovesPrivateWorkspace()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"cancel",false);var plan=plan(f);
        try{
            var outcome=GuidedTvuExecution.run(plan,true,30,p->{},()->Files.exists(f.control().resolve("grandchild.pid")));
            assertTrue(outcome.cancelled());assertEquals(3,pids(f.control()).size());noOrphans(f.control());assertFalse(Files.exists(plan.workspace()));assertFalse(outcome.evidencePaths().isEmpty());
        }finally{emergencyCleanup(f.control());}
    }
    @Test void normalParentCompletionStillReapsTheSyntheticVerifierDescendants()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"orphan",false);var plan=plan(f);
        try{var outcome=GuidedTvuExecution.run(plan,true,30,p->{},()->false);assertEquals(0,outcome.exitCode());assertFalse(outcome.cancelled());assertEquals(3,pids(f.control()).size());noOrphans(f.control());assertFalse(Files.exists(plan.workspace()));}
        finally{emergencyCleanup(f.control());}
    }
    @Test void timeLimitCleansEveryObservedDescendantAndSensitiveFiles()throws Exception {
        var f=GuidedTvuFixtureFactory.create(root,"cancel",false);var plan=plan(f);
        try{var outcome=GuidedTvuExecution.run(plan,true,3,p->{},()->false);assertNotEquals("",outcome.failureKind());noOrphans(f.control());assertFalse(Files.exists(plan.workspace()));}
        finally{emergencyCleanup(f.control());}
    }
    @Test void sigtermOfLedgerPreflightCleansProcessGroupAndTemporaryConfiguration()throws Exception {signal("TERM");}
    @Test void sigintOfLedgerPreflightCleansProcessGroupAndTemporaryConfiguration()throws Exception {signal("INT");}
    private void signal(String name)throws Exception {
        Path control=root.resolve("process-observations"),console=root.resolve("harness-console.txt");
        Path hostBin=root.resolve("synthetic-host-java8/bin");Files.createDirectories(hostBin);Path hostJava=hostBin.resolve("java");Files.writeString(hostJava,"#!/bin/sh\nprintf 'java version \"1.8.0-synthetic\"\\n' >&2\n");Files.setPosixFilePermissions(hostJava,java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        ProcessBuilder launch=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-Xmx256m","-cp",testClasspath(),GuidedTvuSignalHarness.class.getName(),root.toString()).redirectErrorStream(true).redirectOutput(console.toFile());
        launch.environment().put("JAVA_HOME",hostBin.getParent().toString());launch.environment().put("PATH",hostBin+java.io.File.pathSeparator+Objects.toString(System.getenv("PATH"),""));Process parent=launch.start();
        try{
            long deadline=System.nanoTime()+Duration.ofSeconds(30).toNanos();while(!Files.exists(control.resolve("grandchild.pid"))&&parent.isAlive()&&System.nanoTime()<deadline)Thread.sleep(40);
            assertTrue(Files.exists(control.resolve("grandchild.pid")),Files.readString(console));
            Properties observations=new Properties();try(InputStream in=Files.newInputStream(control.resolve("observed.properties"))){observations.load(in);}Path workspace=Path.of(observations.getProperty("base"));
            assertEquals(observations.getProperty("javaHome"),observations.getProperty("environmentJavaHome"));assertTrue(observations.getProperty("bareJavaVersion").contains("17."),observations.getProperty("bareJavaVersion"));
            var node=GuidedTvuFixtureFactory.hashes(root.resolve("node"));var kit=GuidedTvuFixtureFactory.hashes(root.resolve("kit"));
            Process kill=new ProcessBuilder("/bin/kill","-"+name,Long.toString(parent.pid())).start();assertTrue(kill.waitFor(3,TimeUnit.SECONDS));assertEquals(0,kill.exitValue());assertTrue(parent.waitFor(12,TimeUnit.SECONDS),"Parent did not exit after SIG"+name);
            noOrphans(control);assertFalse(Files.exists(workspace),"Sensitive temporary workspace survived SIG"+name);
            assertEquals(node,GuidedTvuFixtureFactory.hashes(root.resolve("node")));assertEquals(kit,GuidedTvuFixtureFactory.hashes(root.resolve("kit")));
        }finally{parent.descendants().forEach(ProcessHandle::destroyForcibly);parent.destroyForcibly();emergencyCleanup(control);}
    }
    private static String testClasspath()throws Exception {
        Set<String> paths=new LinkedHashSet<>(List.of(System.getProperty("java.class.path").split(java.io.File.pathSeparator)));
        for(ClassLoader loader=IndependentGuidedTvuLifecycleTest.class.getClassLoader();loader!=null;loader=loader.getParent())if(loader instanceof URLClassLoader urls)for(var url:urls.getURLs())if(url.getProtocol().equals("file"))paths.add(Path.of(url.toURI()).toString());
        return String.join(java.io.File.pathSeparator,paths);
    }
}
