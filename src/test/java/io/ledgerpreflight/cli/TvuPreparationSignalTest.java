package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.AssessmentService;
import io.ledgerpreflight.integration.GuidedTvuFixtureFactory;
import java.io.*;
import java.net.URLClassLoader;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class TvuPreparationSignalTest {
    @TempDir Path root;
    public static final class Harness {
        public static void main(String[] args)throws Exception {
            Path root=Path.of(args[0]),signal=root.resolve("signal-seen"),release=root.resolve("continue-preparation");
            var fixture=GuidedTvuFixtureFactory.create(root,"success",false);var plan=GuidedTvuExecution.inspect(fixture.options(),new AssessmentService().assess(fixture.options()),null,null,fixture.reports());
            Runtime.getRuntime().addShutdownHook(new Thread(()->{try{Files.writeString(signal,"Observed actual termination signal");}catch(IOException ignored){}}));
            GuidedTvuExecution.run(plan,true,30,p->{},()->{
                if(Files.exists(plan.workspace().resolve("node.conf")))try{
                    Files.writeString(root.resolve("prepared-workspace"),plan.workspace().toString());
                    while(!Files.exists(release))Thread.sleep(20);
                }catch(IOException e){throw new UncheckedIOException(e);}catch(InterruptedException e){Thread.currentThread().interrupt();}
                return false;
            });
        }
    }
    @Test void sigtermDuringPrivateConfigurationPreparationCleansWithoutLaunchingTvu()throws Exception {
        Path console=root.resolve("harness.log"),marker=root.resolve("prepared-workspace"),release=root.resolve("continue-preparation");
        Set<String> entries=new LinkedHashSet<>(List.of(System.getProperty("java.class.path").split(File.pathSeparator)));
        for(ClassLoader loader=getClass().getClassLoader();loader!=null;loader=loader.getParent())if(loader instanceof URLClassLoader urls)for(var url:urls.getURLs())if(url.getProtocol().equals("file"))entries.add(Path.of(url.toURI()).toString());
        Process process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-Xmx256m","-cp",String.join(File.pathSeparator,entries),Harness.class.getName(),root.toString()).redirectErrorStream(true).redirectOutput(console.toFile()).start();
        try {
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);while(!Files.exists(marker)&&process.isAlive()&&System.nanoTime()<deadline)Thread.sleep(20);
            assertTrue(Files.exists(marker),Files.readString(console));Path workspace=Path.of(Files.readString(marker));assertTrue(Files.exists(workspace.resolve("node.conf")));assertFalse(Files.exists(root.resolve("process-observations/started.pid")));
            Process signal=new ProcessBuilder("/bin/kill","-TERM",Long.toString(process.pid())).start();assertTrue(signal.waitFor(3,TimeUnit.SECONDS));assertEquals(0,signal.exitValue());
            deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(!Files.exists(root.resolve("signal-seen"))&&process.isAlive()&&System.nanoTime()<deadline)Thread.sleep(10);
            assertTrue(Files.exists(root.resolve("signal-seen")));Thread.sleep(100);Files.writeString(release,"Allow bounded preparation to observe cancellation");
            assertTrue(process.waitFor(10,TimeUnit.SECONDS));assertFalse(Files.exists(workspace));assertFalse(Files.exists(root.resolve("process-observations/started.pid")));
        }finally{Files.writeString(release,"Release test synchronization");process.descendants().forEach(ProcessHandle::destroyForcibly);process.destroyForcibly();}
    }
}
