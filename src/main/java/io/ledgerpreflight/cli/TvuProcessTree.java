package io.ledgerpreflight.cli;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** A dedicated Linux session contains the validator and verifier descendants. */
final class TvuProcessTree {
    private final Process process;
    private final Map<Long,ProcessHandle> observed=new ConcurrentHashMap<>();
    private final AtomicBoolean stopped=new AtomicBoolean();
    private TvuProcessTree(Process process){this.process=process;}
    static Path sessionLauncher()throws IOException {
        if(!System.getProperty("os.name","").toLowerCase(Locale.ROOT).contains("linux"))throw new IOException("Guided TVU execution requires Linux process-group support.");
        for(String name:List.of("/usr/bin/setsid","/bin/setsid"))if(Files.isRegularFile(Path.of(name))&&Files.isExecutable(Path.of(name)))return Path.of(name);
        throw new IOException("Guided TVU requires the standard Linux setsid utility to manage validator processes safely.");
    }
    static TvuProcessTree start(List<String> command,Path workspace)throws IOException {
        if(command.size()<3||!command.get(0).equals(sessionLauncher().toString())||!command.get(1).equals("--wait"))throw new IOException("The planned TVU command is missing its private process session.");
        Path java=Path.of(command.get(2));
        if(!java.isAbsolute()||!java.getFileName().toString().equals("java")||java.getParent()==null||java.getParent().getParent()==null||!Files.isRegularFile(java)||!Files.isExecutable(java))throw new IOException("The planned TVU Java executable is unavailable.");
        ProcessBuilder builder=new ProcessBuilder(command).directory(workspace.toFile()).redirectErrorStream(true);
        for(String name:List.of("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","LD_PRELOAD","LD_LIBRARY_PATH"))builder.environment().remove(name);
        String inheritedPath=builder.environment().get("PATH");
        builder.environment().put("JAVA_HOME",java.getParent().getParent().toString());
        builder.environment().put("PATH",java.getParent()+(inheritedPath==null||inheritedPath.isEmpty()?"":File.pathSeparator+inheritedPath));
        builder.environment().put("HOME",workspace.toString());builder.environment().put("TMPDIR",workspace.resolve("tmp").toString());
        Process process=builder.start();process.getOutputStream().close();return new TvuProcessTree(process);
    }
    Process process(){return process;}
    void observe()throws IOException {
        try(var descendants=process.descendants()) {
            Iterator<ProcessHandle> iterator=descendants.iterator();while(iterator.hasNext()){ProcessHandle child=iterator.next();if(observed.size()>=1024&&!observed.containsKey(child.pid()))throw new IOException("TVU process-tree safety limit reached.");observed.put(child.pid(),child);}
        }
    }
    void stop() {
        if(!stopped.compareAndSet(false,true))return;
        try{observe();}catch(IOException ignored){}
        signal("TERM");process.destroy();observed.values().forEach(handle->{if(handle.isAlive())handle.destroy();});
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(System.nanoTime()<deadline&&(process.isAlive()||observed.values().stream().anyMatch(ProcessHandle::isAlive))) {
            try{Thread.sleep(25);}catch(InterruptedException e){Thread.currentThread().interrupt();break;}
        }
        // Signal the session even after the parent exits: unobserved children retain its group.
        signal("KILL");observed.values().forEach(handle->{if(handle.isAlive())handle.destroyForcibly();});if(process.isAlive())process.destroyForcibly();
        try{process.waitFor(2,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}
    }
    private void signal(String signal) {
        // The shell program is constant; the sole argument is a JVM-generated numeric PID.
        try {
            Process cleanup=new ProcessBuilder("/bin/sh","-c","kill -"+signal+" -\"$1\" 2>/dev/null || :","ledger-preflight-stop",Long.toString(process.pid())).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if(!cleanup.waitFor(1,TimeUnit.SECONDS))cleanup.destroyForcibly();
        }catch(IOException ignored){}catch(InterruptedException e){Thread.currentThread().interrupt();}
    }
}
