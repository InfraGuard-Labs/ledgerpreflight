package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;

/** Explicitly approved TVU only. Never rewrites node/configuration or runs a migration. */
public final class TvuExecution {
    public record Plan(Path base,Path jar,Path capture,List<String> command){}
    public static Plan prepare(AssessmentService.Options options,Assessment assessment,Path base,Path capture)throws IOException {
        base=base.toAbsolutePath().normalize();capture=capture.toAbsolutePath().normalize();
        Main.ensureOutputSeparate(base,options.node());Main.ensureOutputSeparate(base,options.kit());Main.ensureOutputSeparate(capture,base);
        Reports.checkNoSymlink(base);Reports.checkNoSymlink(capture);
        if(!Files.isDirectory(base)||!Files.isDirectory(base.resolve("cordapps")))throw new IOException("Prepare an isolated validation copy with node.conf and target cordapps first.");
        Path conf=base.resolve("node.conf");new ConfigAnalyzer().analyze(conf);
        // A different path alone is insufficient: reject a copied production connection URL.
        Path original=options.nodeConf()==null?options.node().resolve("node.conf"):options.nodeConf();
        String originalUrl=jdbc(original),cloneUrl=jdbc(conf);
        if(originalUrl==null||cloneUrl==null||cloneUrl.equals(originalUrl))throw new IOException("Validation copy must explicitly use a different disposable database URL from the assessed node.");
        Path jar=options.tvuJar();
        if(jar==null) {
            var candidates=Reports.JSON.valueToTree(assessment.evidence().get("upgrade-kit"));List<Path> matches=new ArrayList<>();
            for(var item:candidates)if(item.path("role").asText().equals("TVU"))matches.add(options.kit().resolve(item.path("path").asText()));
            if(matches.size()!=1)throw new IOException("A unique TVU JAR is required; reassess with --tvu-jar.");jar=matches.get(0);
        }
        jar=jar.toAbsolutePath().normalize();Reports.checkNoSymlink(jar);
        if(!Files.isRegularFile(jar))throw new IOException("TVU JAR is unavailable.");
        var tvuScan=new io.ledgerpreflight.bytecode.BytecodeScanner().scan(jar);
        if(!tvuScan.issues().isEmpty()||tvuScan.jars().size()!=1||!Discovery.version(tvuScan.jars().get(0)).equals(assessment.targetVersion()))
            throw new IOException("TVU version must be established and match the assessed target before execution.");
        // Validation must use the assessed target CorDapps and legacy dependencies, not a stale copy.
        var cloneScan=new io.ledgerpreflight.bytecode.BytecodeScanner().scan(base);
        if(!cloneScan.issues().isEmpty())throw new IOException("Validation copy contains incomplete or unsafe JAR evidence.");
        Map<String,String> expected=new TreeMap<>(),actual=new TreeMap<>();
        for(var item:Reports.JSON.valueToTree(assessment.evidence().get("cordapps-target")))expected.put("cordapps/"+Path.of(item.path("path").asText()).getFileName(),item.path("sha256").asText());
        for(var item:Reports.JSON.valueToTree(assessment.evidence().get("upgrade-kit")))if(item.path("role").asText().equals("LEGACY"))expected.put(item.path("path").asText(),item.path("sha256").asText());
        for(var item:Discovery.inventory(cloneScan))if(Set.of("CORDAPP","LEGACY").contains(item.role()))actual.put(item.path(),item.sha256());
        if(!expected.equals(actual))throw new IOException("Validation-copy CorDapps/legacy-jars differ from the assessed target. Prepare matching bytes before running TVU.");
        // Reject symlinks anywhere in the prepared clone, including config and dependency trees.
        try(var paths=Files.walk(base)){var iter=paths.iterator();int count=0;while(iter.hasNext()){if(++count>10000)throw new IOException("Validation copy exceeds path limit");Reports.checkNoSymlink(iter.next());}}
        List<String> command=List.of(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-Dfile.encoding=UTF-8","-Dlog-path="+capture,"-jar",jar.toString(),"-b",base.toString(),"-f",conf.toString(),"-e",capture.resolve("errors").toString());
        return new Plan(base,jar,capture,command);
    }
    private static String jdbc(Path conf)throws IOException {
        new ConfigAnalyzer().analyze(conf);
        String text=new String(SafeInputs.read(conf,1024*1024),StandardCharsets.UTF_8);
        var config=com.typesafe.config.ConfigFactory.parseString(text);
        Set<String> urls=new LinkedHashSet<>();
        for(String key:List.of("dataSourceProperties.dataSource.url","dataSourceProperties.\"dataSource.url\"","database.url","dataSource.url","\"dataSource.url\""))
            try{if(config.hasPath(key))urls.add(config.getString(key));}
            catch(com.typesafe.config.ConfigException e){throw new IOException("Database URL must be explicit; substitutions are not accepted for execution.");}
        if(urls.size()>1)throw new IOException("Database URL declarations conflict; resolve the validation configuration before execution.");
        return urls.isEmpty()?null:urls.iterator().next();
    }
    public static String databaseTarget(Path conf)throws IOException {
        String url=jdbc(conf);if(url==null)return "Not established";
        String safe=url.replaceAll("//[^/@]+@","//").split("[?;]",2)[0];
        return safe.matches("jdbc:[a-zA-Z0-9]+://[a-zA-Z0-9.\\-_:\\[\\]]+/[a-zA-Z0-9_\\-/]+")?safe:"Configured in the validation copy's node.conf (connection details withheld)";
    }
    public static int run(Plan plan,boolean explicitlyApproved,SessionTerminal terminal,long timeoutSeconds)throws Exception {
        if(!explicitlyApproved)throw new IOException("TVU execution requires explicit confirmation.");
        Reports.checkNoSymlink(plan.capture());
        Files.createDirectory(plan.capture(),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.createDirectory(plan.capture().resolve("errors"));
        ProcessBuilder builder=new ProcessBuilder(plan.command()).directory(plan.base().toFile()).redirectErrorStream(true);
        builder.environment().remove("JAVA_TOOL_OPTIONS");builder.environment().remove("JDK_JAVA_OPTIONS");builder.environment().remove("_JAVA_OPTIONS");
        Process process=builder.start();process.getOutputStream().close();
        Runnable stop=()->{process.descendants().forEach(p->p.destroyForcibly());process.destroyForcibly();};
        Thread hook=new Thread(stop,"stop-approved-tvu");Runtime.getRuntime().addShutdownHook(hook);
        ExecutorService reader=Executors.newSingleThreadExecutor();
        Future<?> capture=reader.submit(()->{
            try(InputStream in=process.getInputStream();OutputStream out=Files.newOutputStream(plan.capture().resolve("console.log"),StandardOpenOption.CREATE_NEW)) {
                byte[] buffer=new byte[8192];long total=0;int n;
                while((n=in.read(buffer))!=-1){total+=n;if(total>16*1024*1024)throw new IOException("TVU console capture exceeded 16 MiB; run is incomplete");out.write(buffer,0,n);}
            }catch(IOException e){stop.run();throw new UncheckedIOException(e);}
        });
        try {
            terminal.text("Running approved TVU validation… Ctrl+C stops the session and TVU.");
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(timeoutSeconds);
            while(!process.waitFor(10,TimeUnit.SECONDS)){if(System.nanoTime()>=end)throw new IOException("TVU time limit reached; evidence is incomplete");terminal.text("TVU is still running; output is captured privately.");}
            capture.get(5,TimeUnit.SECONDS);return process.exitValue();
        } finally {stop.run();reader.shutdownNow();Runtime.getRuntime().removeShutdownHook(hook);}
    }
}
