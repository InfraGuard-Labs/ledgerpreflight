package io.ledgerpreflight.cli;

import com.fasterxml.jackson.databind.JsonNode;
import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.jar.Manifest;
import java.util.zip.*;

/** An explicitly approved TVU run owns a private workspace, process group and evidence capture. */
public final class GuidedTvuExecution {
    private GuidedTvuExecution(){}
    private record Source(Path path,String destination,String sha256,String role){}
    public record Progress(Long expected,Long processed,Long passed,Long failed,long elapsedSeconds,String status){}
    public record Outcome(List<Path> evidencePaths,Map<String,Object> manifest,int exitCode,String failureKind,boolean cancelled,boolean schemaApplied){}
    public static final class Plan {
        private final Path workspace,capture;
        private final List<String> command,warnings;
        private final String schema,targetVersion,tvuVersion;
        private final boolean schemaAutomatic;
        private final int targetCordapps;
        private final TvuConfiguration configuration,original;
        private final List<Source> sources;
        private Plan(Path workspace,Path capture,List<String> command,List<String> warnings,String schema,String targetVersion,String tvuVersion,boolean schemaAutomatic,int targetCordapps,TvuConfiguration configuration,TvuConfiguration original,List<Source> sources){this.workspace=workspace;this.capture=capture;this.command=List.copyOf(command);this.warnings=List.copyOf(warnings);this.schema=schema;this.targetVersion=targetVersion;this.tvuVersion=tvuVersion;this.schemaAutomatic=schemaAutomatic;this.targetCordapps=targetCordapps;this.configuration=configuration;this.original=original;this.sources=List.copyOf(sources);}
        public Path workspace(){return workspace;}public Path capture(){return capture;}public List<String> command(){return command;}public List<String> warnings(){return warnings;}
        public String databaseTarget(){return configuration.databaseTarget();}public String schema(){return schema;}public String targetVersion(){return targetVersion;}public String tvuVersion(){return tvuVersion;}
        public boolean schemaAutomatic(){return schemaAutomatic;}public int targetCordapps(){return targetCordapps;}
    }
    /** Read-only planning. Neither output directories nor a TVU process exist before confirmation. */
    public static Plan inspect(AssessmentService.Options options,Assessment assessment,Path alternateConf,String explicitSchema,Path reportDir)throws IOException {
        Objects.requireNonNull(options);Objects.requireNonNull(assessment);TvuProcessTree.sessionLauncher();
        Path originalPath=options.nodeConf()==null?options.node().resolve("node.conf"):options.nodeConf();
        TvuConfiguration original=alternateConf==null?TvuConfiguration.read(originalPath):TvuConfiguration.inspectSource(originalPath),configuration=alternateConf==null?original:TvuConfiguration.read(alternateConf);
        var config=original.evidence();String schema="";
        if(config.postgresql()||explicitSchema!=null)schema=ConfigAnalyzer.selectTvuSchema(config,explicitSchema);
        configuration.validateRelationship(original,schema);
        boolean automatic=configuration.evidence().postgresql()&&assessment.targetVersion().matches("4\\.12(?:\\.[0-9]+)*")&&!schema.isEmpty()&&!schema.equals(schema.toLowerCase(Locale.ROOT));
        int requirement=assessment.targetVersion().matches("4\\.12(?:\\.[0-9]+)*")?17:assessment.targetVersion().matches("4\\.11(?:\\.[0-9]+)*")?8:0;
        if(requirement==0||Runtime.version().feature()!=requirement)throw new IOException("This target TVU requires a compatible private Java runtime; the available package runtime cannot run this target.");
        Path java=Path.of(System.getProperty("java.home"),"bin","java").toAbsolutePath();if(!Files.isExecutable(java))throw new IOException("The compatible private Java runtime is unavailable.");
        JsonNode inventory=Reports.JSON.valueToTree(assessment.evidence().get("upgrade-kit"));
        List<Source> sources=new ArrayList<>();Source runtime=selected(options.targetCorda(),options.kit(),inventory,"RUNTIME",assessment.targetVersion(),"corda.jar");
        Source validator=selected(options.tvuJar(),options.kit(),inventory,"TVU",assessment.targetVersion(),"corda-tools-transaction-validator.jar");sources.add(runtime);sources.add(validator);
        String main=entrypoint(validator.path(),requirement);
        JsonNode apps=Reports.JSON.valueToTree(assessment.evidence().get("cordapps-target"));int appCount=0;
        for(JsonNode app:apps){Path source=resolve(options.targetCordapps()==null?options.kit():options.targetCordapps(),app.path("path").asText());sources.add(source(source,"cordapps/"+source.getFileName(),app.path("sha256").asText(),"CORDAPP"));appCount++;}
        if(appCount==0&&Reports.JSON.valueToTree(assessment.evidence().get("cordapps-current")).size()>0)throw new IOException("Target CorDapps are missing from the supplied upgrade kit.");
        if(options.legacyJars()!=null)addExplicit(sources,options.legacyJars(),"legacy-jars","LEGACY");
        else for(JsonNode item:inventory)if(item.path("role").asText().equals("LEGACY")){Path path=resolve(options.kit(),item.path("path").asText());sources.add(source(path,"legacy-jars/"+path.getFileName(),item.path("sha256").asText(),"LEGACY"));}
        List<Source> drivers=new ArrayList<>();for(JsonNode item:inventory)if(item.path("role").asText().equals("DRIVER")){Path path=resolve(options.kit(),item.path("path").asText());drivers.add(source(path,"drivers/"+path.getFileName(),item.path("sha256").asText(),"DRIVER"));}
        String owner=Objects.toString(configuration.evidence().safeSettings().get("dataSourceClassName"),switch(Objects.toString(configuration.evidence().safeSettings().get("databaseVendor"),"")){case "PostgreSQL"->"org.postgresql.Driver";case "Oracle"->"oracle.jdbc.OracleDriver";case "SQL Server"->"com.microsoft.sqlserver.jdbc.SQLServerDriver";default->"";}).replace('.','/');
        List<Source> targetProviders=providers(drivers,owner);uniqueProvider(targetProviders);
        if(!owner.isEmpty()&&targetProviders.isEmpty()&&!hasClass(runtime.path(),owner)&&!hasClass(validator.path(),owner)) {
            List<Source> currentProviders=new ArrayList<>();for(JsonNode item:Reports.JSON.valueToTree(assessment.evidence().get("environment")).path("current"))if(item.path("role").asText().equals("DRIVER")){Path path=resolve(options.node(),item.path("path").asText());if(hasClass(path,owner))currentProviders.add(source(path,"drivers/"+path.getFileName(),item.path("sha256").asText(),"DRIVER"));}
            uniqueProvider(currentProviders);if(!currentProviders.isEmpty()){Source current=currentProviders.get(0);String destination=current.destination();if(drivers.stream().anyMatch(source->source.destination().equals(destination)))current=new Source(current.path(),"drivers/current-"+current.sha256().substring(0,12)+"-"+current.path().getFileName(),current.sha256(),current.role());drivers.add(current);}
        }
        sources.addAll(drivers);
        Set<String> destinations=new HashSet<>();long total=0;for(Source source:sources){if(!destinations.add(source.destination()))throw new IOException("Prepared TVU artifacts contain conflicting destination filenames.");total+=Files.size(source.path());}
        if(sources.size()>256||total>8L*1024*1024*1024)throw new IOException("Prepared TVU artifacts exceed the bounded workspace limit.");
        Path report=reportDir.toAbsolutePath().normalize();Main.ensureOutputSeparate(report,options.node());Main.ensureOutputSeparate(report,options.kit());Reports.checkNoSymlink(report);
        String run=Instant.now().toString().replace(':','-')+"-"+UUID.randomUUID().toString().substring(0,8);Path capture=report.resolve("tvu").resolve(run),workspace=report.resolve("tvu").resolve(".workspace-"+run);
        String classpath=(automatic?workspace.resolve("hibernate-config")+File.pathSeparator:"")+workspace.resolve(validator.destination())+File.pathSeparator+workspace.resolve(runtime.destination());
        for(Source source:sources)if(source.role().equals("DRIVER"))classpath+=File.pathSeparator+workspace.resolve(source.destination());
        List<String> command=List.of(TvuProcessTree.sessionLauncher().toString(),"--wait",java.toString(),"-Xmx256m","-Dfile.encoding=UTF-8","-Djava.io.tmpdir="+workspace.resolve("tmp"),"-Dlog-path="+workspace.resolve("output"),"-cp",classpath,main,"-b",workspace.toString(),"-f",workspace.resolve("node.conf").toString(),"-e",workspace.resolve("output/errors").toString());
        List<String> warnings=new ArrayList<>();if(assessment.findings().stream().anyMatch(f->f.category().equals("LEGACY_JARS")&&f.severity().equals("BLOCKED")))warnings.add("The supplied legacy compatibility JAR is shadowed; TVU may confirm the existing compatibility failure.");
        return new Plan(workspace,capture,command,warnings,schema,assessment.targetVersion(),assessment.targetVersion(),automatic,appCount,configuration,original,sources);
    }
    private static Path resolve(Path supplied,String relative)throws IOException {
        if(relative.isBlank()||relative.contains("!/")||Path.of(relative).isAbsolute()||relative.indexOf('\\')>=0)throw new IOException("A required TVU artifact path is not a physical selected input.");
        Path base=supplied.toAbsolutePath().normalize(),path=Files.isRegularFile(base,LinkOption.NOFOLLOW_LINKS)?base:base.resolve(relative).normalize();
        if(!Files.isRegularFile(base,LinkOption.NOFOLLOW_LINKS)&&!path.startsWith(base))throw new IOException("Required TVU artifact escapes the supplied input.");SafeInputs.checkPath(path);return path;
    }
    private static Source selected(Path explicit,Path base,JsonNode inventory,String role,String version,String destination)throws IOException {
        if(explicit!=null) {
            var discovered=new ArtifactDiscovery().scanLayout(explicit);if(!discovered.issues().isEmpty()||discovered.jars().size()!=1)throw new IOException("The selected TVU/runtime artifact cannot be safely identified.");
            var artifact=discovered.jars().get(0);if(!Discovery.version(artifact).equals(version))throw new IOException("The selected TVU/runtime version does not match the assessed target.");return source(explicit,destination,artifact.sha256(),role);
        }
        List<JsonNode> candidates=new ArrayList<>();for(JsonNode item:inventory)if(item.path("role").asText().equals(role)&&item.path("version").asText().equals(version))candidates.add(item);
        if(candidates.size()!=1)throw new IOException("A unique matching target "+(role.equals("TVU")?"TVU artifact":"runtime")+" is required before guided execution.");JsonNode chosen=candidates.get(0);return source(resolve(base,chosen.path("path").asText()),destination,chosen.path("sha256").asText(),role);
    }
    private static Source source(Path path,String destination,String expected,String role)throws IOException {SafeInputs.checkPath(path);if(Files.size(path)>2L*1024*1024*1024||!expected.matches("[a-fA-F0-9]{64}")||!hash(path).equalsIgnoreCase(expected))throw new IOException("A required TVU artifact differs from the assessed input or exceeds its safety limit.");return new Source(path.toAbsolutePath().normalize(),destination,expected.toLowerCase(Locale.ROOT),role);}
    private static boolean hasClass(Path path,String owner)throws IOException {if(owner.isEmpty())return false;try(ZipFile archive=ArchiveSafety.open(path,100000)){return archive.getEntry(owner+".class")!=null;}}
    private static List<Source> providers(List<Source> sources,String owner)throws IOException {List<Source> found=new ArrayList<>();for(Source source:sources)if(hasClass(source.path(),owner))found.add(source);return found;}
    private static void uniqueProvider(List<Source> sources)throws IOException {if(sources.stream().map(Source::sha256).distinct().count()>1)throw new IOException("Multiple JDBC driver providers exist without a proven selection; prepare one matching provider for guided TVU.");}
    private static void addExplicit(List<Source> sources,Path supplied,String folder,String role)throws IOException {
        Reports.checkNoSymlink(supplied);int count=0;try(var walk=Files.walk(supplied,5)){for(Iterator<Path> iter=walk.iterator();iter.hasNext();){Path path=iter.next();if(++count>1024)throw new IOException("TVU dependency input path limit exceeded.");Reports.checkNoSymlink(path);if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))sources.add(source(path,folder+"/"+path.getFileName(),hash(path),role));}}
    }
    private static String entrypoint(Path jar,int javaVersion)throws IOException {
        try(ZipFile archive=ArchiveSafety.open(jar,100000)) {
            ZipEntry metadata=archive.getEntry("META-INF/MANIFEST.MF");if(metadata==null)throw new IOException("The TVU launch manifest is missing.");Manifest manifest;
            try(InputStream input=archive.getInputStream(metadata)){manifest=new Manifest(new ByteArrayInputStream(SafeInputs.bounded(input,65536)));}
            List<String> names=new ArrayList<>();String application=manifest.getMainAttributes().getValue("Application-Class"),launcher=manifest.getMainAttributes().getValue("Main-Class");
            if(application!=null&&!application.isBlank())names.add(application);names.add("net.corda.transactionvalidator.TransactionValidatorKt");if(launcher!=null&&!launcher.isBlank()&&!names.contains(launcher))names.add(launcher);
            for(String name:names) {
                if(!name.matches("[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*"))continue;ZipEntry entry=archive.getEntry(name.replace('.','/')+".class");if(entry==null)continue;
                byte[] bytes;try(InputStream input=archive.getInputStream(entry)){bytes=SafeInputs.bounded(input,2*1024*1024);}if(bytes.length<10||(bytes[0]&255)!=0xca||(bytes[1]&255)!=0xfe||(bytes[2]&255)!=0xba||(bytes[3]&255)!=0xbe)continue;
                ClassReader reader=new ClassReader(bytes);if(reader.readUnsignedShort(6)>javaVersion+44)throw new IOException("The TVU entrypoint requires a newer private Java runtime.");boolean[] found={false};
                reader.accept(new ClassVisitor(Opcodes.ASM9){@Override public MethodVisitor visitMethod(int access,String method,String descriptor,String signature,String[] exceptions){if(method.equals("main")&&descriptor.equals("([Ljava/lang/String;)V")&&(access&(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC))==(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC))found[0]=true;return null;}},ClassReader.SKIP_CODE|ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
                if(found[0])return name;
            }
        }catch(IllegalArgumentException|IndexOutOfBoundsException e){throw new IOException("The TVU entrypoint cannot be safely validated.");}
        throw new IOException("A supported public TVU entrypoint could not be established from the supplied artifact.");
    }
    public static Outcome run(Plan plan,boolean confirmIsolatedDb,long timeoutSeconds,Consumer<Progress> progress,BooleanSupplier cancel)throws IOException {
        if(!confirmIsolatedDb)throw new IOException("TVU execution requires explicit confirmation of an isolated / non-production database copy.");
        if(timeoutSeconds<1||timeoutSeconds>86400)throw new IOException("TVU execution timeout must be between one second and 24 hours.");
        Objects.requireNonNull(progress);Objects.requireNonNull(cancel);plan.configuration.verifyUnchanged();plan.original.verifyUnchanged();
        String started=Instant.now().toString();long startedNanos=System.nanoTime();AtomicReference<TvuProcessTree> tree=new AtomicReference<>();AtomicReference<GuidedTvuCapture> capture=new AtomicReference<>();AtomicReference<Outcome> outcome=new AtomicReference<>();
        AtomicBoolean applied=new AtomicBoolean(),stopping=new AtomicBoolean();ExecutorService reader=Executors.newSingleThreadExecutor(task->{Thread thread=new Thread(task,"tvu-capture");thread.setDaemon(true);return thread;});AtomicReference<Future<?>> reading=new AtomicReference<>();
        Object finishLock=new Object();
        BiFunction<String,Integer,Outcome> finish=(kind,code)->{synchronized(finishLock){if(outcome.get()!=null)return outcome.get();TvuProcessTree running=tree.get();if(running!=null)running.stop();Future<?> read=reading.get();if(read!=null)try{read.get(3,TimeUnit.SECONDS);}catch(Exception ignored){}Outcome value=finish(plan,capture.get(),started,kind,code,applied.get());outcome.set(value);return value;}};
        Thread hook=new Thread(()->{stopping.set(true);finish.apply("USER_CANCELLATION",130);},"stop-guided-tvu");boolean hooked=false;
        try {
            Runtime.getRuntime().addShutdownHook(hook);hooked=true;
            synchronized(finishLock){
            if(cancel.getAsBoolean()||stopping.get())return finish.apply("USER_CANCELLATION",130);
            privateDirectories(plan.capture().getParent());privateDirectory(plan.capture());privateDirectory(plan.workspace());
            for(String directory:List.of("cordapps","legacy-jars","drivers","hibernate-config","output","output/errors","tmp"))privateDirectory(plan.workspace().resolve(directory));
            capture.set(new GuidedTvuCapture(plan.capture(),plan.configuration));
            for(Source source:plan.sources)copy(source,plan.workspace().resolve(source.destination()),()->stopping.get()||cancel.getAsBoolean());plan.configuration.verifyUnchanged();plan.configuration.writePrivate(plan.workspace().resolve("node.conf"));
            if(plan.schemaAutomatic()) {
                Properties properties=new Properties();properties.setProperty("hibernate.default_schema",ConfigAnalyzer.quotedTvuSchema(plan.schema()));
                try(OutputStream writer=Files.newOutputStream(GuidedTvuCapture.privateFile(plan.workspace().resolve("hibernate-config/hibernate.properties")),StandardOpenOption.WRITE)){properties.store(writer,null);}applied.set(true);
            }
            if(cancel.getAsBoolean()||stopping.get())return finish.apply("USER_CANCELLATION",130);
            TvuProcessTree process=TvuProcessTree.start(plan.command(),plan.workspace());tree.set(process);
            GuidedTvuCapture collector=capture.get();reading.set(reader.submit(()->{try{collector.read(process.process().getInputStream());}catch(IOException e){process.stop();throw new UncheckedIOException(e);}}));
            }
            TvuProcessTree process=tree.get();GuidedTvuCapture collector=capture.get();
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(timeoutSeconds),lastProgress=0;
            while(true) {
                process.observe();long now=System.nanoTime();if(now-lastProgress>=TimeUnit.SECONDS.toNanos(1)){progress.accept(collector.progress(TimeUnit.NANOSECONDS.toSeconds(now-startedNanos)));lastProgress=now;}
                if(cancel.getAsBoolean()||Thread.currentThread().isInterrupted())return finish.apply("USER_CANCELLATION",130);
                if(now>=deadline)return finish.apply("EXECUTION_FAILURE",124);
                if(process.process().waitFor(100,TimeUnit.MILLISECONDS))break;
            }
            process.stop();reading.get().get(3,TimeUnit.SECONDS);progress.accept(collector.progress(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime()-startedNanos)));int code=process.process().exitValue();
            String kind=collector.databaseFailure()&&!collector.completeCounters()?"DATABASE_CONNECTION_FAILURE":collector.hasFailure()?"TRANSACTION_VERIFICATION_FAILURE":code!=0||!collector.completeCounters()?"EXECUTION_FAILURE":"NONE";
            return finish.apply(kind,code);
        }catch(InterruptedException e){Thread.currentThread().interrupt();return finish.apply("USER_CANCELLATION",130);}
        catch(IOException|ExecutionException|TimeoutException|RuntimeException e){return stopping.get()||e instanceof InterruptedIOException?finish.apply("USER_CANCELLATION",130):finish.apply(tree.get()==null?"SETUP_FAILURE":"EXECUTION_FAILURE",-1);}
        finally {if(tree.get()!=null)tree.get().stop();reader.shutdownNow();if(hooked)try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException ignored){} }
    }
    private static Outcome finish(Plan plan,GuidedTvuCapture capture,String started,String initialKind,int code,boolean applied) {
        String kind=initialKind;List<Path> evidence=new ArrayList<>();List<String> issues=new ArrayList<>();Map<String,Object> manifest=new TreeMap<>();
        try {
            if(capture!=null){capture.close();try{evidence.addAll(capture.collectGenerated(plan.workspace()));if(!Set.of("SETUP_FAILURE","USER_CANCELLATION").contains(initialKind)&&code>=0&&code!=124){kind=capture.databaseFailure()&&!capture.completeCounters()?"DATABASE_CONNECTION_FAILURE":capture.hasFailure()?"TRANSACTION_VERIFICATION_FAILURE":code!=0||!capture.completeCounters()||capture.schemaFailure()||capture.limitedBinaryEvidence()?"EXECUTION_FAILURE":"NONE";}}catch(IOException e){kind="EXECUTION_FAILURE";issues.add("Generated TVU evidence could not be safely captured in full.");}manifest.put("counters",capture.counters());manifest.put("sourceConsoleSha256",hash(plan.capture().resolve("tvu.log")));}
        }catch(IOException e){kind="EXECUTION_FAILURE";issues.add("TVU evidence capture is incomplete.");}
        boolean cleaned=false;try{deleteWorkspace(plan.workspace());cleaned=true;}catch(IOException e){issues.add("Sensitive TVU workspace cleanup did not complete; the private directory requires attention.");kind="EXECUTION_FAILURE";}
        try{if(capture!=null)evidence.add(0,capture.analysis(kind));}catch(IOException e){kind="EXECUTION_FAILURE";evidence.clear();issues.add("Final TVU analysis evidence could not be safely written.");}
        manifest.put("version","1");manifest.put("started",started);manifest.put("finished",Instant.now().toString());manifest.put("targetVersion",plan.targetVersion());manifest.put("tvuVersion",plan.tvuVersion());manifest.put("exitCode",code);manifest.put("failureKind",kind);manifest.put("cancelled",initialKind.equals("USER_CANCELLATION"));manifest.put("schemaApplied",applied);manifest.put("schema",plan.schema());manifest.put("workspaceCleaned",cleaned);manifest.put("issues",issues);
        manifest.put("artifacts",plan.sources.stream().map(source->Map.of("role",source.role(),"path",source.destination(),"sha256",source.sha256())).toList());manifest.put("classpath",plan.command().get(plan.command().indexOf("-cp")+1).replace(plan.workspace().toString(),"[PRIVATE-WORKSPACE]"));manifest.put("evidence",evidence.stream().map(path->path.getFileName().toString()).toList());
        manifest.put("databaseTarget",plan.databaseTarget());manifest.put("configurationSource",plan.configuration==plan.original?"current node":"explicit alternate");manifest.put("sanitizedConfigurationSha256",plan.configuration.sanitizedFingerprint());
        try {if(Files.isDirectory(plan.capture())){Files.writeString(GuidedTvuCapture.privateFile(plan.capture().resolve("run-manifest.json")),plan.configuration.redact(Reports.json(manifest)));if(capture!=null){var summary=new TvuAnalyzer().analyze(evidence);Files.writeString(GuidedTvuCapture.privateFile(plan.capture().resolve("tvu-summary.json")),plan.configuration.redact(Reports.json(summary)));}}}
        catch(IOException e){manifest.put("manifestWriteFailure",true);kind="EXECUTION_FAILURE";manifest.put("failureKind",kind);evidence.clear();}
        return new Outcome(List.copyOf(evidence),Collections.unmodifiableMap(manifest),code,kind,initialKind.equals("USER_CANCELLATION"),applied);
    }
    private static void privateDirectory(Path directory)throws IOException {Reports.checkNoSymlink(directory);Files.createDirectory(directory,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}
    private static void privateDirectories(Path directory)throws IOException {Reports.checkNoSymlink(directory);if(Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS))return;Path parent=directory.getParent();if(parent!=null)privateDirectories(parent);privateDirectory(directory);}
    private static void copy(Source source,Path destination,BooleanSupplier abort)throws IOException {
        SafeInputs.checkPath(source.path());MessageDigest digest;try{digest=MessageDigest.getInstance("SHA-256");}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
        long total=0;try(InputStream input=Files.newInputStream(source.path(),LinkOption.NOFOLLOW_LINKS);OutputStream output=Files.newOutputStream(GuidedTvuCapture.privateFile(destination),StandardOpenOption.WRITE)){byte[] bytes=new byte[65536];int count;while((count=input.read(bytes))!=-1){if(abort.getAsBoolean())throw new InterruptedIOException("TVU preparation was cancelled.");total+=count;if(total>2L*1024*1024*1024)throw new IOException("TVU artifact copy size limit exceeded.");digest.update(bytes,0,count);output.write(bytes,0,count);}}
        if(!HexFormat.of().formatHex(digest.digest()).equals(source.sha256())||!hash(source.path(),abort).equals(source.sha256()))throw new IOException("A selected TVU artifact changed during preparation.");
    }
    static String hash(Path path)throws IOException {return hash(path,()->false);}
    private static String hash(Path path,BooleanSupplier abort)throws IOException {SafeInputs.checkPath(path);try(InputStream input=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] bytes=new byte[65536];int read;while((read=input.read(bytes))!=-1){if(abort.getAsBoolean())throw new InterruptedIOException("TVU preparation was cancelled.");digest.update(bytes,0,read);}return HexFormat.of().formatHex(digest.digest());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
    private static void deleteWorkspace(Path workspace)throws IOException {
        Reports.checkNoSymlink(workspace.getParent());
        if(!Files.exists(workspace,LinkOption.NOFOLLOW_LINKS))return;
        Files.walkFileTree(workspace,new SimpleFileVisitor<>(){@Override public FileVisitResult visitFile(Path path,java.nio.file.attribute.BasicFileAttributes attributes)throws IOException{Files.delete(path);return FileVisitResult.CONTINUE;}@Override public FileVisitResult postVisitDirectory(Path path,IOException error)throws IOException{if(error!=null)throw error;Files.delete(path);return FileVisitResult.CONTINUE;}});
    }
}
