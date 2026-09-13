package io.ledgerpreflight.integration;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.*;

/** Original executable test double. Uses only the JDK and never opens a database or socket. */
public final class SyntheticGuidedTvuProgram {
    private SyntheticGuidedTvuProgram(){}
    public static void main(String[] args)throws Exception {
        if(args.length>0&&args[0].startsWith("--synthetic-")){child(args);return;}
        Properties fixture=new Properties();try(InputStream in=SyntheticGuidedTvuProgram.class.getResourceAsStream("/synthetic-run.properties")){fixture.load(Objects.requireNonNull(in));}
        String override=System.getenv("SYNTHETIC_TVU_CONTROL");
        Path control=Path.of(override==null||override.isBlank()?fixture.getProperty("control"):override);Files.createDirectories(control);
        Files.writeString(control.resolve("started.pid"),Long.toString(ProcessHandle.current().pid()));
        String mode=fixture.getProperty("mode");Path base=Path.of(argument(args,"-b"));Path conf=Path.of(argument(args,"-f"));Path errors=Path.of(argument(args,"-e"));
        Properties observed=new Properties();observed.setProperty("base",base.toString());observed.setProperty("config",conf.toString());observed.setProperty("javaHome",System.getProperty("java.home"));
        observed.setProperty("arguments",String.join("\n",args));observed.setProperty("jvmArguments",String.join("\n",ManagementFactory.getRuntimeMXBean().getInputArguments()));
        observed.setProperty("javaVersion",System.getProperty("java.version"));observed.setProperty("alternateSelected",Boolean.toString(Files.readString(conf).contains("alternate_copy")));
        observed.setProperty("environmentJavaHome",Objects.toString(System.getenv("JAVA_HOME"),""));
        Process bareJava=new ProcessBuilder("java","-version").redirectErrorStream(true).start();if(!bareJava.waitFor(5,java.util.concurrent.TimeUnit.SECONDS)){bareJava.destroyForcibly();throw new IOException("Synthetic bare-java probe did not finish");}observed.setProperty("bareJavaVersion",new String(bareJava.getInputStream().readAllBytes(),StandardCharsets.UTF_8));
        observed.setProperty("workspaceMode",PosixFilePermissions.toString(Files.getPosixFilePermissions(base)));observed.setProperty("configMode",PosixFilePermissions.toString(Files.getPosixFilePermissions(conf)));
        try(var paths=Files.walk(base)){observed.setProperty("workspaceFiles",String.join("\n",paths.filter(Files::isRegularFile).map(base::relativize).map(Path::toString).sorted().toList()));}
        Properties schema=new Properties();try(InputStream in=SyntheticGuidedTvuProgram.class.getResourceAsStream("/hibernate.properties")){if(in!=null)schema.load(in);}
        String configured=schema.getProperty("hibernate.default_schema","");observed.setProperty("loadedSchema",configured);
        try(OutputStream out=Files.newOutputStream(control.resolve("observed.properties"))){observed.store(out,"Original synthetic execution observations");}
        if(!configured.isEmpty())System.out.println("HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema="+configured+"}");
        for(int i=0;i<4;i++)System.out.println("External verifier process started; unable to verify with external verifier, trying again");
        if(mode.equals("secrets")){
            String raw=Files.readString(conf);var passwords=Pattern.compile("(?i)[\\\"']?(?:password|dataSource\\.password)[\\\"']?\\s*(?:=|:)?\\s*[\\\"']([^\\\"'\\r\\n]+)").matcher(raw);
            while(passwords.find()){Files.writeString(control.resolve("secret-emitted.txt"),"Synthetic credential diagnostic was emitted");System.out.println("Synthetic driver diagnostic: "+passwords.group(1));}
        }
        if(mode.equals("driver"))Class.forName("org.postgresql.Driver");
        if(mode.equals("cancel")||mode.equals("orphan")){spawn("--synthetic-child",control);await(control.resolve("grandchild.pid"));if(mode.equals("cancel"))forever();}
        if(mode.equals("dbfail")){System.out.println("org.postgresql.util.PSQLException: Connection refused");System.exit(1);}
        if(mode.equals("abort")){System.out.println("Validator exited before transaction processing completed");System.exit(4);}
        if(mode.equals("schemafail"))System.out.println("org.hibernate.tool.schema.spi.SchemaManagementException: Schema-validation: missing table [OtherSchema.vault_states]");
        boolean failed=mode.equals("failed")||mode.equals("mixedZip");Files.createDirectories(errors);
        if(failed||mode.equals("unsafeZip")||mode.equals("corruptZip"))try(ZipOutputStream zip=new ZipOutputStream(Files.newOutputStream(errors.resolve("transactions-errors.zip")))){
            if(mode.equals("unsafeZip")){zip.putNextEntry(new ZipEntry("../escape.txt"));zip.write("Synthetic unsafe entry".getBytes(StandardCharsets.UTF_8));zip.closeEntry();}
            else for(int n=0;n<201;n++){
                ZipEntry entry=new ZipEntry("failure-"+n+".txt");entry.setTime(0);zip.putNextEntry(entry);
                zip.write(("java.lang.NoSuchMethodError: 'java.math.BigDecimal org.example.runtime.Amounts.total(java.lang.Iterable)'\n at org.example.ledger.Agreement.verify(Agreement.java:12)\n").getBytes(StandardCharsets.UTF_8));zip.closeEntry();
            }
            if(mode.equals("mixedZip")){zip.putNextEntry(new ZipEntry("transactions/failed-transaction.bin"));zip.write(new byte[]{0,1,2,3,4,5,6,7});zip.closeEntry();}
        }
        if(mode.equals("corruptZip")){Path zip=errors.resolve("transactions-errors.zip");byte[] bytes=Files.readAllBytes(zip);for(int n=0;n+46<=bytes.length;n++)if(bytes[n]==0x50&&bytes[n+1]==0x4b&&bytes[n+2]==0x01&&bytes[n+3]==0x02){bytes[n+16]^=0x20;break;}Files.write(zip,bytes);}
        long delay=60;String delayOverride=System.getenv("SYNTHETIC_TVU_DELAY_MS");if(delayOverride!=null)delay=Math.max(60,Math.min(10_000,Long.parseLong(delayOverride)));
        if(mode.equals("fileLog")){Files.createDirectories(base.resolve("output"));Files.writeString(base.resolve("output/validator.log"),"total: 650\nprocessed: 650\npassed: 650\nfailed: 0\n");return;}
        if(mode.equals("fileConflict")){Files.createDirectories(base.resolve("output"));Files.writeString(base.resolve("output/validator.log"),"total: 650\nprocessed: 650\npassed: 449\nfailed: 201\n");}
        System.out.println("total: 650");System.out.flush();Thread.sleep(delay);
        System.out.println("processed: 650");System.out.flush();Thread.sleep(delay);
        System.out.println("passed: "+(failed?449:650));System.out.flush();Thread.sleep(delay);
        System.out.println("failed: "+(failed?201:0));System.out.flush();
    }
    private static String argument(String[] args,String key){for(int i=0;i+1<args.length;i++)if(args[i].equals(key))return args[i+1];throw new IllegalArgumentException("Missing synthetic argument "+key);}
    private static void child(String[] args)throws Exception {
        Path control=Path.of(args[1]);boolean child=args[0].equals("--synthetic-child");Files.writeString(control.resolve(child?"child.pid":"grandchild.pid"),Long.toString(ProcessHandle.current().pid()));
        if(child)spawn("--synthetic-grandchild",control);forever();
    }
    private static void spawn(String kind,Path control)throws IOException {
        new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-cp",System.getProperty("java.class.path"),SyntheticGuidedTvuProgram.class.getName(),kind,control.toString()).inheritIO().start();
    }
    private static void await(Path path)throws Exception {long deadline=System.nanoTime()+10_000_000_000L;while(!Files.exists(path)){if(System.nanoTime()>deadline)throw new IOException("Synthetic child did not start");Thread.sleep(25);}}
    private static void forever()throws InterruptedException {while(true)Thread.sleep(1000);}
}
