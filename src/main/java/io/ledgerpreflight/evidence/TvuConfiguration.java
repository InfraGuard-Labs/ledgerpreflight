package io.ledgerpreflight.evidence;

import com.typesafe.config.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import java.util.regex.*;

/** Execution-only configuration. Raw values never become assessment or command arguments. */
public final class TvuConfiguration {
    private final Path source;
    private final String text,fingerprint,databaseTarget;
    private final ConfigAnalyzer.ConfigEvidence evidence;
    private final List<String> secrets;
    private final boolean executable;
    private TvuConfiguration(Path source,String text,ConfigAnalyzer.ConfigEvidence evidence,List<String> secrets,String databaseTarget,boolean executable) {
        this.source=source;this.text=text;this.evidence=evidence;this.secrets=secrets;this.databaseTarget=databaseTarget;this.fingerprint=digest(text.getBytes(StandardCharsets.UTF_8));this.executable=executable;
    }
    public static TvuConfiguration read(Path path)throws IOException {return read(path,true);}
    public static TvuConfiguration inspectSource(Path path)throws IOException {return read(path,false);}
    private static TvuConfiguration read(Path path,boolean executable)throws IOException {
        SafeInputs.checkPath(path);Path source=path.toAbsolutePath().normalize();
        try {
            Config config=SafeHocon.read(source,source.getParent()).config();
            if(executable&&!config.isResolved())throw new IOException("TVU configuration contains unresolved values; supply an explicit isolated node configuration.");
            ConfigAnalyzer.ConfigEvidence evidence=new ConfigAnalyzer().analyze(source);
            if(evidence.issues().stream().anyMatch(s->s.startsWith("Unresolved")||s.contains("unsupported expressions")))throw new IOException("TVU configuration is not fully established.");
            Set<String> urls=new LinkedHashSet<>();
            for(String key:List.of("dataSourceProperties.dataSource.url","dataSourceProperties.\"dataSource.url\"","database.url","dataSource.url","\"dataSource.url\""))if(config.hasPath(key))urls.add(config.getString(key));
            if(urls.size()!=1)throw new IOException("TVU requires one explicit database connection in the selected configuration.");
            String url=urls.iterator().next();if(!url.startsWith("jdbc:"))throw new IOException("TVU database configuration is not a recognized JDBC connection.");
            if(executable&&url.matches("(?i).*[?;&](?:sslrootcert|sslcert|sslkey|truststore|keystore)=.*"))throw new IOException("The isolated database configuration references external SSL files. Their safe relocation is not established for guided TVU.");
            Set<String> values=new TreeSet<>(Comparator.comparingInt(String::length).reversed().thenComparing(Comparator.naturalOrder()));
            for(var item:config.entrySet()) {
                if(values.size()>256)throw new IOException("TVU configuration exceeds the credential-redaction limit.");
                String key=item.getKey().toLowerCase(Locale.ROOT);Object value;try{value=item.getValue().unwrapped();}catch(ConfigException.NotResolved e){if(executable)throw e;else continue;}
                if(executable&&(key.contains("datasource")||key.startsWith("database."))&&key.matches(".*(?:sslrootcert|sslcert|sslkey|truststore|keystore)(?:path|file)?[\"]?$"))throw new IOException("The isolated database configuration references external SSL files. Their safe relocation is not established for guided TVU.");
                if(Sanitizer.isSensitiveKey(key))collect(value,values);
                if(key.toLowerCase(Locale.ROOT).contains("jvmargs")&&Sanitizer.redact(Objects.toString(value)).contains("[REDACTED]"))throw new IOException("Sensitive JVM arguments must be removed from the isolated validation configuration.");
            }
            Matcher userinfo=Pattern.compile("://([^/@:]+):([^/@]+)@").matcher(url);
            if(userinfo.find()){values.add(userinfo.group(2));try{values.add(URLDecoder.decode(userinfo.group(2),StandardCharsets.UTF_8));}catch(IllegalArgumentException ignored){}}
            Matcher query=Pattern.compile("(?i)(?:[?;&])(?:password|pwd)=([^;&]+)").matcher(url);
            while(query.find()){values.add(query.group(1));try{values.add(URLDecoder.decode(query.group(1),StandardCharsets.UTF_8));}catch(IllegalArgumentException ignored){}}
            if(executable)for(var item:config.entrySet())if(item.getKey().toLowerCase(Locale.ROOT).contains("jvmargs"))for(String secret:values)if(Objects.toString(item.getValue().unwrapped()).contains(secret))throw new IOException("Sensitive values must be removed from the isolated verifier JVM arguments.");
            String rendered=config.root().render(ConfigRenderOptions.defaults().setOriginComments(false).setComments(false).setJson(true));
            if(rendered.length()>2*1024*1024)throw new IOException("TVU configuration exceeds the private-copy size limit.");
            String target=url.replaceAll("//[^/@]+@","//").split("[?;]",2)[0];
            if(!target.matches("jdbc:[a-zA-Z0-9]+://[a-zA-Z0-9.\\-_:\\[\\]]+/[a-zA-Z0-9_\\-/]+"))target="Configured from supplied node (connection details withheld)";
            return new TvuConfiguration(source,rendered,evidence,List.copyOf(values),target,executable);
        } catch(ConfigException|IllegalArgumentException e){throw new IOException("TVU node configuration could not be read safely; check its explicit database and schema settings.");}
    }
    private static void collect(Object value,Set<String> secrets)throws IOException {
        if(value instanceof Map<?,?> map){for(Object child:map.values())collect(child,secrets);}
        else if(value instanceof Collection<?> list){for(Object child:list)collect(child,secrets);}
        else if(value!=null){String text=value.toString();if(text.length()>4096)throw new IOException("TVU credential value exceeds the redaction limit.");if(!text.isEmpty()){secrets.add(text);text.lines().filter(line->!line.isEmpty()).forEach(secrets::add);}}
    }
    public ConfigAnalyzer.ConfigEvidence evidence(){return evidence;}
    public String fingerprint(){return fingerprint;}
    public String sanitizedFingerprint(){return digest(redact(text).getBytes(StandardCharsets.UTF_8));}
    public String databaseTarget(){return redact(databaseTarget);}
    public String redact(String raw){String safe=raw;for(String secret:secrets)safe=safe.replace(secret,"[REDACTED]");return Sanitizer.redact(safe).replaceAll("(?im)(\\b(?:user|username)\\s*[:=]\\s*)(?:\"[^\"\\r\\n]*\"|[^,;\\s}]+)","$1[REDACTED]");}
    public void verifyUnchanged()throws IOException {if(!read(source,executable).fingerprint.equals(fingerprint))throw new IOException("The selected TVU configuration changed after confirmation; review it again.");}
    public void writePrivate(Path destination)throws IOException {
        if(!executable)throw new IOException("A structural source snapshot cannot be used as an execution configuration.");
        try(OutputStream out=Files.newOutputStream(Files.createFile(destination,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))),StandardOpenOption.WRITE)){out.write(text.getBytes(StandardCharsets.UTF_8));}
    }
    public void validateRelationship(TvuConfiguration original,String selectedSchema)throws IOException {
        Map<String,Object> previous=original.evidence.safeSettings(),next=evidence.safeSettings();
        String vendor=Objects.toString(previous.get("databaseVendor"),"Unknown");
        if(vendor.equals("Unknown")||!vendor.equals(next.get("databaseVendor")))throw new IOException("The isolated configuration does not establish the same database vendor as the assessed node.");
        for(String key:List.of("myLegalName","nodeType","notaryMode")) {
            Object known=previous.get(key);if(known!=null&&!known.equals("Unknown")&&!known.equals(next.get(key)))throw new IOException("The isolated configuration does not match the assessed node identity or role.");
        }
        if(!selectedSchema.isEmpty()) {
            if(evidence.contradictory()&&!original.evidence.contradictory())throw new IOException("The isolated configuration introduces conflicting schema declarations.");
            String alternate=ConfigAnalyzer.selectTvuSchema(evidence,selectedSchema);
            if(!selectedSchema.equals(alternate))throw new IOException("The isolated configuration does not match the selected schema.");
        }
    }
    public static String digest(byte[] bytes){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}}
}
