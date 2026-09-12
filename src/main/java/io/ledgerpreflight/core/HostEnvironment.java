package io.ledgerpreflight.core;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import io.ledgerpreflight.evidence.SafeInputs;
import io.ledgerpreflight.evidence.Sanitizer;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/** Separates this analyzer process from operator-supplied source/target server evidence. */
public record HostEnvironment(String executionOs,String executionArch,String analyzerJava,
        String currentJava,String currentJavaSource,String targetRequiredJava,String plannedTargetJava,
        String targetJavaReadiness,String sourceHostOs,String confidence,List<String> observations) {
    public HostEnvironment { observations=List.copyOf(observations); }
    private static final int MAX_EVIDENCE=16*1024;
    private static final Set<String> FIELDS=Set.of("sourceHostOs","currentJava","plannedTargetJava");
    private static final Pattern JAVA=Pattern.compile("^(?:1\\.)?([0-9]{1,3})(?:\\.([0-9]{1,6}))?(?:\\.([0-9]{1,6}))?(?:[._+\\-][A-Za-z0-9.+_-]{1,80})?$");

    /** /etc/os-release describes the execution namespace; it never proves the mounted node's OS. */
    public static HostEnvironment inspect(Path evidence)throws IOException {
        String release="";
        Path file=Path.of("/etc/os-release");
        if(Files.exists(file)) {
            // Distribution-owned os-release commonly links to /usr/lib/os-release. Only this fixed
            // OS metadata path permits a bounded followed read; supplied evidence rejects symlinks.
            try(InputStream input=Files.newInputStream(file)){release=new String(SafeInputs.bounded(input,MAX_EVIDENCE),StandardCharsets.UTF_8);}
            catch(IOException|SecurityException e){release="";}
        }
        return inspect(evidence,System.getenv(),release,System.getProperty("os.name","UNKNOWN"),System.getProperty("os.arch","UNKNOWN"),System.getProperty("java.version","UNKNOWN"));
    }

    /** Explicit process metadata arguments enable deterministic tests without running host commands. */
    public static HostEnvironment inspect(Path evidence,Map<String,String> environment,String osRelease,
            String osName,String arch,String javaVersion)throws IOException {
        Map<String,String> supplied=load(evidence);List<String> notes=new ArrayList<>();
        String os=executionOs(osRelease,osName),current="UNKNOWN",currentSource="NOT_SUPPLIED";
        String launcher=environment.get("LP_HOST_JAVA_VERSION");
        if(launcher!=null&&!launcher.isBlank()){current=clean(launcher);currentSource="LAUNCHER_ENVIRONMENT";notes.add("Launcher Java describes the launcher's environment, not necessarily the current node server or its configured JVM.");}
        if(supplied.containsKey("currentJava")){current=supplied.get("currentJava");currentSource="USER_SUPPLIED_SOURCE_HOST";}
        String sourceOs=supplied.getOrDefault("sourceHostOs","UNKNOWN"),readiness="UNVERIFIED";
        String planned=supplied.get("plannedTargetJava");
        if(planned!=null){
            Matcher matcher=JAVA.matcher(planned);
            if(!matcher.matches())throw new IOException("plannedTargetJava must be a Java version such as 17.0.12");
            int major=Integer.parseInt(matcher.group(1));
            if(planned.toLowerCase(Locale.ROOT).matches(".*(?:ea|internal|snapshot).*"))readiness="UNVERIFIED";
            else if(major!=17)readiness="INCOMPATIBLE";
            else if(matcher.group(2)==null||matcher.group(3)==null)readiness="JAVA_17_REPORTED_PATCH_UNVERIFIED";
            else {int minor=Integer.parseInt(matcher.group(2)),patch=Integer.parseInt(matcher.group(3));readiness=minor==0&&patch>=9?"USER_REPORTED_COMPATIBLE":"INCOMPATIBLE";}
            notes.add("Planned target Java "+planned+" is user-supplied evidence; installation, provenance, support and effective runtime have not been independently verified.");
        }
        notes.add("Execution OS and analyzer Java belong to this process/container. They do not establish the current node server's OS or Java.");
        notes.add("A bundled analyzer Java 17 can assess a Java 8 environment without changing its default Java. Target Corda 4.12 still requires its own supported Java 17 deployment.");
        if(osRelease==null||osRelease.isBlank())notes.add("OS release metadata was unavailable; execution OS falls back to the JVM os.name property.");
        return new HostEnvironment(os,clean(arch),clean(javaVersion),current,currentSource,"17",Objects.toString(planned,"UNKNOWN"),readiness,sourceOs,evidence==null?"EXECUTION_OBSERVED_SOURCE_UNVERIFIED":"USER_SUPPLIED",notes);
    }

    private static Map<String,String> load(Path path)throws IOException {
        if(path==null)return Map.of();
        ObjectMapper mapper=new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(4).maxStringLength(512).maxNumberLength(20).build()).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        JsonNode data=mapper.readTree(SafeInputs.read(path,MAX_EVIDENCE));
        if(data==null||!data.isObject())throw new IOException("Host environment evidence must be a JSON object");
        Map<String,String> result=new TreeMap<>();Iterator<Map.Entry<String,JsonNode>> fields=data.fields();
        while(fields.hasNext()){
            var field=fields.next();
            if(!FIELDS.contains(field.getKey()))throw new IOException("Unknown host environment evidence field");
            if(!field.getValue().isTextual()||field.getValue().asText().isBlank()||field.getValue().asText().length()>512||field.getValue().asText().chars().anyMatch(Character::isISOControl))throw new IOException("Host environment evidence values must be bounded nonempty strings without control characters");
            result.put(field.getKey(),clean(field.getValue().asText()));
        }
        if(result.isEmpty())throw new IOException("Host environment evidence must supply at least one supported field");
        return result;
    }
    private static String executionOs(String release,String fallback){
        if(release!=null&&release.length()<=MAX_EVIDENCE){
            Map<String,String> values=new HashMap<>();
            for(String line:release.split("\\R")){int equals=line.indexOf('=');if(equals<1)continue;String key=line.substring(0,equals);if(!Set.of("PRETTY_NAME","NAME","VERSION_ID").contains(key))continue;String value=line.substring(equals+1).strip();if(value.length()>=2&&((value.startsWith("\"")&&value.endsWith("\""))||(value.startsWith("'")&&value.endsWith("'"))))value=value.substring(1,value.length()-1);values.put(key,clean(value));}
            if(values.containsKey("PRETTY_NAME"))return values.get("PRETTY_NAME");
            if(values.containsKey("NAME"))return values.get("NAME")+(values.containsKey("VERSION_ID")?" "+values.get("VERSION_ID"):"");
        }
        return clean(fallback);
    }
    private static String clean(String value){if(value==null||value.isBlank())return "UNKNOWN";String bounded=value.length()>512?value.substring(0,512):value;return Sanitizer.redact(bounded.replaceAll("[\\p{Cntrl}]"," ")).strip();}
}
