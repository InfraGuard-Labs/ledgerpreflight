package io.ledgerpreflight.evidence;

import io.ledgerpreflight.bytecode.ArchiveSafety;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

/** Positive schema-loading evidence from supplied TVU logs; configuration text alone is not execution proof. */
public final class TvuSchemaEvidence {
    public record Proof(String status,boolean handled,boolean mismatch,String expectedSchema,
                        List<String> configuredValues,List<String> sources,List<String> evidence) {}
    private static final Pattern LOADED=Pattern.compile("(?i)(?:^|\\s)HHH000205:\\s*loaded properties from resource hibernate\\.properties:\\s*\\{([^\\r\\n]{0,8192})}");
    private static final Pattern PROPERTY=Pattern.compile("(?:^|,\\s*)hibernate\\.default_schema\\s*=\\s*(\"(?:[^\"]|\"\"){1,512}\"|[^,}\\r\\n]{1,512})(?=\\s*(?:,|$))");
    private static final long MAX_TOTAL=64L*1024*1024;
    private static final class State {
        long bytes;int entries;boolean schemaFailure;final Set<String> values=new TreeSet<>(),sources=new TreeSet<>();
        void accept(byte[] bytes,String source)throws IOException {
            this.bytes+=bytes.length;if(this.bytes>MAX_TOTAL)throw new IOException("TVU schema evidence size limit exceeded");
            String text=new String(bytes,StandardCharsets.UTF_8);
            schemaFailure|=text.toLowerCase(Locale.ROOT).contains("schema-validation: missing table");
            Matcher lines=LOADED.matcher(text);
            while(lines.find()){
                Matcher property=PROPERTY.matcher(lines.group(1));
                while(property.find()){
                    String value=property.group(1).strip();
                    if(value.codePoints().anyMatch(Character::isISOControl))continue;
                    if(values.size()>=32||sources.size()>=64)throw new IOException("TVU schema proof count limit exceeded");
                    values.add(value);sources.add(Sanitizer.redact(source));
                }
            }
        }
    }
    public static Proof analyze(List<Path> inputs,String expected)throws IOException {
        State state=new State();TreeSet<Path> paths=new TreeSet<>();int visited=0;
        for(Path input:inputs){
            Path root=input.toAbsolutePath().normalize();
            for(Path parent=root;parent!=null;parent=parent.getParent())if(Files.isSymbolicLink(parent))throw new IOException("Symbolic links are not accepted as TVU evidence");
            if(Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)){
                try(var walk=Files.walk(root,9)){
                    for(var iterator=walk.iterator();iterator.hasNext();){
                        Path path=iterator.next();if(++visited>4096)throw new IOException("TVU evidence directory limit exceeded");
                        if(Files.isSymbolicLink(path))throw new IOException("TVU evidence contains a symbolic link");
                        if(Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS)){if(root.relativize(path).getNameCount()>=9)throw new IOException("TVU evidence directory depth exceeded");}
                        else if(evidenceFile(path.getFileName().toString()))paths.add(path);
                    }
                }
            }else{if(++visited>4096)throw new IOException("TVU evidence file count exceeded");paths.add(root);}
        }
        for(Path path:paths){
            SafeInputs.checkPath(path);
            if(!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".zip")){
                state.accept(SafeInputs.read(path,SafeInputs.MAX_TEXT_BYTES),path.getFileName().toString());continue;
            }
            if(Files.size(path)>MAX_TOTAL)throw new IOException("TVU archive size limit exceeded");
            Set<String> names=new HashSet<>();
            try(ZipFile zip=ArchiveSafety.open(path,2000)){
                for(var iterator=zip.entries();iterator.hasMoreElements();){
                    ZipEntry entry=iterator.nextElement();String name=entry.getName().replace('\\','/');
                    if(++state.entries>2000||name.startsWith("/")||name.matches("^[A-Za-z]:.*")||Arrays.asList(name.split("/")).contains("..")||!names.add(name))throw new IOException("Unsafe TVU schema archive entry");
                    if(entry.isDirectory()||!evidenceFile(name)||name.toLowerCase(Locale.ROOT).endsWith(".zip"))continue;
                    if(entry.getSize()<0||entry.getSize()>SafeInputs.MAX_TEXT_BYTES||entry.getCompressedSize()>0&&entry.getSize()/Math.max(1,entry.getCompressedSize())>1000)throw new IOException("TVU schema archive expansion limit exceeded");
                    try(InputStream stream=zip.getInputStream(entry)){byte[] data=SafeInputs.bounded(stream,SafeInputs.MAX_TEXT_BYTES);CRC32 crc=new CRC32();crc.update(data);if(data.length!=entry.getSize()||entry.getCrc()!=crc.getValue())throw new IOException("TVU schema archive integrity mismatch");state.accept(data,path.getFileName()+"!/"+name);}
                }
            }
        }
        String wanted=expected==null?"":expected;
        boolean matching=false,mismatch=false;
        if(!state.values.isEmpty()&&!wanted.isBlank()){
            String quoted=ConfigAnalyzer.quotedTvuSchema(wanted);
            matching=state.values.size()==1&&state.values.contains(quoted);mismatch=!matching;
        }
        return new Proof(state.schemaFailure?"FAILED":matching?"HANDLED":mismatch?"MISMATCH":"UNPROVEN",matching&&!state.schemaFailure,mismatch,wanted,
            List.copyOf(state.values),List.copyOf(state.sources),List.of(state.schemaFailure?"Supplied TVU evidence reports schema validation failure":matching?"Supplied Hibernate startup evidence reports the expected quoted default schema":mismatch?"Supplied Hibernate startup schema does not consistently match the intended quoted schema":"Matching Hibernate schema-loading evidence was not established","Evidence applies to the supplied TVU run; it does not establish database isolation or physical database contents"));
    }
    private static boolean evidenceFile(String name){String lower=name.toLowerCase(Locale.ROOT);return lower.endsWith(".log")||lower.endsWith(".txt")||lower.endsWith(".json")||lower.endsWith(".zip");}
    private TvuSchemaEvidence(){}
}