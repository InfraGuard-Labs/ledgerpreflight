package io.ledgerpreflight.cli;

import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

/** Bounded, redacted capture; analysis uses final counters, not repeated progress snapshots. */
final class GuidedTvuCapture {
    private static final Pattern COUNTS=Pattern.compile("(?i)\\b(total(?:\\s+transactions?)?|transactions?\\s+total|transactions?\\s+expected|expected(?:\\s+transactions?)?|transactions?\\s+processed|processed(?:\\s+transactions?)?|passed(?:\\s+transactions?)?|succeeded|successful(?:\\s+transactions?)?|verification\\s+failed|failed(?:\\s+transactions?)?|failures)\\s*[:=]\\s*([0-9][0-9,]*)");
    private final Path directory;
    private final TvuConfiguration configuration;
    private final List<String> schemaLines=new ArrayList<>(),causes=new ArrayList<>();
    private final Map<String,Long> counters=new TreeMap<>(),counterLines=new TreeMap<>();
    private long lineNumber,totalCharacters;private int omittedBinaryEntries;private boolean counterConflict,pem;
    private final Writer writer;
    GuidedTvuCapture(Path directory,TvuConfiguration configuration)throws IOException {
        this.directory=directory;this.configuration=configuration;writer=Files.newBufferedWriter(privateFile(directory.resolve("tvu.log")),StandardCharsets.UTF_8,StandardOpenOption.WRITE);
    }
    void read(InputStream input)throws IOException {
        try(Reader reader=new InputStreamReader(input,StandardCharsets.UTF_8)) {
            char[] buffer=new char[4096];StringBuilder line=new StringBuilder();int read;
            while((read=reader.read(buffer))!=-1)for(int i=0;i<read;i++) {
                if(++totalCharacters>16L*1024*1024)throw new IOException("TVU output exceeded its bounded capture limit.");
                char ch=buffer[i];if(ch=='\n'){accept(line.toString());line.setLength(0);}else if(ch!='\r'){if(line.length()>=65536)throw new IOException("TVU output line exceeded its bounded capture limit.");line.append(ch);}
            }
            if(!line.isEmpty())accept(line.toString());
        } finally{synchronized(this){writer.flush();}}
    }
    private synchronized void accept(String raw)throws IOException {
        lineNumber++;Matcher matches=COUNTS.matcher(raw);
        while(matches.find()) {
            long number;try{number=Long.parseLong(matches.group(2).replace(",",""));}catch(NumberFormatException e){counterConflict=true;continue;}
            String key=matches.group(1).toLowerCase(Locale.ROOT);key=key.contains("expected")||key.contains("total")?"expected":key.contains("processed")?"processed":key.contains("passed")||key.contains("succeed")||key.contains("successful")?"passed":"failed";
            Long previous=counters.put(key,number);if(previous!=null&&(number<previous||key.equals("expected")&&previous!=number))counterConflict=true;counterLines.put(key,lineNumber);
        }
        String safe=configuration.redact(raw).replaceAll("[\\p{Cntrl}&&[^\\t]]","");
        if(raw.matches(".*-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE).*")){pem=true;safe="[REDACTED PRIVATE MATERIAL]";}
        else if(pem)safe="[REDACTED PRIVATE MATERIAL]";
        if(raw.contains("-----END "))pem=false;
        Sanitizer.assertSafe(safe,"TVU captured output");writer.write(safe);writer.write('\n');writer.flush();
        if(schemaLines.size()<32&&(safe.contains("HHH000205")&&safe.contains("hibernate.default_schema")||safe.toLowerCase(Locale.ROOT).contains("schema-validation: missing table")))schemaLines.add(safe);
        if(causes.size()<16&&(safe.matches("(?i).*\\b(?:[A-Za-z_$][\\w$.]*Exception|[A-Za-z_$][\\w$.]*Error)\\b.*")||safe.toLowerCase(Locale.ROOT).contains("connection refused")))causes.add(safe);
    }
    synchronized GuidedTvuExecution.Progress progress(long elapsed) {return new GuidedTvuExecution.Progress(counters.get("expected"),counters.get("processed"),counters.get("passed"),counters.get("failed"),elapsed,"In progress");}
    synchronized boolean hasFailure(){return counters.getOrDefault("failed",0L)>0;}
    synchronized boolean schemaFailure(){return schemaLines.stream().anyMatch(line->line.toLowerCase(Locale.ROOT).contains("schema-validation: missing table"));}
    synchronized boolean limitedBinaryEvidence(){return omittedBinaryEntries>0;}
    synchronized boolean databaseFailure(){return causes.stream().anyMatch(s->s.toLowerCase(Locale.ROOT).matches(".*(?:connection refused|connectionexception|authentication failed|cannot connect|could not connect).*"));}
    synchronized boolean completeCounters(){Long expected=counters.get("expected"),processed=counters.get("processed"),passed=counters.get("passed"),failed=counters.get("failed");return !counterConflict&&expected!=null&&expected>0&&processed!=null&&expected.equals(processed)&&passed!=null&&failed!=null&&passed<=Long.MAX_VALUE-failed&&passed+failed==processed;}
    synchronized Map<String,Object> counters(){return Map.of("observed",Map.copyOf(counters),"sourceLines",Map.copyOf(counterLines),"consistentFinalSummary",completeCounters(),"omittedBinaryEntries",omittedBinaryEntries);}
    synchronized void close()throws IOException {writer.close();}
    private synchronized void observeGeneratedLog(String text,int logNumber) {
        Map<String,Long> local=new TreeMap<>(),lines=new TreeMap<>();boolean conflict=false;long line=0;
        for(Iterator<String> input=text.lines().iterator();input.hasNext();) {
            String value=input.next();line++;Matcher matches=COUNTS.matcher(value);
            while(matches.find()) {
                long number;try{number=Long.parseLong(matches.group(2).replace(",",""));}catch(NumberFormatException e){conflict=true;continue;}
                String key=matches.group(1).toLowerCase(Locale.ROOT);key=key.contains("expected")||key.contains("total")?"expected":key.contains("processed")?"processed":key.contains("passed")||key.contains("succeed")||key.contains("successful")?"passed":"failed";
                Long previous=local.put(key,number);if(previous!=null&&(number<previous||key.equals("expected")&&previous!=number))conflict=true;lines.put(key,line);
            }
            if(schemaLines.size()<32&&(value.contains("HHH000205")&&value.contains("hibernate.default_schema")||value.toLowerCase(Locale.ROOT).contains("schema-validation: missing table")))schemaLines.add(value);
            if(causes.size()<16&&value.matches("(?i).*\\b(?:[A-Za-z_$][\\w$.]*Exception|[A-Za-z_$][\\w$.]*Error)\\b.*"))causes.add(value);
        }
        boolean priorComplete=completeCounters();boolean localComplete=local.keySet().containsAll(List.of("expected","processed","passed","failed"));
        // A progress-only secondary log cannot invalidate a complete console summary.
        if(!priorComplete||localComplete) {
            counterConflict|=conflict;
            for(var item:local.entrySet()) {
                Long previous=counters.get(item.getKey());if(priorComplete&&previous!=null&&!previous.equals(item.getValue())||!priorComplete&&previous!=null&&previous>item.getValue())counterConflict=true;
                counters.put(item.getKey(),item.getValue());counterLines.put("validator-"+logNumber+":"+item.getKey(),lines.get(item.getKey()));
            }
        }
    }
    synchronized Path analysis(String failureKind)throws IOException {
        StringBuilder result=new StringBuilder("LedgerPreflight guided TVU evidence\n");
        if(!counterConflict)for(String key:List.of("expected","processed","passed","failed"))if(counters.containsKey(key))result.append(switch(key){case "expected"->"Total";case "processed"->"Processed";case "passed"->"Passed";default->"Failed";}).append(": ").append(counters.get(key)).append('\n');
        if(counterConflict)result.append("TvuEvidenceException: observed transaction counters reset or conflicted; a complete run is not established.\n");
        for(String line:schemaLines)result.append(line).append('\n');
        if(!Set.of("NONE","TRANSACTION_VERIFICATION_FAILURE").contains(failureKind)) {
            result.append("TvuExecutionException: ").append(failureKind).append("; successful validation is not established.\n");
            for(String cause:causes)result.append(cause).append('\n');
        }
        Path path=privateFile(directory.resolve("analysis.log"));String safe=configuration.redact(result.toString());Sanitizer.assertSafe(safe,"TVU analysis evidence");Files.writeString(path,safe);return path;
    }
    List<Path> collectGenerated(Path workspace)throws IOException {
        List<Path> inputs=new ArrayList<>();int visited=0,archiveCount=0,logCount=0;long expanded=0;
        try(var stream=Files.walk(workspace,10)) {
            Iterator<Path> paths=stream.iterator();
            while(paths.hasNext()) {
                Path path=paths.next();if(++visited>4096)throw new IOException("TVU generated-output path limit exceeded.");
                if(Files.isSymbolicLink(path))throw new IOException("TVU generated evidence contains a symbolic link.");
                if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))continue;
                String lower=path.getFileName().toString().toLowerCase(Locale.ROOT);
                if(lower.endsWith(".zip")) {
                    if(++archiveCount>32||Files.size(path)>64L*1024*1024)throw new IOException("TVU generated archive limit exceeded.");
                    Path target=privateFile(directory.resolve("errors-"+archiveCount+".zip"));
                    try(ZipFile original=ArchiveSafety.open(path,2000);ZipOutputStream output=new ZipOutputStream(Files.newOutputStream(target,StandardOpenOption.WRITE))) {
                        Set<String> seen=new HashSet<>();int record=0,omitted=0;
                        for(var items=original.entries();items.hasMoreElements();) {
                            ZipEntry item=items.nextElement();BytecodeScanner.validateEntry(item.getName());if(!seen.add(item.getName()))throw new IOException("TVU generated archive has duplicate entries.");if(item.isDirectory())continue;
                            if(item.getSize()<0||item.getSize()>8*1024*1024||item.getSize()>1024*1024&&(item.getCompressedSize()<=0||item.getSize()/item.getCompressedSize()>200))throw new IOException("TVU generated archive expansion limit exceeded.");
                            String name=item.getName().toLowerCase(Locale.ROOT);if(!name.endsWith(".txt")&&!name.endsWith(".log")&&!name.endsWith(".json")){omitted++;omittedBinaryEntries++;continue;}
                            byte[] data;try(InputStream input=original.getInputStream(item)){data=SafeInputs.bounded(input,8*1024*1024);}CRC32 crc=new CRC32();crc.update(data);if(data.length!=item.getSize()||crc.getValue()!=item.getCrc())throw new IOException("TVU generated archive entry size or CRC is invalid.");expanded+=data.length;if(expanded>64L*1024*1024)throw new IOException("TVU generated evidence total expansion limit exceeded.");
                            String safe=configuration.redact(new String(data,StandardCharsets.UTF_8));Sanitizer.assertSafe(safe,"TVU generated error record");ZipEntry renamed=new ZipEntry(String.format(Locale.ROOT,"record-%04d.txt",++record));renamed.setTime(0);output.putNextEntry(renamed);output.write(safe.getBytes(StandardCharsets.UTF_8));output.closeEntry();
                        }
                        if(omitted>0){ZipEntry note=new ZipEntry("omitted-binary-evidence.txt");note.setTime(0);output.putNextEntry(note);output.write((omitted+" binary transaction entries were withheld. Textual diagnostics were retained; this sanitized archive has limited evidence.\n").getBytes(StandardCharsets.UTF_8));output.closeEntry();}
                    } catch(IOException e){Files.deleteIfExists(target);throw e;}
                    inputs.add(target);
                } else if(lower.endsWith(".log")||lower.endsWith(".txt")) {
                    if(++logCount>64)throw new IOException("TVU generated log count limit exceeded.");
                    String text=configuration.redact(new String(SafeInputs.read(path,8*1024*1024),StandardCharsets.UTF_8));expanded+=text.length();if(expanded>64L*1024*1024)throw new IOException("TVU generated evidence total expansion limit exceeded.");
                    Sanitizer.assertSafe(text,"TVU generated log");Path target=privateFile(directory.resolve("validator-"+logCount+".log"));Files.writeString(target,text);
                    observeGeneratedLog(text,logCount);
                }
            }
        }
        return inputs;
    }
    static Path privateFile(Path path)throws IOException {return Files.createFile(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));}
}
