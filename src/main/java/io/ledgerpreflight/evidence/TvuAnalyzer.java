package io.ledgerpreflight.evidence;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

public final class TvuAnalyzer {
    public record TvuEvidence(Long expected, Long processed, Long succeeded, Long failed, int detailedRecords,
            Map<String,Integer> rootCauses, boolean schemaValidationFailure, boolean consistent,
            boolean completeSuccess, List<String> issues) { }
    private static final int MAX_ENTRIES=2000, MAX_ARCHIVE_BYTES=64*1024*1024;
    private static final Pattern COUNTS=Pattern.compile("(?i)\\b(total(?:\\s+transactions?)?|transactions?\\s+total|transactions?\\s+expected|expected(?:\\s+transactions?)?|transactions?\\s+processed|processed(?:\\s+transactions?)?|passed(?:\\s+transactions?)?|succeeded|successful(?:\\s+transactions?)?|verification\\s+failed|failed(?:\\s+transactions?)?|failures)\\s*[:=]\\s*([0-9][0-9,]*)");
    private static final Pattern ROOT=Pattern.compile("(?m)(?:^|[\\s\\[:])((?:[a-zA-Z_$][\\w$]*\\.){0,64}[A-Za-z_$][\\w$]*(?:Error|Exception))(?:\\s*:\\s*([^\\r\\n]{0,1000}))?");
    private static final class State {
        Long expected,processed,succeeded,failed; boolean schema,conflict,unknownDetails; int details; long bytes;
        TreeMap<String,Integer> roots=new TreeMap<>(); ArrayList<String> issues=new ArrayList<>(); HashSet<String> seen=new HashSet<>();
        void accept(String text, String recordId) throws IOException {
            bytes+=text.length(); if(bytes>MAX_ARCHIVE_BYTES) throw new IOException("TVU evidence total size limit exceeded");
            Matcher m=COUNTS.matcher(text);
            while(m.find()) {
                long n; try { n=Long.parseLong(m.group(2).replace(",","")); } catch(NumberFormatException e) { throw new IOException("TVU counter exceeds supported range"); }
                String k=m.group(1).toLowerCase(Locale.ROOT); Long prior;
                if(k.contains("expected")||k.contains("total")) { prior=expected; expected=n; }
                else if(k.contains("processed")) { prior=processed; processed=n; }
                else if(k.contains("succeed")||k.contains("successful")||k.contains("passed")) { prior=succeeded; succeeded=n; }
                else { prior=failed; failed=n; }
                if(prior!=null && prior!=n) conflict=true;
            }
            schema |= text.toLowerCase(Locale.ROOT).contains("schema-validation: missing table");
            String root=null; Matcher err=ROOT.matcher(text);
            while(err.find()) {
                String candidate=err.group(1)+(err.group(2)==null?"":": "+err.group(2).strip());
                root=Sanitizer.redact(candidate).replaceAll("(?i)\\b[0-9a-f]{32,}\\b", "[TRANSACTION-ID]");
                if(recordId==null) roots.putIfAbsent(root,0);
            }
            if(recordId!=null && root!=null && seen.add(recordId+":"+digest(text))) { details++; roots.merge(root,1,Integer::sum); }
            if(recordId!=null && root==null) unknownDetails=true;
        }
    }
    public TvuEvidence analyze(List<Path> paths) throws IOException {
        State s=new State();
        for(Path path: expand(paths)) {
            SafeInputs.checkPath(path);
            if(path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".zip")) readZip(path,s);
            else s.accept(new String(SafeInputs.read(path,SafeInputs.MAX_TEXT_BYTES),StandardCharsets.UTF_8),null);
        }
        boolean consistent=!s.conflict;
        if(s.processed!=null && s.succeeded!=null && s.failed!=null)
            consistent &= s.succeeded<=Long.MAX_VALUE-s.failed && s.succeeded+s.failed==s.processed;
        if(s.expected!=null && s.processed!=null) consistent &= s.expected.equals(s.processed);
        if(s.failed!=null) consistent &= s.details<=s.failed;
        if(!consistent) s.issues.add("TVU summaries conflict, are incomplete, or do not reconcile with supplied detailed records");
        if(s.failed!=null && s.failed>s.details) s.issues.add(s.failed+" failures reported; "+s.details+" detailed failure records supplied; root-cause counts cover only supplied records");
        if(s.unknownDetails) s.issues.add("Error archive contains records with unrecognized failure format; manual review is required");
        boolean success=!paths.isEmpty() && consistent && !s.schema && !s.unknownDetails && s.roots.isEmpty() && s.expected!=null && s.expected>0 &&
            s.processed!=null && s.succeeded!=null && s.failed!=null && s.failed==0 && s.expected.equals(s.processed) && s.processed.equals(s.succeeded);
        if(!paths.isEmpty() && (s.expected==null||s.processed==null||s.succeeded==null||s.failed==null)) s.issues.add("Complete TVU summary counters were not found; success is not established");
        return new TvuEvidence(s.expected,s.processed,s.succeeded,s.failed,s.details,Collections.unmodifiableMap(s.roots),s.schema,consistent,success,List.copyOf(s.issues));
    }
    private static List<Path> expand(List<Path> paths) throws IOException {
        TreeSet<Path> files=new TreeSet<>(Comparator.comparing(Path::toString)); int visited=0;
        for(Path input:paths) {
            Path absolute=input.toAbsolutePath().normalize();
            for(Path p=absolute;p!=null;p=p.getParent()) if(Files.isSymbolicLink(p)) throw new IOException("Symbolic links are not accepted as TVU evidence");
            if(Files.isDirectory(absolute,LinkOption.NOFOLLOW_LINKS)) {
                try(var walk=Files.walk(absolute,9)) {
                    Iterator<Path> iter=walk.iterator();
                    while(iter.hasNext()) {
                        Path child=iter.next(); if(++visited>4096) throw new IOException("TVU directory entry limit exceeded");
                        if(Files.isSymbolicLink(child)) throw new IOException("TVU directory contains a symbolic link");
                        if(Files.isDirectory(child,LinkOption.NOFOLLOW_LINKS)) {
                            if(absolute.relativize(child).getNameCount()>=9) throw new IOException("TVU directory depth limit exceeded");
                            continue;
                        }
                        String name=child.getFileName().toString().toLowerCase(Locale.ROOT);
                        if(name.endsWith(".txt")||name.endsWith(".log")||name.endsWith(".zip")||name.endsWith(".json")) files.add(child);
                    }
                } catch(UncheckedIOException e) { throw new IOException("TVU evidence directory could not be read safely",e.getCause()); }
            } else { if(++visited>4096) throw new IOException("TVU input count limit exceeded"); files.add(absolute); }
        }
        return List.copyOf(files);
    }
    private static void readZip(Path path,State s) throws IOException {
        if(Files.size(path)>MAX_ARCHIVE_BYTES) throw new IOException("TVU archive compressed size limit exceeded");
        int count=0; HashSet<String> names=new HashSet<>();
        try(ZipFile zip=new ZipFile(path.toFile())) {
            Enumeration<? extends ZipEntry> entries=zip.entries();
            while(entries.hasMoreElements()) {
                ZipEntry entry=entries.nextElement(); if(++count>MAX_ENTRIES) throw new IOException("TVU archive entry limit exceeded");
                String name=entry.getName().replace('\\','/');
                if(name.startsWith("/") || name.matches("^[A-Za-z]:.*") || Arrays.asList(name.split("/")).contains("..") || !names.add(name)) throw new IOException("Unsafe or duplicate TVU archive entry");
                if(entry.isDirectory()) continue;
                if(entry.getSize()>SafeInputs.MAX_TEXT_BYTES || (entry.getSize()>1024*1024 && entry.getCompressedSize()>0 && entry.getSize()/entry.getCompressedSize()>200)) throw new IOException("TVU archive bomb limit exceeded");
                String lower=name.toLowerCase(Locale.ROOT);
                if(!(lower.endsWith(".txt")||lower.endsWith(".log")||lower.endsWith(".json"))) { s.unknownDetails=true; s.issues.add("Non-text archive evidence omitted"); continue; }
                try(InputStream in=zip.getInputStream(entry)) { s.accept(new String(SafeInputs.bounded(in,SafeInputs.MAX_TEXT_BYTES),StandardCharsets.UTF_8),name); }
            }
        } catch(ZipException e) { throw new IOException("Malformed TVU ZIP archive"); }
    }
    private static String digest(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable",e); }
    }
}
