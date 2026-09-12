package io.ledgerpreflight.evidence;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;

/** Packages generated textual evidence only. Never traverses an input directory. */
public final class SupportBundle {
    private static final ObjectMapper JSON=new ObjectMapper();
    private static final Set<String> ALLOWED=Set.of("README.txt","summary.txt","summary.html","assessment.json",
        "environment.json","upgrade-kit.json","cordapps-current.json","cordapps-target.json","runtime-api-delta.json",
        "node-discovery.json","discovery.json","other-jars-current.json","other-jars-target.json","internal-api-usage.json","legacy-jars-analysis.json","classpath-analysis.json","schema-analysis.json",
        "tvu-summary.json","findings.json","reproduction.txt","sanitized-node.conf");
    public Path create(Path output, Map<String,String> permittedEvidence) throws IOException {
        if(permittedEvidence.isEmpty()) throw new IOException("Support bundle has no evidence");
        TreeMap<String,byte[]> entries=new TreeMap<>(); long total=0;
        for(var entry:permittedEvidence.entrySet()) {
            if(!ALLOWED.contains(entry.getKey())) throw new IOException("Support bundle entry is not allowlisted");
            String source=Objects.requireNonNull(entry.getValue());
            if(source.length()>SafeInputs.MAX_TEXT_BYTES) throw new IOException("Support bundle entry size limit exceeded");
            String safe;
            if(entry.getKey().endsWith(".json")) {
                try { safe=JSON.writerWithDefaultPrettyPrinter().writeValueAsString(sanitizeJson(JSON.readTree(source))); }
                catch(com.fasterxml.jackson.core.JsonProcessingException e) { throw new IOException("Support bundle JSON entry is malformed: "+entry.getKey()); }
            } else safe=Sanitizer.redact(source);
            Sanitizer.assertSafe(safe,entry.getKey());
            byte[] bytes=safe.getBytes(StandardCharsets.UTF_8); total+=bytes.length;
            if(bytes.length>SafeInputs.MAX_TEXT_BYTES || total>32*1024*1024) throw new IOException("Support bundle size limit exceeded");
            entries.put(entry.getKey(),bytes);
        }
        StringBuilder checksums=new StringBuilder();
        for(var entry:entries.entrySet()) checksums.append(sha256(entry.getValue())).append("  ").append(entry.getKey()).append('\n');
        entries.put("checksums.sha256",checksums.toString().getBytes(StandardCharsets.UTF_8));
        Path absolute=output.toAbsolutePath().normalize();
        for(Path p=absolute;p!=null;p=p.getParent()) if(Files.isSymbolicLink(p)) throw new IOException("Support bundle output contains symbolic link");
        Files.createDirectories(absolute.getParent());
        Path temp=Files.createTempFile(absolute.getParent(),".ledgerpreflight-bundle-",".tmp");
        try {
            try(ZipOutputStream zip=new ZipOutputStream(Files.newOutputStream(temp))) {
                for(var entry:entries.entrySet()) {
                    ZipEntry ze=new ZipEntry(entry.getKey()); ze.setTime(0); zip.putNextEntry(ze); zip.write(entry.getValue()); zip.closeEntry();
                }
            }
            // Reopen the completed temporary ZIP and scan its actual entries before publication.
            try(ZipInputStream zip=new ZipInputStream(Files.newInputStream(temp))) {
                ZipEntry entry;while((entry=zip.getNextEntry())!=null) {
                    byte[] bytes=SafeInputs.bounded(zip,SafeInputs.MAX_TEXT_BYTES);
                    Sanitizer.assertSafe(new String(bytes,StandardCharsets.UTF_8),entry.getName());
                    if(!Arrays.equals(bytes,entries.get(entry.getName())))throw new IOException("Support package integrity validation failed");
                }
            }
            // Refuse overwrite; an existing bundle can be separately reviewed or removed.
            Files.move(temp,absolute);
            return absolute;
        } finally { Files.deleteIfExists(temp); }
    }
    private static JsonNode sanitizeJson(JsonNode node) throws IOException {
        if(node==null) throw new IOException("Support bundle JSON entry is empty");
        if(node.isTextual()) return TextNode.valueOf(Sanitizer.redact(node.textValue()));
        if(node.isObject()) {
            ObjectNode result=JSON.createObjectNode(); var fields=node.fields();
            while(fields.hasNext()) { var field=fields.next(); result.set(Sanitizer.redact(field.getKey()),Sanitizer.isSensitiveKey(field.getKey())?TextNode.valueOf("[REDACTED]"):sanitizeJson(field.getValue())); }
            return result;
        }
        if(node.isArray()) { ArrayNode result=JSON.createArrayNode(); for(JsonNode value:node) result.add(sanitizeJson(value)); return result; }
        return node;
    }
    private static String sha256(byte[] data) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }
        catch(NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable",e); }
    }
}
