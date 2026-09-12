package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import io.ledgerpreflight.evidence.BoundedPaths;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.jar.Manifest;
import java.util.zip.*;

/** Physical artifact identity only. No method bodies, nested-library expansion or class loading.
 * Every physical file has an independent metadata budget. These headers are never API evidence. */
public final class ArtifactDiscovery {
    private static final long ARCHIVE_LIMIT=1024L*1024*1024, HEADER_BUDGET=64L*1024*1024;
    private static final int ENTRY_LIMIT=100000, RESOURCE_LIMIT=65536, CLASS_LIMIT=2*1024*1024;

    public ScanResult scan(Path supplied) {
        List<JarInventory> artifacts=new ArrayList<>(); List<ScanIssue> issues=new ArrayList<>();
        try {
            Path root=supplied.toRealPath();
            var tree=BoundedPaths.discover(root,32,ENTRY_LIMIT);
            tree.issues().forEach(s->issues.add(new ScanIssue("LP-IDENTITY-001","discovery",s)));
            Set<Path> seen=new HashSet<>();
            for(Path input:tree.files()) if(isArchive(input)&&seen.add(input.toRealPath())) {
                String label=Files.isRegularFile(root)?root.getFileName().toString():root.relativize(input).toString().replace('\\','/');
                try { artifacts.add(inspect(input,label,issues)); }
                catch(IOException|RuntimeException e){issues.add(new ScanIssue("LP-IDENTITY-001",label,"Artifact identity incomplete: "+Objects.toString(e.getMessage(),"invalid archive")));}
            }
        } catch(IOException|SecurityException e){issues.add(new ScanIssue("LP-IDENTITY-001","discovery",Objects.toString(e.getMessage(),"input unavailable")));}
        artifacts.sort(Comparator.comparing(JarInventory::path));issues.sort(Comparator.comparing(ScanIssue::path).thenComparing(ScanIssue::message));
        return new ScanResult(List.copyOf(artifacts),List.copyOf(issues));
    }
    public static boolean isArchive(Path file)throws IOException {
        if(file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))return true;
        try(InputStream in=Files.newInputStream(file)){byte[] magic=in.readNBytes(4);return magic.length==4&&magic[0]=='P'&&magic[1]=='K'&&(magic[2]==3&&magic[3]==4||magic[2]==5&&magic[3]==6);}
    }
    private JarInventory inspect(Path file,String label,List<ScanIssue> issues)throws IOException {
        if(Files.size(file)>ARCHIVE_LIMIT)throw new IOException("Physical archive exceeds identity size limit");
        Map<String,String> metadata=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String,ClassInfo> classes=new TreeMap<>();List<String> signatures=new ArrayList<>(),entrypoints=new ArrayList<>();
        try(ZipFile zip=new ZipFile(file.toFile())) {
            if(zip.size()>ENTRY_LIMIT)throw new IOException("Physical archive exceeds identity entry limit");
            List<ZipEntry> entries=new ArrayList<>();Set<String> names=new HashSet<>();
            for(var enumeration=zip.entries();enumeration.hasMoreElements();) {
                ZipEntry entry=enumeration.nextElement();BytecodeScanner.validateEntry(entry.getName());
                if(!names.add(entry.getName()))throw new IOException("Duplicate archive entry");
                entries.add(entry);
            }
            // The physical manifest is inspected before any class/resource expansion.
            for(ZipEntry entry:entries)if(entry.getName().equalsIgnoreCase("META-INF/MANIFEST.MF"))
                new Manifest(new ByteArrayInputStream(read(zip,entry,RESOURCE_LIMIT))).getMainAttributes().forEach((k,v)->metadata.put(k.toString(),v.toString()));
            for(ZipEntry entry:entries) {
                String name=entry.getName(),lower=name.toLowerCase(Locale.ROOT);
                if(lower.endsWith(".class")&&!name.startsWith("META-INF/versions/")) {
                    String c=name.substring(0,name.length()-6);classes.put(c,new ClassInfo(c,null,List.of(),0,0,List.of(),List.of()));
                }
                if(lower.matches("meta-inf/[^/]+\\.(sf|rsa|dsa|ec)"))signatures.add(name);
                if(lower.contains("corda")&&(lower.endsWith("version.properties")||lower.endsWith("build-info.properties"))) {
                    Properties props=new Properties();props.load(new ByteArrayInputStream(read(zip,entry,RESOURCE_LIMIT)));
                    for(String key:List.of("Corda-Release-Version","Corda-Platform-Version","Corda-Vendor")) {
                        String alias=key.equals("Corda-Release-Version")?"releaseVersion":key.equals("Corda-Platform-Version")?"platformVersion":"vendor";
                        String value=props.getProperty(key,props.getProperty(alias,props.getProperty(key.equals("Corda-Release-Version")?"version":key.equals("Corda-Platform-Version")?"platform.version":"vendor")));
                        if(value!=null&&value.length()<=128){String prior=metadata.putIfAbsent(key,value.strip());if(prior!=null&&!prior.equals(value.strip())&&key.contains("Version"))metadata.merge("Metadata-Conflict",key,(a,b)->a+", "+b);}
                    }
                }
                if(Set.of("META-INF/services/net.corda.core.contracts.Contract","META-INF/services/net.corda.core.flows.FlowLogic").contains(name))
                    for(String line:new String(read(zip,entry,RESOURCE_LIMIT),java.nio.charset.StandardCharsets.UTF_8).split("\\R")){String provider=line.split("#",2)[0].strip().replace('.','/');if(classes.containsKey(provider)||names.contains(provider+".class"))entrypoints.add(provider);}
            }
            JarInventory preliminary=new JarInventory(label,"",metadata,classes,signatures,entrypoints);
            // Header-only fallback for pre-manifest CorDapps. No method instructions are visited.
            if(Discovery.role(preliminary).equals("UNKNOWN")) {
                long readBytes=0;
                for(ZipEntry entry:entries)if(classes.containsKey(entry.getName().replaceFirst("\\.class$",""))&&entry.getName().endsWith(".class")) {
                    try {
                        if(entry.getSize()<0||entry.getSize()>CLASS_LIMIT||readBytes+entry.getSize()>HEADER_BUDGET)throw new IOException("Legacy identity header budget reached");
                        byte[] bytes=read(zip,entry,CLASS_LIMIT);readBytes+=bytes.length;ClassReader reader=new ClassReader(bytes);
                        String name=reader.getClassName();if(!entry.getName().equals(name+".class"))throw new IOException("Class name does not match entry");
                        classes.put(name,new ClassInfo(name,reader.getSuperName(),List.of(reader.getInterfaces()),reader.getAccess(),reader.readUnsignedShort(6),List.of(),List.of()));
                        reader.accept(new ClassVisitor(Opcodes.ASM9){@Override public AnnotationVisitor visitAnnotation(String descriptor,boolean visible){if(descriptor.equals("Lnet/corda/core/serialization/CordaSerializable;"))entrypoints.add(name);return null;}},ClassReader.SKIP_CODE|ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
                    } catch(IOException|IllegalArgumentException|ArrayIndexOutOfBoundsException e){issues.add(new ScanIssue("LP-IDENTITY-001",label,"Legacy identity header inspection incomplete: "+e.getMessage()));break;}
                    catch(StackOverflowError e){issues.add(new ScanIssue("LP-IDENTITY-001",label,"Legacy identity annotation nesting exceeds parser stack capacity"));break;}
                }
            }
        }
        Collections.sort(signatures);metadata.putIfAbsent("Metadata-Origin","Physical archive manifest, entries and class headers");
        return new JarInventory(label,sha256(file),Collections.unmodifiableMap(metadata),Collections.unmodifiableMap(classes),List.copyOf(signatures),entrypoints.stream().distinct().sorted().toList());
    }
    private static byte[] read(ZipFile zip,ZipEntry entry,int limit)throws IOException {
        if(entry.getSize()>limit)throw new IOException("Identity resource exceeds bounded size");
        try(InputStream in=zip.getInputStream(entry)){byte[] bytes=in.readNBytes(limit+1);if(bytes.length>limit)throw new IOException("Identity resource exceeds bounded size");return bytes;}
    }
    private static String sha256(Path file)throws IOException {
        try(InputStream in=Files.newInputStream(file)){MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];long total=0;int n;while((n=in.read(buffer))!=-1){if((total+=n)>ARCHIVE_LIMIT)throw new IOException("Physical archive grew beyond limit");digest.update(buffer,0,n);}return HexFormat.of().formatHex(digest.digest());}
        catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
}
