package io.ledgerpreflight.bytecode;

import io.ledgerpreflight.evidence.SafeInputs;
import io.ledgerpreflight.core.ManifestMetadata;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;

/** Required-owner lookup with an independent budget; unrelated class bodies are never parsed. */
public final class TargetedRuntimeLookup {
    public record Artifact(Path path,String label,String expectedSha256) {
        public Artifact(Path path,String label){this(path,label,"");}
        public Artifact {Objects.requireNonNull(path);Objects.requireNonNull(label);expectedSha256=Objects.requireNonNullElse(expectedSha256,"");}
    }
    public enum State {FOUND,ABSENT,INCOMPLETE,AMBIGUOUS}
    public record Result(State state,ClassInfo info,List<String> origins,String detail) {
        public Result {origins=List.copyOf(origins);}
    }
    public record Limits(long maxArchiveBytes,long maxNestedBytes,long maxReadBytes,int maxEntries,
                         int maxDepth,int maxNestedArchives,int maxOwners,int maxClassBytes,
                         int maxMembers,long maxSignatureBytes,long maxMillis,int javaFeature) {
        public Limits {if(maxArchiveBytes<1||maxNestedBytes<1||maxReadBytes<1||maxEntries<1||maxDepth<0||maxNestedArchives<1||maxOwners<1||maxClassBytes<1||maxMembers<1||maxSignatureBytes<1||maxMillis<1||javaFeature<8)throw new IllegalArgumentException("Targeted lookup limits must be positive");}
        public static Limits defaults(){return new Limits(1024L*1024*1024,256L*1024*1024,2L*1024*1024*1024,500000,4,256,4096,2*1024*1024,20000,8L*1024*1024,90000,17);}
        public Limits forJava(int feature){return new Limits(maxArchiveBytes,maxNestedBytes,maxReadBytes,maxEntries,maxDepth,maxNestedArchives,maxOwners,maxClassBytes,maxMembers,maxSignatureBytes,maxMillis,feature);}
    }
    private record Stamp(long size,FileTime modified,Object key) {}
    private record Candidate(int version,ZipEntry entry) {}
    private static final class BudgetExceeded extends IOException {BudgetExceeded(String message){super(message);}}
    private static final class SignatureExceeded extends RuntimeException {SignatureExceeded(String message){super(message);}}
    private static final class Pending {
        ClassInfo info;final List<String> origins=new ArrayList<>();String failure;int definitions;
        void found(ClassInfo value,String origin){definitions++;if(origins.size()<8)origins.add(origin);if(info==null)info=value;}
    }
    private final List<Artifact> artifacts;
    private final Limits limits;
    private final Map<String,Result> cache=new TreeMap<>();
    private final Map<Path,Stamp> stamps=new HashMap<>();
    private final Set<Path> verified=new HashSet<>();
    private long bytesRead,signatureBytes,started;
    private int entries,nested;
    private String invalidated;

    public TargetedRuntimeLookup(List<Artifact> artifacts){this(artifacts,Limits.defaults());}
    public TargetedRuntimeLookup(List<Artifact> artifacts,int javaFeature){this(artifacts,Limits.defaults().forJava(javaFeature));}
    public TargetedRuntimeLookup(List<Artifact> artifacts,Limits limits){
        this.limits=Objects.requireNonNull(limits);
        this.artifacts=artifacts.stream().sorted(Comparator.comparing(Artifact::label).thenComparing(a->a.path().toString())).limit(257).toList();
        if(artifacts.size()>256)invalidated="Required runtime artifact count limit reached";
    }

    public Result lookup(String owner){
        if(!validOwner(owner))return incomplete("Invalid required owner name");
        if(invalidated!=null)return incomplete(invalidated);
        try{verifySnapshots();}catch(IOException e){invalidated=e.getMessage();return incomplete(invalidated);}
        if(!cache.containsKey(owner))prefetch(List.of(owner));
        return cache.getOrDefault(owner,incomplete("Required owner cache limit reached"));
    }

    /** Batch required owners before resolving ancestors, so a capsule is streamed once per batch. */
    public void prefetch(Collection<String> owners){
        if(invalidated!=null)return;
        if(started==0)started=System.nanoTime();
        Map<String,Pending> pending=new TreeMap<>();
        for(String owner:owners){
            if(!validOwner(owner))continue;
            if(cache.containsKey(owner)||pending.containsKey(owner))continue;
            if(cache.size()+pending.size()>=limits.maxOwners())break;
            pending.put(owner,new Pending());
        }
        if(pending.isEmpty())return;
        String failure=null;
        try{
            tick();verifySnapshots();
            if(artifacts.isEmpty())throw new IOException("No selected runtime artifacts were supplied");
            Set<Path> physical=new HashSet<>();
            for(Artifact artifact:artifacts){
                Path path=artifact.path().toAbsolutePath().normalize();
                if(!physical.add(path))continue;
                SafeInputs.checkPath(path);Stamp before=stamp(path);
                if(before.size()>limits.maxArchiveBytes())throw new BudgetExceeded("Required runtime archive size limit reached");
                stamps.putIfAbsent(path,before);
                if(!stamps.get(path).equals(before))throw new IOException("Selected runtime changed during required-symbol lookup");
                if(!verified.contains(path)&&!artifact.expectedSha256().isBlank()){
                    if(!artifact.expectedSha256().matches("(?i)[0-9a-f]{64}"))throw new IOException("Selected runtime identity hash is unavailable");
                    if(!hash(path).equalsIgnoreCase(artifact.expectedSha256()))throw new IOException("Selected runtime hash differs from discovery evidence");
                    verified.add(path);
                }
                search(path,artifact.label(),0,pending);
            }
            verifySnapshots();
        }catch(IOException|RuntimeException e){failure=Objects.toString(e.getMessage(),"Required runtime lookup could not complete");}
        for(var item:pending.entrySet()){
            Pending value=item.getValue();Result result;
            if(value.definitions>1)result=new Result(State.AMBIGUOUS,null,value.origins,"Multiple supplied components define this owner; class selection is unproven");
            else if(failure!=null||value.failure!=null)result=new Result(State.INCOMPLETE,null,value.origins,failure!=null?failure:value.failure);
            else if(value.info!=null)result=new Result(State.FOUND,value.info,value.origins,"Required owner found uniquely after complete targeted lookup");
            else result=new Result(State.ABSENT,null,List.of(),"Required owner absent after complete targeted lookup of supplied runtime artifacts");
            cache.put(item.getKey(),result);
        }
    }

    private void search(Path file,String label,int depth,Map<String,Pending> pending)throws IOException {
        tick();if(depth>limits.maxDepth())throw new BudgetExceeded("Required nested runtime depth limit reached");
        try(ZipFile zip=ArchiveSafety.open(file,limits.maxEntries())){
            Set<String> names=new HashSet<>();Map<String,Candidate> candidates=new TreeMap<>();
            boolean multi=multiRelease(zip);
            for(var enumeration=zip.entries();enumeration.hasMoreElements();){
                ZipEntry entry=enumeration.nextElement();tick();if(++entries>limits.maxEntries())throw new BudgetExceeded("Required archive entry count limit reached");
                String name=entry.getName();validateEntry(name);
                if(!names.add(name))throw new IOException("Duplicate runtime archive entry");
                if(entry.isDirectory())continue;
                String logical=name;int version=0;
                if(name.startsWith("META-INF/versions/")){
                    String tail=name.substring(18);int slash=tail.indexOf('/');if(slash<1)continue;
                    try{version=Integer.parseInt(tail.substring(0,slash));}catch(NumberFormatException e){continue;}
                    if(!multi||version<9||version>limits.javaFeature())continue;
                    logical=tail.substring(slash+1);
                }
                if(logical.endsWith(".class")){
                    String owner=logical.substring(0,logical.length()-6);
                    if(pending.containsKey(owner)){
                        Candidate prior=candidates.get(owner);if(prior==null||version>prior.version())candidates.put(owner,new Candidate(version,entry));
                    }
                }
            }
            names.clear();
            for(var item:candidates.entrySet()){
                Pending value=pending.get(item.getKey());ZipEntry entry=item.getValue().entry();
                try{
                    checkExpandedEntry(entry,limits.maxClassBytes());byte[] bytes;
                    try(InputStream in=zip.getInputStream(entry)){bytes=read(in,entry,limits.maxClassBytes());}
                    ClassInfo info=parse(bytes,item.getKey());
                    String origin=label+"!/"+entry.getName();reserve(128,origin);
                    value.found(info,origin);
                }catch(BudgetExceeded e){throw e;}
                catch(IOException|RuntimeException e){value.failure="Required class could not be inspected: "+Objects.toString(e.getMessage(),"Malformed class");}
                catch(StackOverflowError e){value.failure="Required class nesting exceeded parser stack capacity";}
            }
            // A first hit is insufficient: later components may define the same class.
            for(var enumeration=zip.entries();enumeration.hasMoreElements();){
                ZipEntry entry=enumeration.nextElement();String name=entry.getName();
                if(entry.isDirectory()||!name.toLowerCase(Locale.ROOT).endsWith(".jar"))continue;
                tick();if(++nested>limits.maxNestedArchives())throw new BudgetExceeded("Required nested archive count limit reached");
                if(depth>=limits.maxDepth())throw new BudgetExceeded("Required nested runtime depth limit reached");
                checkExpandedEntry(entry,limits.maxNestedBytes());
                Path temporary=Files.createTempFile("ledger-preflight-required-",".archive",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                try{
                    try(InputStream in=zip.getInputStream(entry);OutputStream out=Files.newOutputStream(temporary)){copy(in,out,entry,limits.maxNestedBytes());}
                    search(temporary,label+"!/"+name,depth+1,pending);
                }finally{Files.deleteIfExists(temporary);}
            }
        }
    }

    private boolean multiRelease(ZipFile zip)throws IOException {
        ZipEntry entry=zip.getEntry("META-INF/MANIFEST.MF");if(entry==null)return false;
        // Signed per-entry sections are irrelevant to version selection. The shared parser
        // bounds main headers and their continuations without expanding the whole manifest.
        try(InputStream in=new FilterInputStream(zip.getInputStream(entry)){
            @Override public int read()throws IOException {int value=super.read();if(value!=-1)charge(1);return value;}
            @Override public int read(byte[] data,int offset,int length)throws IOException {int count=in.read(data,offset,length);if(count>0)charge(count);return count;}
        }){
            return "true".equalsIgnoreCase(ManifestMetadata.read(in).get("Multi-Release"));
        }
    }
    private ClassInfo parse(byte[] bytes,String owner)throws IOException {
        ClassReader reader=new ClassReader(bytes);if(!owner.equals(reader.getClassName()))throw new IOException("Required class name differs from archive path");
        int major=reader.readUnsignedShort(6),minor=reader.readUnsignedShort(4);
        if(major<45||major>limits.javaFeature()+44||minor!=0&&(major!=45||minor>3))
            throw new IOException("Required class bytecode is unsupported by the selected runtime Java version");
        List<Member> members=new ArrayList<>();String[] faces=reader.getInterfaces();
        reserve(160,reader.getClassName(),reader.getSuperName());for(String face:faces)reserve(64,face);
        reader.accept(new ClassVisitor(Opcodes.ASM9){
            private void member(String kind,int access,String name,String descriptor){
                if(members.size()>=limits.maxMembers())throw new SignatureExceeded("Required class member count limit reached");
                reserve(96,name,descriptor);members.add(new Member(kind,name,descriptor,access));
            }
            @Override public FieldVisitor visitField(int access,String name,String descriptor,String signature,Object value){member("FIELD",access,name,descriptor);return null;}
            @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){member("METHOD",access,name,descriptor);return null;}
        },ClassReader.SKIP_CODE|ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
        members.sort(Comparator.comparing(Member::kind).thenComparing(Member::name).thenComparing(Member::descriptor));
        return new ClassInfo(reader.getClassName(),reader.getSuperName(),List.of(faces),reader.getAccess(),reader.readUnsignedShort(6),List.copyOf(members),List.of());
    }
    private void reserve(int base,String...strings){
        long amount=base;for(String value:strings)if(value!=null){if(value.length()>2048)throw new SignatureExceeded("Required symbol text size limit reached");amount+=48L+2L*value.length();}
        if(signatureBytes+amount>limits.maxSignatureBytes())throw new SignatureExceeded("Required compact symbol cache size limit reached");signatureBytes+=amount;
    }
    private void checkExpandedEntry(ZipEntry entry,long maximum)throws IOException {
        if(entry.getSize()<0||entry.getSize()>maximum)throw new IOException("Required entry byte limit reached");
        if(entry.getSize()>1024*1024&&(entry.getCompressedSize()<=0||entry.getSize()/entry.getCompressedSize()>200))throw new IOException("Required entry compression ratio limit reached");
    }
    private byte[] read(InputStream in,ZipEntry entry,int maximum)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream((int)Math.min(entry.getSize(),65536));copy(in,out,entry,maximum);return out.toByteArray();
    }
    private void copy(InputStream in,OutputStream out,ZipEntry entry,long maximum)throws IOException {
        byte[] buffer=new byte[8192];long count=0;int n;CRC32 crc=new CRC32();
        while((n=in.read(buffer))!=-1){count+=n;charge(n);if(count>maximum)throw new BudgetExceeded("Required expanded entry byte limit reached");crc.update(buffer,0,n);out.write(buffer,0,n);}
        if(count!=entry.getSize()||entry.getCrc()!=crc.getValue())throw new IOException("Required archive entry size or CRC does not match directory");
    }
    private String hash(Path path)throws IOException {
        try(InputStream in=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){
            MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];int n;
            while((n=in.read(buffer))!=-1){charge(n);digest.update(buffer,0,n);}return HexFormat.of().formatHex(digest.digest());
        }catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private void charge(int count)throws IOException {bytesRead+=count;tick();if(bytesRead>limits.maxReadBytes())throw new BudgetExceeded("Required lookup byte budget reached");}
    private void tick()throws BudgetExceeded {if(started!=0&&(System.nanoTime()-started)/1000000>limits.maxMillis())throw new BudgetExceeded("Required lookup time limit reached");}
    private void verifySnapshots()throws IOException {
        for(var entry:stamps.entrySet()){SafeInputs.checkPath(entry.getKey());if(!entry.getValue().equals(stamp(entry.getKey())))throw new IOException("Selected runtime changed during required-symbol lookup");}
    }
    private static Stamp stamp(Path path)throws IOException {BasicFileAttributes attrs=Files.readAttributes(path,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);return new Stamp(attrs.size(),attrs.lastModifiedTime(),attrs.fileKey());}
    private static boolean validOwner(String name){
        if(name==null||name.isEmpty()||name.length()>2048||name.startsWith("/")||name.endsWith("/")||name.contains("\\")||name.contains(".")||name.contains(":"))return false;
        for(int i=0;i<name.length();i++)if(Character.isISOControl(name.charAt(i)))return false;return !name.contains("//");
    }
    private static Result incomplete(String detail){return new Result(State.INCOMPLETE,null,List.of(),detail);}
}
