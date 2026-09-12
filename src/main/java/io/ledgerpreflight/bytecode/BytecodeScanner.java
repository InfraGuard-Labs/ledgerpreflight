package io.ledgerpreflight.bytecode;

import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.jar.Manifest;
import java.util.zip.*;

/** Offline inventory. Never loads, links, executes, or extracts analyzed classes. */
public final class BytecodeScanner {
    public record Limits(long maxArchiveBytes, int maxEntryBytes, long maxExpandedBytes,
                         int maxEntries, int maxDepth, int maxClasses, int maxReferences) {
        public Limits { if (maxArchiveBytes < 1 || maxEntryBytes < 1 || maxExpandedBytes < 1 || maxEntries < 1 || maxDepth < 0 || maxClasses < 1 || maxReferences < 1) throw new IllegalArgumentException("All scan limits must be positive"); }
        public static Limits defaults() { return new Limits(1024L*1024*1024,32*1024*1024,512L*1024*1024,100000,4,30000,300000); }
    }
    public record Member(String kind,String name,String descriptor,int access) { public boolean isStatic(){return (access&Opcodes.ACC_STATIC)!=0;} }
    public record Reference(String sourceMethod,String kind,String owner,String name,String descriptor,int opcode) {
        public boolean isStatic(){return opcode==Opcodes.INVOKESTATIC || opcode==Opcodes.GETSTATIC || opcode==Opcodes.PUTSTATIC;}
        public String symbol(){return owner.replace('/','.')+"."+name+descriptor;}
    }
    public record ClassInfo(String name,String superName,List<String> interfaces,int access,int majorVersion,
                            List<Member> members,List<Reference> references) {}
    public record JarInventory(String path,String sha256,Map<String,String> manifest,Map<String,ClassInfo> classes,List<String> signatureFiles) {}
    public record ScanIssue(String code,String path,String message) {}
    public record ScanResult(List<JarInventory> jars,List<ScanIssue> issues) {}
    private final Limits limits;
    public BytecodeScanner(){this(Limits.defaults());}
    public BytecodeScanner(Limits limits){this.limits=Objects.requireNonNull(limits);}
    private static final class Budget { long expanded; int entries,classes,references,files; }
    private static final class LimitException extends IOException { LimitException(String message){super(message);} }

    public ScanResult scan(Path root) {
        List<JarInventory> jars=new ArrayList<>(); List<ScanIssue> issues=new ArrayList<>(); Budget budget=new Budget();
        Path absolute=root.toAbsolutePath().normalize();
        try {
            absolute=absolute.toRealPath();
            if(Files.isRegularFile(absolute,LinkOption.NOFOLLOW_LINKS)){scanFile(absolute,absolute.getFileName().toString(),jars,issues,budget);}
            else {
                var tree=io.ledgerpreflight.evidence.BoundedPaths.discover(absolute,32,limits.maxEntries());
                for(String issue:tree.issues())issues.add(new ScanIssue("LP-INPUT-001","discovery",issue));
                Set<Path> scanned=new HashSet<>();
                for(Path input:tree.files())if(input.toString().toLowerCase(Locale.ROOT).endsWith(".jar")&&scanned.add(input.toRealPath()))scanFile(input.toRealPath(),absolute.relativize(input).toString().replace((char)92,'/'),jars,issues,budget);
            }
        }catch(IOException|UncheckedIOException|SecurityException e){issues.add(new ScanIssue("LP-INPUT-001",absolute.getFileName().toString(),e.getMessage()));}
        jars.sort(Comparator.comparing(JarInventory::path));issues.sort(Comparator.comparing(ScanIssue::path).thenComparing(ScanIssue::message));
        return new ScanResult(List.copyOf(jars),List.copyOf(issues));
    }
    private void scanFile(Path path,String label,List<JarInventory> jars,List<ScanIssue> issues,Budget budget)throws IOException {
        int start=jars.size();
        try {
            if(Files.size(path)>limits.maxArchiveBytes())throw new LimitException("Archive exceeds compressed size limit");
            try(ZipFile validated=new ZipFile(path.toFile())){if(validated.size()>limits.maxEntries())throw new LimitException("Archive entry count exceeds limit");}
            String hash;
            try(InputStream input=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){hash=hash(input);}
            try(InputStream input=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){scanArchive(input,label,hash,0,jars,issues,budget);}
        }catch(LimitException e){jars.subList(start,jars.size()).clear();issues.add(new ScanIssue("LP-INPUT-001",label,"Archive analysis limit reached: "+e.getMessage()));
            if(Files.size(path)>limits.maxArchiveBytes())return;
            try(ZipFile zip=new ZipFile(path.toFile())){if(zip.size()<=limits.maxEntries()){var entries=zip.entries();while(entries.hasMoreElements())validateEntry(entries.nextElement().getName());ZipEntry entry=zip.getEntry("META-INF/MANIFEST.MF");if(entry!=null&&entry.getSize()<=65536){byte[] data;try(InputStream in=zip.getInputStream(entry)){data=in.readNBytes(65537);}if(data.length<=65536){Map<String,String> metadata=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);new Manifest(new ByteArrayInputStream(data)).getMainAttributes().forEach((k,v)->metadata.put(k.toString(),v.toString()));metadata.put("Metadata-Origin","Outer manifest; bytecode coverage incomplete");try(InputStream in=Files.newInputStream(path)){jars.add(new JarInventory(label,hash(in),metadata,Map.of(),List.of()));}}}}}catch(IOException ignored){}}
        catch(IOException|RuntimeException e){jars.subList(start,jars.size()).clear();issues.add(new ScanIssue("LP-INPUT-001",label,"Cannot inventory archive: "+e.getMessage()));}
    }
    private record Candidate(int version,ClassInfo info) {}
    private void scanArchive(InputStream raw,String label,String hash,int depth,List<JarInventory> jars,List<ScanIssue> issues,Budget budget)throws IOException {
        if(depth>limits.maxDepth())throw new LimitException("Nested archive depth exceeds limit: "+label);
        Map<String,String> manifest=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);Map<String,List<Candidate>> candidates=new TreeMap<>();List<String> signatures=new ArrayList<>();Set<String> names=new HashSet<>();
        PushbackInputStream peek=new PushbackInputStream(new BufferedInputStream(raw),4);byte[] magic=peek.readNBytes(4);peek.unread(magic);
        if(magic.length!=4||magic[0]!='P'||magic[1]!='K'|| !((magic[2]==3&&magic[3]==4)||(magic[2]==5&&magic[3]==6)))throw new IOException("Invalid ZIP signature");
        try(ZipInputStream zip=new ZipInputStream(peek)) {
            ZipEntry entry;
            while((entry=zip.getNextEntry())!=null){
                if(++budget.entries>limits.maxEntries())throw new LimitException("Archive entry count exceeds limit");
                String name=entry.getName();validateEntry(name);
                if(!names.add(name))throw new IOException("Duplicate archive entry: "+name);
                if(entry.isDirectory()){zip.closeEntry();continue;}
                if(entry.getSize()>limits.maxEntryBytes())throw new LimitException("Archive entry exceeds size limit: "+name);
                byte[] data=readBounded(zip,budget);
                if(entry.getCompressedSize()>0&&data.length>1024*1024&&data.length/entry.getCompressedSize()>200)throw new LimitException("Archive compression ratio exceeds limit: "+name);
                String lower=name.toLowerCase(Locale.ROOT);
                if(lower.equals("meta-inf/manifest.mf")){
                    Manifest parsed=new Manifest(new ByteArrayInputStream(data));parsed.getMainAttributes().forEach((key,value)->mergeMetadata(manifest,key.toString(),value.toString()));
                }else if((lower.contains("corda") && (lower.endsWith("version.properties")||lower.endsWith("build-info.properties")))){
                    if(data.length>65536)throw new IOException("Version metadata exceeds size limit");
                    Properties properties=new Properties();properties.load(new ByteArrayInputStream(data));
                    for(String key:List.of("Corda-Release-Version","Corda-Platform-Version","Corda-Vendor")){String alias=switch(key){case "Corda-Release-Version"->"releaseVersion";case "Corda-Platform-Version"->"platformVersion";default->"vendor";};String value=properties.getProperty(key,properties.getProperty(alias,properties.getProperty(key.equals("Corda-Release-Version")?"version":key.equals("Corda-Platform-Version")?"platform.version":"vendor")));if(value!=null&&value.length()<=128){mergeMetadata(manifest,key,value.strip());manifest.put("Metadata-Origin",name);}}
                }else if(lower.endsWith(".jar")){
                    try{validateZipEnd(data);scanArchive(new ByteArrayInputStream(data),label+"!/"+name,hash(new ByteArrayInputStream(data)),depth+1,jars,issues,budget);}
                    catch(LimitException e){throw e;}catch(IOException|RuntimeException e){issues.add(new ScanIssue("LP-INPUT-001",label+"!/"+name,"Cannot inventory nested archive: "+e.getMessage()));}
                }else if(lower.endsWith(".class")) {
                    if(++budget.classes>limits.maxClasses())throw new LimitException("Class count exceeds limit");
                    int version=0;String logical=name;
                    if(name.startsWith("META-INF/versions/")){
                        String remainder=name.substring(18);int slash=remainder.indexOf('/');
                        if(slash<0)throw new IOException("Malformed multi-release entry: "+name);
                        try{version=Integer.parseInt(remainder.substring(0,slash));}catch(NumberFormatException e){throw new IOException("Malformed multi-release version: "+name,e);}
                        logical=remainder.substring(slash+1);if(version<9||version>17)continue;
                    }
                    try {
                        ClassInfo info=parse(data,budget);
                        if(!logical.equals(info.name()+".class"))throw new IOException("Class name does not match archive path: "+name);
                        candidates.computeIfAbsent(info.name(),key->new ArrayList<>()).add(new Candidate(version,info));
                    }catch(IllegalArgumentException|ArrayIndexOutOfBoundsException e){throw new IOException("Malformed/unsupported class "+name+": "+e.getMessage(),e);}
                    catch(StackOverflowError e){throw new IOException("Class constant nesting exceeds parser stack capacity: "+name,e);}
                }else if(lower.matches("meta-inf/[^/]+\\.(sf|rsa|dsa|ec)"))signatures.add(name);
                zip.closeEntry();
            }
        }
        boolean multi=manifest.entrySet().stream().anyMatch(e->e.getKey().equalsIgnoreCase("Multi-Release")&&e.getValue().equalsIgnoreCase("true"));
        Map<String,ClassInfo> classes=new TreeMap<>();
        candidates.forEach((name,values)->values.stream().filter(c->c.version()==0||multi).max(Comparator.comparingInt(Candidate::version)).ifPresent(c->classes.put(name,c.info())));
        // Capsule identity may be carried by bundled Corda metadata rather than the outer manifest.
        for(JarInventory nested:jars)if(nested.path().startsWith(label+"!/"))for(String key:List.of("Corda-Release-Version","Corda-Platform-Version","Corda-Vendor")){if(nested.manifest().containsKey("Metadata-Conflict"))manifest.put("Metadata-Conflict",nested.manifest().get("Metadata-Conflict"));String value=nested.manifest().get(key);if(value!=null){mergeMetadata(manifest,key,value);manifest.putIfAbsent("Metadata-Origin",nested.path());}}
        Collections.sort(signatures);
        jars.add(new JarInventory(label,hash,Collections.unmodifiableMap(manifest),Collections.unmodifiableMap(classes),List.copyOf(signatures)));
    }
    private static void mergeMetadata(Map<String,String> manifest,String key,String value){String previous=manifest.putIfAbsent(key,value);if(previous!=null&&!previous.equals(value)&&key.contains("Version"))manifest.merge("Metadata-Conflict",key,(a,b)->a.contains(b)?a:a+", "+b); }
    public static void validateEntry(String name)throws IOException {
        if(name.isEmpty()||name.length()>4096||name.startsWith("/")||name.contains("\\")||name.contains(":"))throw new IOException("Unsafe archive entry path");
        for(String part:name.split("/"))if(part.equals("..")||part.equals("."))throw new IOException("Archive path traversal rejected");
        for(int i=0;i<name.length();i++)if(Character.isISOControl(name.charAt(i)))throw new IOException("Control character in archive entry");
    }
    private static void validateZipEnd(byte[] bytes)throws IOException {
        for(int offset=bytes.length-22;offset>=Math.max(0,bytes.length-65557);offset--){
            if(bytes[offset]==0x50&&bytes[offset+1]==0x4b&&bytes[offset+2]==5&&bytes[offset+3]==6){
                int comment=(bytes[offset+20]&255)|((bytes[offset+21]&255)<<8);
                if(offset+22+comment!=bytes.length)continue;
                long directorySize=u32(bytes,offset+12),directoryOffset=u32(bytes,offset+16);
                int entryCount=u16(bytes,offset+10);
                if(u16(bytes,offset+4)!=0||u16(bytes,offset+6)!=0||u16(bytes,offset+8)!=entryCount||entryCount==65535||directorySize==0xffffffffL||directoryOffset==0xffffffffL)throw new IOException("Nested split/ZIP64 archive is unsupported");
                if(directoryOffset+directorySize!=offset)throw new IOException("Invalid nested ZIP central directory bounds");
                int cursor=(int)directoryOffset;
                for(int entry=0;entry<entryCount;entry++){
                    if(cursor+46>offset||u32(bytes,cursor)!=0x02014b50L)throw new IOException("Invalid nested ZIP central directory entry");
                    long local=u32(bytes,cursor+42);
                    if(local+4>directoryOffset||u32(bytes,(int)local)!=0x04034b50L)throw new IOException("Invalid nested ZIP local entry offset");
                    cursor+=46+u16(bytes,cursor+28)+u16(bytes,cursor+30)+u16(bytes,cursor+32);
                }
                if(cursor!=offset)throw new IOException("Invalid nested ZIP central directory length");
                return;
            }
        }
        throw new IOException("Truncated nested ZIP: end-of-central-directory record missing");
    }
    private static int u16(byte[] bytes,int offset){return (bytes[offset]&255)|((bytes[offset+1]&255)<<8);}
    private static long u32(byte[] bytes,int offset){return (bytes[offset]&255L)|((bytes[offset+1]&255L)<<8)|((bytes[offset+2]&255L)<<16)|((bytes[offset+3]&255L)<<24);}
    private byte[] readBounded(InputStream in,Budget budget)throws IOException {
        ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int count,total=0;
        while((count=in.read(buffer))!=-1){total+=count;budget.expanded+=count;if(total>limits.maxEntryBytes()||budget.expanded>limits.maxExpandedBytes())throw new LimitException("Expanded archive size exceeds limit");output.write(buffer,0,count);}
        return output.toByteArray();
    }
    private String hash(InputStream input)throws IOException {
        try{MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];int count;long total=0;while((count=input.read(buffer))!=-1){if((total+=count)>limits.maxArchiveBytes())throw new LimitException("Archive exceeds compressed size limit");digest.update(buffer,0,count);}return HexFormat.of().formatHex(digest.digest());}
        catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private ClassInfo parse(byte[] bytes,Budget budget)throws IOException {
        ClassReader reader=new ClassReader(bytes);List<Member> members=new ArrayList<>();Set<Reference> references=new LinkedHashSet<>();
        ClassVisitor visitor=new ClassVisitor(Opcodes.ASM9){
            void add(Reference reference){if(references.add(reference)&&++budget.references>limits.maxReferences())throw new IllegalArgumentException("Reference count exceeds limit");}
            void type(String source,Type type){if(type.getSort()==Type.METHOD){type(source,type.getReturnType());for(Type arg:type.getArgumentTypes())type(source,arg);}else if(type.getSort()==Type.ARRAY)type(source,type.getElementType());else if(type.getSort()==Type.OBJECT)add(new Reference(source,"CLASS",type.getInternalName(),"","",0));}
            void constant(String source,Object value){if(value instanceof Type t)type(source,t);else if(value instanceof Handle h){int tag=h.getTag();int opcode=switch(tag){case Opcodes.H_GETFIELD->Opcodes.GETFIELD;case Opcodes.H_GETSTATIC->Opcodes.GETSTATIC;case Opcodes.H_PUTFIELD->Opcodes.PUTFIELD;case Opcodes.H_PUTSTATIC->Opcodes.PUTSTATIC;case Opcodes.H_INVOKESTATIC->Opcodes.INVOKESTATIC;case Opcodes.H_INVOKEINTERFACE->Opcodes.INVOKEINTERFACE;case Opcodes.H_INVOKESPECIAL,Opcodes.H_NEWINVOKESPECIAL->Opcodes.INVOKESPECIAL;default->Opcodes.INVOKEVIRTUAL;};add(new Reference(source,tag<=4?"FIELD":"METHOD",h.getOwner(),h.getName(),h.getDesc(),opcode));type(source,Type.getType(h.getDesc()));}else if(value instanceof ConstantDynamic c){constant(source,c.getBootstrapMethod());type(source,Type.getType(c.getDescriptor()));for(int i=0;i<c.getBootstrapMethodArgumentCount();i++)constant(source,c.getBootstrapMethodArgument(i));}}
            @Override public void visit(int version,int access,String name,String signature,String parent,String[] interfaces){if(parent!=null)type("<class>",Type.getObjectType(parent));for(String face:interfaces)type("<class>",Type.getObjectType(face));}
            @Override public FieldVisitor visitField(int access,String name,String descriptor,String signature,Object value){members.add(new Member("FIELD",name,descriptor,access));type("<field:"+name+">",Type.getType(descriptor));constant("<field:"+name+">",value);return null;}
            @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
                members.add(new Member("METHOD",name,descriptor,access));String source=name+descriptor;type(source,Type.getMethodType(descriptor));if(exceptions!=null)for(String exception:exceptions)type(source,Type.getObjectType(exception));
                return new MethodVisitor(Opcodes.ASM9){
                    @Override public void visitMethodInsn(int opcode,String owner,String method,String desc,boolean isInterface){add(new Reference(source,"METHOD",owner,method,desc,opcode));type(source,Type.getMethodType(desc));}
                    @Override public void visitFieldInsn(int opcode,String owner,String field,String desc){add(new Reference(source,"FIELD",owner,field,desc,opcode));type(source,Type.getType(desc));}
                    @Override public void visitTypeInsn(int opcode,String name){type(source,name.startsWith("[")?Type.getType(name):Type.getObjectType(name));}
                    @Override public void visitLdcInsn(Object value){constant(source,value);}
                    @Override public void visitInvokeDynamicInsn(String name,String descriptor,Handle bootstrap,Object... args){type(source,Type.getMethodType(descriptor));constant(source,bootstrap);for(Object arg:args)constant(source,arg);}
                    @Override public void visitMultiANewArrayInsn(String descriptor,int dimensions){type(source,Type.getType(descriptor));}
                    @Override public void visitTryCatchBlock(Label start,Label end,Label handler,String type){if(type!=null)type(source,Type.getObjectType(type));}
                };
            }
        };
        reader.accept(visitor,ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
        members.sort(Comparator.comparing(Member::kind).thenComparing(Member::name).thenComparing(Member::descriptor));
        List<Reference> sorted=references.stream().sorted(Comparator.comparing(Reference::sourceMethod).thenComparing(Reference::symbol).thenComparing(Reference::kind)).toList();
        return new ClassInfo(reader.getClassName(),reader.getSuperName(),List.of(reader.getInterfaces()),reader.getAccess(),reader.readUnsignedShort(6),List.copyOf(members),sorted);
    }
}
