package io.ledgerpreflight.bytecode;

import org.objectweb.asm.*;
import io.ledgerpreflight.core.*;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import java.util.zip.*;

/** Offline bounded symbols. Classes are never executed; nested archives are spooled sequentially. */
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
    public record JarInventory(String path,String sha256,Map<String,String> manifest,Map<String,ClassInfo> classes,List<String> signatureFiles,List<String> cordappEntrypoints) {
        public JarInventory(String path,String sha256,Map<String,String> manifest,Map<String,ClassInfo> classes,List<String> signatureFiles){this(path,sha256,manifest,classes,signatureFiles,List.of());}
    }
    public record ScanIssue(String code,String path,String message) {}
    public record ScanResult(List<JarInventory> jars,List<ScanIssue> issues) {}
    private final Limits limits;
    // A scanner belongs to one assessment. This ceiling spans current/target/override scans.
    private long retainedBytes;
    public static final long MAX_RETAINED_BYTES=24L*1024*1024;
    public BytecodeScanner(){this(Limits.defaults());}
    public BytecodeScanner(Limits limits){this.limits=Objects.requireNonNull(limits);}
    private static final class Budget {long expanded,retained;int entries,classes,references,symbols,nested;}
    private static final class LimitException extends IOException {LimitException(String message){super(message);}}
    private static final class SymbolLimit extends RuntimeException {SymbolLimit(String message){super(message);}}
    private void reserve(Budget budget,int overhead,String...values){
        long amount=overhead;for(String value:values)if(value!=null){if(value.length()>2048)throw new SymbolLimit("Symbol text size limit reached");amount+=48L+2L*value.length();}
        if(++budget.symbols>120000||retainedBytes+amount>MAX_RETAINED_BYTES)throw new SymbolLimit("Retained symbol memory/count limit reached");
        retainedBytes+=amount;budget.retained+=amount;
    }
    public ScanResult scan(Path root){return scan(root,null);}
    public ScanResult scanLayout(Path root,ScanResult identity){return scan(root,identity);}
    private ScanResult scan(Path supplied,ScanResult identity){
        List<JarInventory> jars=new ArrayList<>();List<ScanIssue> issues=new ArrayList<>();
        try{
            Path root=supplied.toRealPath();Set<Path> seen=new HashSet<>();
            if(identity!=null){
                for(JarInventory artifact:identity.jars()){
                    String role=Discovery.role(artifact);if(role.equals("TVU"))continue;
                    Path file=Files.isRegularFile(root)?root:root.resolve(artifact.path());
                    boolean instructions=Set.of("CORDAPP","LEGACY","LEGACY_CONTRACT").contains(role);
                    if(seen.add(file.toRealPath()))scanFile(file,artifact.path(),jars,issues,instructions);
                }
            }else{
                var tree=io.ledgerpreflight.evidence.BoundedPaths.discover(root,32,limits.maxEntries());
                tree.issues().forEach(i->issues.add(new ScanIssue("LP-INPUT-001","discovery",i)));
                for(Path p:tree.files())if(ArtifactDiscovery.isArchive(p)&&seen.add(p.toRealPath())){
                    String label=Files.isRegularFile(root)?root.getFileName().toString():root.relativize(p).toString().replace((char)92,'/');
                    scanFile(p,label,jars,issues,true);
                }
            }
        }catch(IOException|SecurityException e){issues.add(new ScanIssue("LP-INPUT-001","discovery",Objects.toString(e.getMessage(),"Input unavailable")));}
        jars.sort(Comparator.comparing(JarInventory::path));issues.sort(Comparator.comparing(ScanIssue::path).thenComparing(ScanIssue::message));
        return new ScanResult(List.copyOf(jars),List.copyOf(issues));
    }
    private void scanFile(Path path,String label,List<JarInventory> jars,List<ScanIssue> issues,boolean instructions){
        Budget budget=new Budget();int start=jars.size(),issueStart=issues.size();
        try{
            if(Files.size(path)>limits.maxArchiveBytes())throw new LimitException("Compressed archive size limit reached");
            scanArchive(path,label,hash(path),0,jars,issues,budget,instructions);
        }catch(IOException|RuntimeException e){
            jars.subList(start,jars.size()).clear();issues.subList(issueStart,issues.size()).clear();retainedBytes-=budget.retained;
            issues.add(new ScanIssue("LP-INPUT-001",label,"Analysis incomplete: "+Objects.toString(e.getMessage(),"Invalid archive")+"; inspected entries="+budget.entries+", classes="+budget.classes+", references="+budget.references+". Remaining symbols and entries were not analyzed."));
            if(e instanceof LimitException||e instanceof SymbolLimit)try(ZipFile zip=ArchiveSafety.open(path,limits.maxEntries())){
                for(var entries=zip.entries();entries.hasMoreElements();)validateEntry(entries.nextElement().getName());
                ZipEntry mf=zip.getEntry("META-INF/MANIFEST.MF");if(mf!=null)try(InputStream in=zip.getInputStream(mf)){
                    Map<String,String> metadata=ManifestMetadata.read(in);metadata.put("Metadata-Origin","Physical manifest; compatibility analysis incomplete");
                    jars.add(new JarInventory(label,hash(path),metadata,Map.of(),List.of()));
                }
            }catch(IOException ignored){}
        }
    }
    private record Candidate(int version,ClassInfo info){}
    private void scanArchive(Path file,String label,String hash,int depth,List<JarInventory> jars,List<ScanIssue> issues,Budget budget,boolean instructions)throws IOException {
        if(depth>limits.maxDepth())throw new LimitException("Nested archive depth limit reached");
        reserve(budget,256,label,hash);
        Map<String,String> manifest=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String,Candidate> candidates=new TreeMap<>();List<String> signatures=new ArrayList<>(),entrypoints=new ArrayList<>();Set<String> names=new HashSet<>();
        try(ZipFile zip=ArchiveSafety.open(file,limits.maxEntries())){
            ZipEntry mf=zip.getEntry("META-INF/MANIFEST.MF");if(mf!=null)try(InputStream in=zip.getInputStream(mf)){manifest.putAll(ManifestMetadata.read(in));}
            boolean multi="true".equalsIgnoreCase(manifest.get("Multi-Release"));
            for(var enumeration=zip.entries();enumeration.hasMoreElements();){
                ZipEntry entry=enumeration.nextElement();String name=entry.getName(),lower=name.toLowerCase(Locale.ROOT);
                if(++budget.entries>limits.maxEntries())throw new LimitException("Archive entry count limit reached");
                validateEntry(name);if(!names.add(name))throw new IOException("Duplicate archive entry");
                if(entry.isDirectory()||lower.equals("meta-inf/manifest.mf"))continue;
                if(entry.getSize()<0||entry.getSize()>limits.maxEntryBytes())throw new LimitException("Entry size limit reached: "+name);
                if(entry.getCompressedSize()>0&&entry.getSize()>1024*1024&&entry.getSize()/entry.getCompressedSize()>200)throw new LimitException("Archive compression ratio limit reached: "+name);
                if(lower.endsWith(".jar")){
                    if(++budget.nested>128)throw new LimitException("Nested archive count limit reached");
                    if(depth>=limits.maxDepth())throw new LimitException("Nested archive depth limit reached");
                    Path temporary=Files.createTempFile("ledger-preflight-", ".archive",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                    try{
                        try(InputStream in=zip.getInputStream(entry);OutputStream out=Files.newOutputStream(temporary)){copyBounded(in,out,budget,limits.maxEntryBytes());}
                        try{scanArchive(temporary,label+"!/"+name,hash(temporary),depth+1,jars,issues,budget,instructions);}
                        catch(LimitException|SymbolLimit e){throw e;}
                        catch(IOException|RuntimeException e){String message="Nested archive incomplete: "+e.getMessage();reserve(budget,128,label+"!/"+name,message);issues.add(new ScanIssue("LP-INPUT-001",label+"!/"+name,message));}
                    }finally{Files.deleteIfExists(temporary);}
                }else if(lower.endsWith(".class")){
                    if(++budget.classes>limits.maxClasses())throw new LimitException("Class count limit reached");
                    int version=0;String logical=name;
                    if(name.startsWith("META-INF/versions/")){
                        String tail=name.substring(18);int slash=tail.indexOf('/');if(slash<0)throw new IOException("Malformed multi-release entry");
                        version=Integer.parseInt(tail.substring(0,slash));logical=tail.substring(slash+1);if(!multi||version<9||version>17)continue;
                    }
                    int classLimit=Math.min(2*1024*1024,limits.maxEntryBytes());
                    if(entry.getSize()>classLimit)throw new LimitException("Class byte size limit reached: "+name);
                    byte[] data=read(zip,entry,budget,classLimit);
                    try{
                        ClassInfo info=parse(data,budget,instructions);
                        if(!logical.equals(info.name()+".class"))throw new IOException("Class name does not match archive path: "+name);
                        Candidate prior=candidates.get(info.name());if(prior==null||version>prior.version())candidates.put(info.name(),new Candidate(version,info));
                    }catch(StackOverflowError e){throw new IOException("Class constant nesting exceeds parser stack capacity: "+name);}
                }else if(lower.contains("corda")&&(lower.endsWith("version.properties")||lower.endsWith("build-info.properties"))){
                    Properties p=new Properties();p.load(new ByteArrayInputStream(read(zip,entry,budget,65536)));
                    if(!manifest.containsKey("Application-ID"))for(String key:List.of("Corda-Release-Version","Corda-Platform-Version","Corda-Vendor")){
                        String alias=key.equals("Corda-Release-Version")?"releaseVersion":key.equals("Corda-Platform-Version")?"platformVersion":"vendor";
                        String value=p.getProperty(key,p.getProperty(alias,p.getProperty(key.equals("Corda-Release-Version")?"version":key.equals("Corda-Platform-Version")?"platform.version":"vendor")));
                        if(value!=null&&value.length()<=128)mergeMetadata(manifest,key,value.strip());
                    }
                }else if(Set.of("META-INF/services/net.corda.core.contracts.Contract","META-INF/services/net.corda.core.flows.FlowLogic").contains(name)){
                    for(String line:new String(read(zip,entry,budget,65536),java.nio.charset.StandardCharsets.UTF_8).split("\\R")){
                        String provider=line.split("#",2)[0].strip().replace('.','/');if(!provider.isBlank()){reserve(budget,64,provider);entrypoints.add(provider);}
                    }
                }else{
                    try(InputStream in=zip.getInputStream(entry)){copyBounded(in,OutputStream.nullOutputStream(),budget,limits.maxEntryBytes());}
                    if(lower.matches("meta-inf/[^/]+\\.(sf|rsa|dsa|ec)")){reserve(budget,64,name);signatures.add(name);}
                }
            }
        }
        Map<String,ClassInfo> classes=new TreeMap<>();candidates.forEach((k,v)->classes.put(k,v.info()));
        boolean ownRelease=List.of("Corda-Release-Version","Corda-Version","Application-Version").stream().anyMatch(manifest::containsKey);
        boolean ownPlatform=manifest.containsKey("Corda-Platform-Version")||manifest.containsKey("Platform-Version");
        for(JarInventory nested:jars)if(nested.path().startsWith(label+"!/"))for(String key:List.of("Corda-Release-Version","Corda-Platform-Version","Corda-Vendor")){
            if(key.equals("Corda-Release-Version")&&ownRelease||key.equals("Corda-Platform-Version")&&ownPlatform||key.equals("Corda-Vendor")&&manifest.containsKey(key))continue;
            String value=nested.manifest().get(key);if(value!=null)mergeMetadata(manifest,key,value);
        }
        for(var attribute:manifest.entrySet())reserve(budget,96,attribute.getKey(),attribute.getValue());
        Collections.sort(signatures);jars.add(new JarInventory(label,hash,Collections.unmodifiableMap(manifest),Collections.unmodifiableMap(classes),List.copyOf(signatures),entrypoints.stream().filter(classes::containsKey).distinct().sorted().toList()));
    }
    private static void mergeMetadata(Map<String,String> map,String key,String value){String prior=map.putIfAbsent(key,value);if(prior!=null&&!prior.equals(value)&&key.contains("Version"))map.merge("Metadata-Conflict",key,(a,b)->a.contains(b)?a:a+", "+b);}
    public static void validateEntry(String name)throws IOException {
        if(name.isEmpty()||name.length()>4096||name.startsWith("/")||name.contains("\\")||name.contains(":"))throw new IOException("Unsafe archive entry path");
        for(String part:name.split("/"))if(part.equals("..")||part.equals("."))throw new IOException("Archive path traversal rejected");
        for(int i=0;i<name.length();i++)if(Character.isISOControl(name.charAt(i)))throw new IOException("Control character in archive entry");
    }
    private void copyBounded(InputStream in,OutputStream out,Budget budget,int limit)throws IOException {
        byte[] buffer=new byte[8192];long total=0;int count;
        while((count=in.read(buffer))!=-1){total+=count;budget.expanded+=count;if(total>limit||budget.expanded>limits.maxExpandedBytes())throw new LimitException("Expanded byte limit reached");out.write(buffer,0,count);}
    }
    private byte[] read(ZipFile zip,ZipEntry entry,Budget budget,int limit)throws IOException {
        if(entry.getSize()<0||entry.getSize()>limit)throw new LimitException("Entry byte limit reached: "+entry.getName());
        byte[] data=new byte[(int)entry.getSize()];
        try(InputStream in=zip.getInputStream(entry)){
            int at=0;while(at<data.length){int n=in.read(data,at,data.length-at);if(n<0)throw new IOException("Truncated entry");at+=n;budget.expanded+=n;if(budget.expanded>limits.maxExpandedBytes())throw new LimitException("Expanded byte limit reached");}
            if(in.read()!=-1)throw new IOException("Entry size changed");return data;
        }
    }
    private String hash(Path path)throws IOException {
        try(InputStream input=Files.newInputStream(path)){MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];int n;long total=0;while((n=input.read(buffer))!=-1){if((total+=n)>limits.maxArchiveBytes())throw new LimitException("Compressed archive size limit reached");digest.update(buffer,0,n);}return HexFormat.of().formatHex(digest.digest());}
        catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private ClassInfo parse(byte[] bytes,Budget budget,boolean instructions)throws IOException {
        ClassReader reader=new ClassReader(bytes);reserve(budget,160,reader.getClassName(),reader.getSuperName());String[] interfaces=reader.getInterfaces();for(String face:interfaces)reserve(budget,64,face);List<Member> members=new ArrayList<>();Set<Reference> references=new LinkedHashSet<>();
        ClassVisitor visitor=new ClassVisitor(Opcodes.ASM9){
            void add(Reference reference){if(references.add(reference)){reserve(budget,160,reference.sourceMethod(),reference.owner(),reference.name(),reference.descriptor());if(++budget.references>limits.maxReferences())throw new SymbolLimit("Reference count limit reached");}}
            void type(String source,Type type){if(!instructions)return;if(type.getSort()==Type.METHOD){type(source,type.getReturnType());for(Type arg:type.getArgumentTypes())type(source,arg);}else if(type.getSort()==Type.ARRAY)type(source,type.getElementType());else if(type.getSort()==Type.OBJECT)add(new Reference(source,"CLASS",type.getInternalName(),"","",0));}
            void constant(String source,Object value){if(!instructions)return;if(value instanceof Type t)type(source,t);else if(value instanceof Handle h){int tag=h.getTag();int opcode=switch(tag){case Opcodes.H_GETFIELD->Opcodes.GETFIELD;case Opcodes.H_GETSTATIC->Opcodes.GETSTATIC;case Opcodes.H_PUTFIELD->Opcodes.PUTFIELD;case Opcodes.H_PUTSTATIC->Opcodes.PUTSTATIC;case Opcodes.H_INVOKESTATIC->Opcodes.INVOKESTATIC;case Opcodes.H_INVOKEINTERFACE->Opcodes.INVOKEINTERFACE;case Opcodes.H_INVOKESPECIAL,Opcodes.H_NEWINVOKESPECIAL->Opcodes.INVOKESPECIAL;default->Opcodes.INVOKEVIRTUAL;};add(new Reference(source,tag<=4?"FIELD":"METHOD",h.getOwner(),h.getName(),h.getDesc(),opcode));type(source,Type.getType(h.getDesc()));}else if(value instanceof ConstantDynamic c){constant(source,c.getBootstrapMethod());type(source,Type.getType(c.getDescriptor()));for(int i=0;i<c.getBootstrapMethodArgumentCount();i++)constant(source,c.getBootstrapMethodArgument(i));}}
            @Override public void visit(int version,int access,String name,String signature,String parent,String[] interfaces){if(parent!=null)type("<class>",Type.getObjectType(parent));for(String face:interfaces)type("<class>",Type.getObjectType(face));}
            @Override public FieldVisitor visitField(int access,String name,String descriptor,String signature,Object value){reserve(budget,96,name,descriptor);members.add(new Member("FIELD",name,descriptor,access));type("<field:"+name+">",Type.getType(descriptor));constant("<field:"+name+">",value);return null;}
            @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
                reserve(budget,96,name,descriptor);members.add(new Member("METHOD",name,descriptor,access));String source=name+descriptor;type(source,Type.getMethodType(descriptor));if(exceptions!=null)for(String exception:exceptions)type(source,Type.getObjectType(exception));
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
        reader.accept(visitor,ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES|(instructions?0:ClassReader.SKIP_CODE));
        members.sort(Comparator.comparing(Member::kind).thenComparing(Member::name).thenComparing(Member::descriptor));
        List<Reference> sorted=references.stream().sorted(Comparator.comparing(Reference::sourceMethod).thenComparing(Reference::symbol).thenComparing(Reference::kind)).toList();
        return new ClassInfo(reader.getClassName(),reader.getSuperName(),List.of(interfaces),reader.getAccess(),reader.readUnsignedShort(6),List.copyOf(members),sorted);
    }
}
