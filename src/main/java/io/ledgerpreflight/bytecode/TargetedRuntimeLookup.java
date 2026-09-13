package io.ledgerpreflight.bytecode;

import io.ledgerpreflight.evidence.SafeInputs;
import io.ledgerpreflight.core.ManifestMetadata;
import io.ledgerpreflight.core.Discovery;
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
    public enum Role {RUNTIME,VERIFIER,SUPPORTING,LEGACY}
    public enum Scope {ALL,NODE_RUNTIME,VERIFIER}
    public enum ContextPresence {PRESENT,ABSENT,UNKNOWN}
    public record Artifact(Path path,String label,String expectedSha256,Role role) {
        public Artifact(Path path,String label){this(path,label,"");}
        public Artifact(Path path,String label,String expectedSha256){this(path,label,expectedSha256,Role.RUNTIME);}
        public Artifact {Objects.requireNonNull(path);Objects.requireNonNull(label);expectedSha256=Objects.requireNonNullElse(expectedSha256,"");Objects.requireNonNull(role);}
    }
    public enum State {FOUND,ABSENT,INCOMPLETE,AMBIGUOUS}
    public record Result(State state,ClassInfo info,List<String> origins,String detail,
                         String winningOrigin,List<String> shadowedOrigins,String precedenceEvidence) {
        public Result(State state,ClassInfo info,List<String> origins,String detail){this(state,info,origins,detail,"",List.of(),"");}
        public Result {origins=List.copyOf(origins);shadowedOrigins=List.copyOf(shadowedOrigins);}
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
    private record Definition(ClassInfo info,String origin,String component) {}
    private static final class Pending {
        final List<Definition> definitions=new ArrayList<>();String failure;
        void found(ClassInfo value,String origin,String component){if(definitions.size()<32)definitions.add(new Definition(value,origin,component));else failure="Required duplicate-definition retention limit reached";}
    }
    private final List<Artifact> artifacts;
    private final Limits limits;
    private final Scope scope;
    private List<String> provenClasspathOrder;
    private Map<String,String> selectedClassSources=Map.of();
    private final Set<String> verifierComponents=new TreeSet<>();
    public record Component(String label,Role role) {}
    private final Map<String,Role> components=new TreeMap<>();
    private boolean contextInspected;
    private String contextFailure;
    private final Map<String,Result> cache=new TreeMap<>();
    private final Map<Path,Stamp> stamps=new HashMap<>();
    private final Set<Path> verified=new HashSet<>();
    private final Set<String> nestedComponents=new HashSet<>();
    private record Dependencies(List<String> locations,boolean limited) {}
    private final Map<String,Dependencies> declaredDependencies=new HashMap<>();
    private final Set<String> activeComponents=new HashSet<>();
    private final Set<String> unresolvedDeclaringComponents=new HashSet<>();
    private long dependencyTextBytes;
    private boolean unresolvedDependencies;
    private long bytesRead,signatureBytes,started;
    private int entries;
    private String invalidated;

    public TargetedRuntimeLookup(List<Artifact> artifacts){this(artifacts,Limits.defaults());}
    public TargetedRuntimeLookup(List<Artifact> artifacts,int javaFeature){this(artifacts,Limits.defaults().forJava(javaFeature));}
    public TargetedRuntimeLookup(List<Artifact> artifacts,Limits limits){
        this(artifacts,limits,Scope.ALL,List.of());
    }
    /** Ordering is accepted only as exact artifact/component labels already bound to this context. */
    public TargetedRuntimeLookup(List<Artifact> artifacts,Limits limits,Scope scope,List<String> provenClasspathOrder){
        this.limits=Objects.requireNonNull(limits);
        this.scope=Objects.requireNonNull(scope);
        this.provenClasspathOrder=List.copyOf(provenClasspathOrder);
        this.artifacts=artifacts.stream().sorted(Comparator.comparing(Artifact::label).thenComparing(a->a.path().toString())).limit(257).toList();
        if(artifacts.size()>256)invalidated="Required runtime artifact count limit reached";
        if(provenClasspathOrder.size()>256||provenClasspathOrder.stream().anyMatch(s->s==null||s.length()>2048))invalidated="Required classpath proof limit reached";
    }

    /** Detect an optional bundled verifier without requiring broad bytecode indexing. */
    public ContextPresence contextPresence(){
        if(scope!=Scope.VERIFIER)return artifacts.isEmpty()?ContextPresence.ABSENT:ContextPresence.PRESENT;
        if(!contextInspected){
            contextInspected=true;if(started==0)started=System.nanoTime();
            contextFailure=scan(artifacts.stream().filter(a->a.role()==Role.RUNTIME||a.role()==Role.VERIFIER).toList(),Map.of(),false);
        }
        if(!verifierComponents.isEmpty())return ContextPresence.PRESENT;
        return invalidated!=null||contextFailure!=null?ContextPresence.UNKNOWN:ContextPresence.ABSENT;
    }
    public boolean hasVerifierContext(){return contextPresence()!=ContextPresence.ABSENT;}
    public boolean contextComplete(){contextPresence();return invalidated==null&&contextFailure==null;}
    public List<String> verifierComponents(){contextPresence();return List.copyOf(verifierComponents);}
    public List<Component> components(){
        if(!contextInspected){contextInspected=true;if(started==0)started=System.nanoTime();contextFailure=scan(artifacts,Map.of(),false);}
        return components.entrySet().stream().map(e->new Component(e.getKey(),e.getValue())).toList();
    }
    public void setProvenClasspathOrder(List<String> order){
        if(!cache.isEmpty())throw new IllegalStateException("Classpath proof must be bound before required owners are resolved");
        if(order.size()>256||order.stream().anyMatch(s->s==null||s.length()>2048))throw new IllegalArgumentException("Required classpath proof limit reached");
        provenClasspathOrder=List.copyOf(order);
    }
    /** Sources are exact bound context component labels; an empty label retains unresolved evidence. */
    public void setSelectedClassSources(Map<String,String> sources){
        if(!cache.isEmpty())throw new IllegalStateException("Class-load proof must be bound before required owners are resolved");
        if(sources.size()>limits.maxOwners()||sources.entrySet().stream().anyMatch(e->!validOwner(e.getKey())||e.getValue()==null||e.getValue().length()>2048)||sources.entrySet().stream().mapToLong(e->2L*(e.getKey().length()+e.getValue().length())+128).sum()>limits.maxSignatureBytes())throw new IllegalArgumentException("Required class-load proof limit reached");
        selectedClassSources=Map.copyOf(sources);
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
        List<Artifact> primary=scope==Scope.ALL?artifacts:artifacts.stream().filter(a->scope==Scope.NODE_RUNTIME?a.role()==Role.RUNTIME:a.role()==Role.RUNTIME||a.role()==Role.VERIFIER||a.role()==Role.LEGACY).toList();
        String failure=primary.isEmpty()?"No selected runtime artifacts were supplied":scan(primary,pending,false);
        Map<String,Pending> fallback=new TreeMap<>();
        for(var item:pending.entrySet()){
            Result result=select(item.getKey(),item.getValue(),failure,false);
            if(scope!=Scope.ALL&&result.state()==State.ABSENT)fallback.put(item.getKey(),new Pending());
            cache.put(item.getKey(),result);
        }
        List<Artifact> supporting=artifacts.stream().filter(a->a.role()==Role.SUPPORTING).toList();
        if(!fallback.isEmpty()&&!supporting.isEmpty()){
            failure=scan(supporting,fallback,true);
            for(var item:fallback.entrySet())cache.put(item.getKey(),select(item.getKey(),item.getValue(),failure,true));
        }
        for(String owner:pending.keySet())if(cache.get(owner).state()==State.ABSENT&&selectedClassSources.containsKey(owner))cache.put(owner,incomplete("Supplied class-load source could not be confirmed in this execution context"));
    }

    private String scan(List<Artifact> selected,Map<String,Pending> pending,boolean fallback){
        if(invalidated!=null)return invalidated;
        activeComponents.clear();unresolvedDeclaringComponents.clear();unresolvedDependencies=false;
        try{
            tick();verifySnapshots();
            Set<Path> physical=new HashSet<>();
            for(Artifact artifact:selected){
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
                boolean active=scope!=Scope.VERIFIER||artifact.role()==Role.VERIFIER||artifact.role()==Role.LEGACY||fallback;
                search(path,artifact.label(),0,pending,active,artifact.role());
            }
            verifySnapshots();
            if(scope!=Scope.ALL)for(String component:activeComponents){
                Dependencies dependencies=declaredDependencies.get(component);
                if(dependencies==null)continue;
                if(dependencies.limited())unresolvedDeclaringComponents.add(component);
                for(String dependency:dependencies.locations())if(!activeComponents.contains(relativeDependency(component,dependency)))unresolvedDeclaringComponents.add(component);
            }
            unresolvedDependencies=!unresolvedDeclaringComponents.isEmpty();
            return null;
        }catch(IOException|RuntimeException e){return Objects.toString(e.getMessage(),"Required runtime lookup could not complete");}
    }

    private Result select(String owner,Pending value,String failure,boolean fallback){
        List<String> origins=value.definitions.stream().map(Definition::origin).sorted().toList();
        if(failure!=null||value.failure!=null)return new Result(State.INCOMPLETE,null,origins,failure!=null?failure:value.failure);
        if(value.definitions.isEmpty())return unresolvedDependencies?new Result(State.INCOMPLETE,null,List.of(),"Required owner lookup is incomplete because a declared execution-context classpath dependency could not be inspected"):new Result(State.ABSENT,null,List.of(),"Required owner absent after complete targeted lookup of the selected execution context");
        Definition winner=value.definitions.get(0);String proof=fallback?"Selected runtime owner is absent after complete lookup; supporting dependency supplies this owner":"Selected execution context contains one definition after complete targeted lookup";
        Definition loaded=null;
        if(selectedClassSources.containsKey(owner)){
            String source=selectedClassSources.get(owner);
            List<Definition> candidates=value.definitions.stream().filter(d->!source.isBlank()&&(d.component().equals(source)||d.component().startsWith(source+"!/"))).toList();
            if(candidates.size()!=1)return new Result(State.INCOMPLETE,null,origins,"Supplied class-load source does not uniquely identify a definition in this execution context");
            loaded=candidates.get(0);
        }
        if(value.definitions.size()>1){
            int minimum=Integer.MAX_VALUE;Set<Integer> ranks=new HashSet<>();boolean ordered=true;
            for(Definition definition:value.definitions){
                int rank=rank(definition.component());
                if(rank<0||!ranks.add(rank))ordered=false;
                if(rank>=0&&rank<minimum){minimum=rank;winner=definition;}
            }
            if(!ordered&&loaded==null)return new Result(State.AMBIGUOUS,null,origins,"Multiple components define this owner in the same execution context; class selection is unproven");
            if(ordered&&loaded!=null&&!loaded.equals(winner))return new Result(State.INCOMPLETE,null,origins,"Supplied class-load source contradicts the supplied classpath order in this execution context");
            if(loaded!=null){winner=loaded;proof="Supplied class-load evidence identifies this exact component in the selected execution context";}
            else proof="Exact supplied classpath order selects this component before every other definition in the same execution context";
        }else if(loaded!=null)proof="Supplied class-load evidence agrees with the unique definition in the selected execution context";
        if(loaded==null)for(String declaring:unresolvedDeclaringComponents)if(!declaring.equals(winner.component())){
            int winningRank=rank(winner.component()),declaringRank=rank(declaring);
            if(winningRank<0||declaringRank<0||winningRank>=declaringRank)return new Result(State.INCOMPLETE,null,origins,"An unresolved declared classpath dependency could precede the candidate owner in this execution context");
        }
        if(loaded==null&&unresolvedDeclaringComponents.contains(winner.component()))proof="Owner is defined in the declaring component before its unresolved manifest Class-Path dependencies";
        String winning=winner.origin();List<String> shadowed=origins.stream().filter(s->!s.equals(winning)).toList();
        return new Result(State.FOUND,winner.info(),List.of(winning),proof,winning,shadowed,proof);
    }

    private int rank(String component){
        int found=-1;Set<String> matched=new HashSet<>();
        for(int i=0;i<provenClasspathOrder.size();i++){
            String entry=provenClasspathOrder.get(i);
            if(component.equals(entry)||component.startsWith(entry+"!/")){
                if(!matched.add(entry))return -1;
                if(found<0)found=i;
            }
        }
        return found;
    }

    private void search(Path file,String label,int depth,Map<String,Pending> pending,boolean active,Role inheritedRole)throws IOException {
        tick();if(depth>limits.maxDepth())throw new BudgetExceeded("Required nested runtime depth limit reached");
        try(ZipFile zip=ArchiveSafety.open(file,limits.maxEntries())){
            Map<String,String> manifest=manifest(zip);
            // Artifact roles identify execution boundaries; the requested owner's package never does.
            String declaredRole=Discovery.role(new JarInventory("component","",manifest,Map.of(),List.of(),List.of()));
            boolean declaredLaunch=List.of("Main-Class","Application-Class","Start-Class","Application-ID").stream().anyMatch(key->!manifest.getOrDefault(key,"").isBlank());
            boolean inferredVerifier=declaredRole.equals("VERIFIER")||!declaredLaunch&&zip.getEntry("net/corda/verifier/Main.class")!=null;
            // A selected physical node remains the authority even if its archive also ships
            // a verifier entry point. Only nested applications need inferred role boundaries.
            boolean verifierRoot=depth==0?inheritedRole==Role.VERIFIER:inferredVerifier;
            Role componentRole=verifierRoot?Role.VERIFIER:inheritedRole;
            if(!components.containsKey(label)){reserve(80,label);components.put(label,componentRole);}
            if(verifierRoot)verifierComponents.add(label);
            if(scope==Scope.NODE_RUNTIME&&componentRole==Role.VERIFIER)return;
            if(scope==Scope.VERIFIER&&componentRole==Role.VERIFIER)active=true;
            if(scope==Scope.VERIFIER&&provenClasspathOrder.contains(label))active=true;
            if(scope!=Scope.ALL&&active){
                activeComponents.add(label);
                if(!declaredDependencies.containsKey(label))declaredDependencies.put(label,dependencies(zip));
            }
            Set<String> names=new HashSet<>();Map<String,Candidate> candidates=new TreeMap<>();
            boolean multi="true".equalsIgnoreCase(manifest.get("Multi-Release"));
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
                    String loaded=selectedClassSources.get(owner);
                    boolean loadedHere=scope==Scope.VERIFIER&&loaded!=null&&!loaded.isBlank()&&(label.equals(loaded)||label.startsWith(loaded+"!/"));
                    if((active||loadedHere)&&pending.containsKey(owner)){
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
                    value.found(info,origin,label);
                }catch(BudgetExceeded e){throw e;}
                catch(IOException|RuntimeException e){value.failure="Required class could not be inspected: "+Objects.toString(e.getMessage(),"Malformed class");}
                catch(StackOverflowError e){value.failure="Required class nesting exceeded parser stack capacity";}
            }
            // A first hit is insufficient: later components may define the same class.
            for(var enumeration=zip.entries();enumeration.hasMoreElements();){
                ZipEntry entry=enumeration.nextElement();String name=entry.getName();
                if(entry.isDirectory()||!name.toLowerCase(Locale.ROOT).endsWith(".jar"))continue;
                tick();String nestedLabel=label+"!/"+name;
                if(!nestedComponents.contains(nestedLabel)){if(nestedComponents.size()>=limits.maxNestedArchives())throw new BudgetExceeded("Required nested archive count limit reached");nestedComponents.add(nestedLabel);}
                if(depth>=limits.maxDepth())throw new BudgetExceeded("Required nested runtime depth limit reached");
                checkExpandedEntry(entry,limits.maxNestedBytes());
                Path temporary=Files.createTempFile("ledger-preflight-required-",".archive",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                try{
                    try(InputStream in=zip.getInputStream(entry);OutputStream out=Files.newOutputStream(temporary)){copy(in,out,entry,limits.maxNestedBytes());}
                    search(temporary,label+"!/"+name,depth+1,pending,active,componentRole);
                }finally{Files.deleteIfExists(temporary);}
            }
        }
    }

    /** Inspect only bounded manifest main headers; never follow a declared URL or external path. */
    private Dependencies dependencies(ZipFile zip)throws IOException {
        ZipEntry entry=zip.getEntry("META-INF/MANIFEST.MF");if(entry==null)return new Dependencies(List.of(),false);
        ByteArrayOutputStream value=new ByteArrayOutputStream();boolean keep=false,limited=false,seen=false;long total=0;
        try(InputStream input=zip.getInputStream(entry);BufferedInputStream in=new BufferedInputStream(input,8192)){
            while(true){
                ByteArrayOutputStream line=new ByteArrayOutputStream();int c;
                while((c=in.read())!=-1&&c!='\n'){charge(1);if(++total>8L*1024*1024||line.size()>=65536)return new Dependencies(List.of(),true);line.write(c);}
                if(c=='\n'){charge(1);total++;}
                byte[] bytes=line.toByteArray();int length=bytes.length;if(length>0&&bytes[length-1]=='\r')length--;
                if(length==0)break;
                if(bytes[0]==' '){
                    if(keep){if(value.size()+length-1>16384)limited=true;else if(!limited)value.write(bytes,1,length-1);}
                }else{
                    int colon=0;while(colon<length&&bytes[colon]!=':')colon++;
                    keep=colon<length&&new String(bytes,0,colon,java.nio.charset.StandardCharsets.US_ASCII).equalsIgnoreCase("Class-Path");
                    if(keep){if(seen||length-colon-2>16384)limited=true;else if(colon+2<=length)value.write(bytes,colon+2,length-colon-2);seen=true;}
                }
                if(c==-1)break;
            }
        }
        if(limited)return new Dependencies(List.of(),true);
        String text=value.toString(java.nio.charset.StandardCharsets.UTF_8).strip();if(text.isEmpty())return new Dependencies(List.of(),false);
        String[] locations=text.split("\\s+");if(locations.length>256||Arrays.stream(locations).anyMatch(s->s.length()>2048)||dependencyTextBytes+2L*text.length()>256*1024)return new Dependencies(List.of(),true);
        dependencyTextBytes+=2L*text.length();return new Dependencies(List.of(locations),false);
    }
    private static String relativeDependency(String component,String dependency){
        if(dependency.isEmpty()||dependency.startsWith("/")||dependency.contains(":")||dependency.contains("\\")||dependency.contains("%")||dependency.contains("*")||dependency.contains("?")||dependency.endsWith("/"))return "";
        int boundary=component.lastIndexOf("!/");String capsule=boundary<0?"":component.substring(0,boundary+2),path=component.substring(boundary<0?0:boundary+2);
        int slash=path.lastIndexOf('/');String relative=(slash<0?"":path.substring(0,slash+1))+dependency;
        Deque<String> parts=new ArrayDeque<>();for(String part:relative.split("/")){
            if(part.equals("..")){if(parts.isEmpty())return "";parts.removeLast();}
            else if(!part.isEmpty()&&!part.equals("."))parts.addLast(part);
        }
        return capsule+String.join("/",parts);
    }

    private Map<String,String> manifest(ZipFile zip)throws IOException {
        ZipEntry entry=zip.getEntry("META-INF/MANIFEST.MF");if(entry==null)return Map.of();
        // Signed per-entry sections are irrelevant to version selection. The shared parser
        // bounds main headers and their continuations without expanding the whole manifest.
        try(InputStream in=new FilterInputStream(zip.getInputStream(entry)){
            @Override public int read()throws IOException {int value=super.read();if(value!=-1)charge(1);return value;}
            @Override public int read(byte[] data,int offset,int length)throws IOException {int count=in.read(data,offset,length);if(count>0)charge(count);return count;}
        }){
            return ManifestMetadata.read(in);
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
