package io.ledgerpreflight.bytecode;

import java.util.*;
import java.util.function.Predicate;
import org.objectweb.asm.Opcodes;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;
import static io.ledgerpreflight.bytecode.TargetedRuntimeLookup.*;

/** Exact linkage questions extracted exclusively from active current CorDapp bytecode. */
public final class RequiredSymbolAnalyzer {
    public enum Resolution { COMPATIBLE, MISSING_METHOD, MISSING_FIELD, MISSING_CLASS, DESCRIPTOR_MISMATCH, INVOCATION_MISMATCH, ACCESS_INCOMPATIBLE, UNKNOWN }
    public enum ExecutionContext { CURRENT_NODE_RUNTIME, TARGET_NODE_RUNTIME, TARGET_VERIFIER }
    public record Source(String sourceArtifact,String sourceClass,String sourceMethod,String owner,String member,String descriptor,String referenceType) {}
    public record Symbol(String owner,String member,String descriptor,String kind,int opcode,Boolean ownerInterface) {
        public Symbol(String owner,String member,String descriptor,String kind,int opcode){this(owner,member,descriptor,kind,opcode,opcode==Opcodes.INVOKEINTERFACE?Boolean.TRUE:opcode==Opcodes.INVOKEVIRTUAL?Boolean.FALSE:null);}
        public String display(){return owner.replace('/','.')+"."+member+descriptor;}
        Reference reference(){return new Reference("",kind,owner,member,descriptor,opcode,ownerInterface);}
    }
    public record Proof(String classStatus,String memberStatus,List<String> artifacts,String declaringClass,List<String> availableDescriptors,String detail,String winningArtifact,List<String> shadowedArtifacts,String precedenceEvidence) {
        public Proof(String classStatus,String memberStatus,List<String> artifacts,String declaringClass,List<String> availableDescriptors,String detail){this(classStatus,memberStatus,artifacts,declaringClass,availableDescriptors,detail,"",List.of(),"");}
        public Proof { winningArtifact=winningArtifact==null?"":winningArtifact;shadowedArtifacts=shadowedArtifacts==null?List.of():List.copyOf(shadowedArtifacts);precedenceEvidence=precedenceEvidence==null?"":precedenceEvidence; }
    }
    public record ContextResult(ExecutionContext context,Proof proof,Resolution resolution,List<Source> sources) {
        public ContextResult(ExecutionContext context,Proof proof,Resolution resolution){this(context,proof,resolution,List.of());}
        public ContextResult { sources=sources==null?List.of():List.copyOf(sources); }
    }
    public record SymbolResult(Symbol symbol,List<Source> sources,Proof current,Proof target,Resolution resolution,List<ContextResult> contexts) {
        public SymbolResult(Symbol symbol,List<Source> sources,Proof current,Proof target,Resolution resolution){this(symbol,sources,current,target,resolution,List.of());}
        public SymbolResult { contexts=contexts==null?List.of():List.copyOf(contexts); }
    }
    public record Analysis(List<CompatibilityAnalyzer.CompatibilityIssue> findings,List<SymbolResult> symbols,boolean complete,List<JarInventory> currentClasses,List<JarInventory> targetClasses,List<JarInventory> verifierClasses) {
        public Analysis(List<CompatibilityAnalyzer.CompatibilityIssue> findings,List<SymbolResult> symbols,boolean complete,List<JarInventory> currentClasses,List<JarInventory> targetClasses){this(findings,symbols,complete,currentClasses,targetClasses,List.of());}
    }
    public interface Lookup { Result lookup(String owner); default void prefetch(Collection<String> owners){} }
    private static final int MAX_SYMBOLS=4096,MAX_SOURCES=16384;
    private static final long MAX_SOURCE_BYTES=2L*1024*1024;
    private record Linked(Result owner,Member member,ClassInfo declaring,Set<String> alternatives,boolean incomplete,String detail) {}
    private static final class Tracked implements Lookup {
        final Lookup delegate;final Map<String,Result> results=new TreeMap<>();final Set<String> local;int steps;
        Tracked(Lookup delegate,Set<String> local){this.delegate=delegate;this.local=local;}
        public void prefetch(Collection<String> owners){delegate.prefetch(owners);}
        public Result lookup(String owner){if(++steps>65536)return new Result(State.INCOMPLETE,null,List.of(),"Required hierarchy resolution work limit reached");Result result=delegate.lookup(owner);results.put(owner,result);return result;}
        List<JarInventory> inventories(){Map<String,Map<String,ClassInfo>> jars=new TreeMap<>();for(var entry:results.entrySet()){var result=entry.getValue();if(!local.contains(entry.getKey())&&result.state()==State.FOUND&&result.info()!=null)for(String origin:result.origins())jars.computeIfAbsent(origin,k->new TreeMap<>()).put(result.info().name(),result.info());}return jars.entrySet().stream().map(e->new JarInventory(e.getKey(),"",Map.of(),Collections.unmodifiableMap(e.getValue()),List.of())).toList();}
    }
    private static Lookup adapt(TargetedRuntimeLookup lookup){return new Lookup(){public Result lookup(String owner){return lookup.lookup(owner);}public void prefetch(Collection<String> owners){lookup.prefetch(owners);}};}
    public Analysis analyze(List<JarInventory> consumers,TargetedRuntimeLookup current,TargetedRuntimeLookup target){return analyze(consumers,adapt(current),adapt(target));}
    public Analysis analyze(List<JarInventory> consumers,TargetedRuntimeLookup current,TargetedRuntimeLookup target,TargetedRuntimeLookup verifier){return analyze(consumers,adapt(current),adapt(target),verifier==null?null:adapt(verifier));}
    public Analysis analyze(List<JarInventory> consumers,TargetedRuntimeLookup current,TargetedRuntimeLookup target,TargetedRuntimeLookup verifier,Predicate<Source> verifierApplies){return analyze(consumers,adapt(current),adapt(target),verifier==null?null:adapt(verifier),verifierApplies);}
    public Analysis analyze(List<JarInventory> consumers,Lookup currentLookup,Lookup targetLookup){return analyze(consumers,currentLookup,targetLookup,null);}
    /** Each lookup represents one execution context; absence of a verifier lookup means it is not being evaluated. */
    public Analysis analyze(List<JarInventory> consumers,Lookup currentLookup,Lookup targetLookup,Lookup verifierLookup){return analyze(consumers,currentLookup,targetLookup,verifierLookup,source->true);}
    public Analysis analyze(List<JarInventory> consumers,Lookup currentLookup,Lookup targetLookup,Lookup verifierLookup,Predicate<Source> verifierApplies){
        Objects.requireNonNull(verifierApplies,"verifierApplies");
        Map<String,List<Result>> local=new TreeMap<>();for(JarInventory jar:consumers)for(ClassInfo cls:jar.classes().values())local.computeIfAbsent(cls.name(),k->new ArrayList<>()).add(new Result(State.FOUND,cls,List.of(jar.path()),"Active current CorDapp class"));
        Tracked current=new Tracked(withLocal(currentLookup,local),local.keySet()),target=new Tracked(withLocal(targetLookup,local),local.keySet());
        Tracked verifier=verifierLookup==null?null:new Tracked(withLocal(verifierLookup,local),local.keySet());
        Comparator<Symbol> ordering=Comparator.comparing(Symbol::owner).thenComparing(Symbol::member).thenComparing(Symbol::descriptor).thenComparing(Symbol::kind).thenComparingInt(Symbol::opcode).thenComparing(s->String.valueOf(s.ownerInterface()));
        Map<Symbol,LinkedHashSet<Source>> required=new TreeMap<>(ordering);boolean limited=false;int sourceCount=0;long sourceBytes=0;
        outer:for(JarInventory jar:consumers.stream().sorted(Comparator.comparing(JarInventory::path)).toList())for(ClassInfo cls:new TreeMap<>(jar.classes()).values())for(Reference ref:cls.references()){
            if(platform(ref.owner())||ref.owner().startsWith("[")||local.containsKey(ref.owner())&&(ref.kind().equals("CLASS")||declaredLocally(local,ref.owner(),ref,new HashSet<>())))continue;
            Symbol symbol=new Symbol(ref.owner(),ref.name(),ref.descriptor(),ref.kind(),ref.opcode(),ref.ownerInterface());
            if(!required.containsKey(symbol)&&required.size()>=MAX_SYMBOLS){limited=true;break outer;}
            var sources=required.computeIfAbsent(symbol,k->new LinkedHashSet<>());
            Source source=new Source(physical(jar.path()),cls.name(),ref.sourceMethod(),ref.owner(),ref.name(),ref.descriptor(),referenceType(ref));
            if(sources.contains(source))continue;
            long bytes=160L+2L*(source.sourceArtifact().length()+source.sourceClass().length()+source.sourceMethod().length()+source.owner().length()+source.member().length()+source.descriptor().length());
            if(sourceCount>=MAX_SOURCES||sourceBytes+bytes>MAX_SOURCE_BYTES){if(sources.isEmpty())required.remove(symbol);limited=true;break outer;}sources.add(source);sourceCount++;sourceBytes+=bytes;
        }
        prepareHierarchy(current,required.keySet());prepareHierarchy(target,required.keySet());
        if(verifier!=null)prepareHierarchy(verifier,required.entrySet().stream().filter(e->e.getValue().stream().anyMatch(verifierApplies)).map(Map.Entry::getKey).toList());
        List<SymbolResult> symbols=new ArrayList<>();List<CompatibilityAnalyzer.CompatibilityIssue> findings=new ArrayList<>();Map<String,SymbolResult> roots=new LinkedHashMap<>(),internalRoots=new LinkedHashMap<>();boolean complete=!limited;
        for(var entry:required.entrySet()){
            Symbol symbol=entry.getKey();Linked before=resolve(current,symbol),after=resolve(target,symbol);List<Source> sources=List.copyOf(entry.getValue());
            Resolution nodeResolution=classify(symbol,before,after,sources,target);List<ContextResult> contexts=new ArrayList<>();
            Proof currentProof=proof(before,symbol),targetProof=proof(after,symbol);
            contexts.add(new ContextResult(ExecutionContext.CURRENT_NODE_RUNTIME,currentProof,classify(symbol,before,before,sources,current),sources));
            contexts.add(new ContextResult(ExecutionContext.TARGET_NODE_RUNTIME,targetProof,nodeResolution,sources));
            List<Source> verifierSources=verifier==null?List.of():sources.stream().filter(verifierApplies).toList();
            if(!verifierSources.isEmpty()){Linked verified=resolve(verifier,symbol);contexts.add(new ContextResult(ExecutionContext.TARGET_VERIFIER,proof(verified,symbol),classify(symbol,before,verified,verifierSources,verifier),verifierSources));}
            Resolution result=aggregate(contexts);complete&=contexts.stream().filter(c->c.context()!=ExecutionContext.CURRENT_NODE_RUNTIME).noneMatch(c->c.resolution()==Resolution.UNKNOWN);
            SymbolResult proof=new SymbolResult(symbol,sources,currentProof,targetProof,result,contexts);symbols.add(proof);
            if(result!=Resolution.COMPATIBLE)roots.merge(rootKey(proof),proof,RequiredSymbolAnalyzer::combineSources);
            if(internal(symbol.owner()))internalRoots.merge(symbol.owner()+"|"+symbol.kind()+"|"+symbol.member()+"|"+symbol.descriptor(),proof,RequiredSymbolAnalyzer::combineSources);
        }
        roots.values().forEach(root->findings.add(finding(root)));
        internalRoots.values().forEach(root->findings.add(issue("LP-INTERNAL-001","WARNING","CorDapp references an internal Corda API; internal APIs have no normal stability guarantee",evidence(root),"Replace internal API use with a supported API, or validate the exact supplied runtime and historical transactions with TVU.")));
        if(limited)findings.add(issue("LP-ANALYSIS-LIMIT","UNKNOWN","Required compatibility reference limit reached; remaining questions are unresolved",Map.of("sourceScope","active-current-cordapp","retainedSymbols",Integer.toString(required.size()),"retainedSources",Integer.toString(sourceCount)),"Complete bounded analysis of the active current CorDapps before upgrading."));
        return new Analysis(List.copyOf(findings),List.copyOf(symbols),complete,current.inventories(),target.inventories(),verifier==null?List.of():verifier.inventories());
    }
    private static boolean blocked(Resolution resolution){return resolution!=Resolution.COMPATIBLE&&resolution!=Resolution.UNKNOWN;}
    private static Resolution aggregate(List<ContextResult> contexts){
        List<Resolution> target=contexts.stream().filter(c->c.context()!=ExecutionContext.CURRENT_NODE_RUNTIME).map(ContextResult::resolution).toList();
        return target.stream().filter(RequiredSymbolAnalyzer::blocked).findFirst().orElse(target.contains(Resolution.UNKNOWN)?Resolution.UNKNOWN:Resolution.COMPATIBLE);
    }
    private static String rootKey(SymbolResult result){Symbol symbol=result.symbol();return result.resolution()+"|"+symbol.owner()+(result.resolution()==Resolution.MISSING_CLASS?"":"|"+symbol.kind()+"|"+symbol.member()+"|"+symbol.descriptor());}
    private static SymbolResult combineSources(SymbolResult first,SymbolResult next){
        Set<Source> sources=new LinkedHashSet<>(first.sources());sources.addAll(next.sources());
        Map<ExecutionContext,ContextResult> contexts=new LinkedHashMap<>();first.contexts().forEach(c->contexts.put(c.context(),c));
        next.contexts().forEach(c->contexts.merge(c.context(),c,(a,b)->{
            ContextResult retained=blocked(a.resolution())?a:blocked(b.resolution())?b:a.resolution()==Resolution.UNKNOWN?a:b;
            Set<Source> contextSources=new LinkedHashSet<>(a.sources());contextSources.addAll(b.sources());return new ContextResult(retained.context(),retained.proof(),retained.resolution(),List.copyOf(contextSources));
        }));
        return new SymbolResult(first.symbol(),List.copyOf(sources),first.current(),first.target(),first.resolution(),List.copyOf(contexts.values()));
    }
    private record HierarchyQuestion(String owner,Symbol symbol) {}
    /** Batch only ancestors needed for undeclared exact members, avoiding one capsule traversal per caller. */
    private static void prepareHierarchy(Lookup lookup,Collection<Symbol> symbols){
        Set<HierarchyQuestion> pending=new LinkedHashSet<>(),visited=new HashSet<>();for(Symbol symbol:symbols)pending.add(new HierarchyQuestion(symbol.owner(),symbol));
        for(int depth=0;depth<=128&&!pending.isEmpty();depth++){
            lookup.prefetch(pending.stream().map(HierarchyQuestion::owner).distinct().sorted().toList());Set<HierarchyQuestion> next=new LinkedHashSet<>();
            for(HierarchyQuestion question:pending){
                if(visited.size()>=32768)return;if(!visited.add(question))continue;Result result=lookup.lookup(question.owner());Symbol symbol=question.symbol();
                if(result.state()!=State.FOUND||symbol.kind().equals("CLASS"))continue;ClassInfo info=result.info();Reference ref=symbol.reference();
                if(info.members().stream().anyMatch(m->m.kind().equals(ref.kind())&&m.name().equals(ref.name())&&m.descriptor().equals(ref.descriptor())))continue;
                if(ref.name().equals("<init>")||ref.name().equals("<clinit>")||ref.kind().equals("METHOD")&&ref.isStatic()&&(info.access()&Opcodes.ACC_INTERFACE)!=0)continue;
                List<String> parents=new ArrayList<>();if(info.superName()!=null)parents.add(info.superName());if(ref.kind().equals("FIELD")||!ref.isStatic())parents.addAll(info.interfaces());
                for(String parent:parents)if(!parent.equals("java/lang/Object")){HierarchyQuestion inherited=new HierarchyQuestion(parent,symbol);if(!visited.contains(inherited))next.add(inherited);}
            }
            pending=next;
        }
    }
    private static Lookup withLocal(Lookup runtime,Map<String,List<Result>> local){return new Lookup(){public Result lookup(String owner){List<Result> found=local.get(owner);return found==null?runtime.lookup(owner):found.size()==1?found.get(0):new Result(State.AMBIGUOUS,null,found.stream().flatMap(r->r.origins().stream()).sorted().toList(),"Active current CorDapps contain multiple definitions");}public void prefetch(Collection<String> owners){runtime.prefetch(owners.stream().filter(o->!local.containsKey(o)).toList());}};}
    private static boolean declaredLocally(Map<String,List<Result>> local,String owner,Reference ref,Set<String> visited){
        if(visited.size()>128||!visited.add(owner))return false;List<Result> definitions=local.get(owner);if(definitions==null||definitions.size()!=1)return false;ClassInfo cls=definitions.get(0).info();
        if(cls.members().stream().anyMatch(m->m.kind().equals(ref.kind())&&m.name().equals(ref.name())&&m.descriptor().equals(ref.descriptor())&&m.isStatic()==ref.isStatic()))return true;
        if(ref.name().equals("<init>")||ref.name().equals("<clinit>"))return false;
        if(cls.superName()!=null&&declaredLocally(local,cls.superName(),ref,visited))return true;return cls.interfaces().stream().anyMatch(i->declaredLocally(local,i,ref,new HashSet<>(visited)));
    }
    private static Linked resolve(Lookup lookup,Symbol symbol){
        Result owner=lookup.lookup(symbol.owner());
        if(owner.state()!=State.FOUND)return new Linked(owner,null,null,Set.of(),owner.state()!=State.ABSENT,owner.detail());
        if(symbol.kind().equals("CLASS"))return new Linked(owner,null,owner.info(),Set.of(),false,"");
        Linked member=resolveMember(lookup,owner.info(),symbol.reference(),new HashSet<>(),0);
        return new Linked(owner,member.member(),member.declaring(),member.alternatives(),member.incomplete(),member.detail());
    }
    private static Linked resolveMember(Lookup lookup,ClassInfo info,Reference ref,Set<String> visited,int depth){
        return resolveMember(lookup,info,ref,visited,depth,new HashMap<>());
    }
    private static Linked resolveMember(Lookup lookup,ClassInfo info,Reference ref,Set<String> visited,int depth,Map<String,Linked> memo){
        Linked cached=memo.get(info.name());if(cached!=null)return cached;
        Linked result=resolveMemberUncached(lookup,info,ref,visited,depth,memo);
        if(memo.size()<4096)memo.put(info.name(),result);return result;
    }
    private static Linked resolveMemberUncached(Lookup lookup,ClassInfo info,Reference ref,Set<String> visited,int depth,Map<String,Linked> memo){
        if(depth>128||!visited.add(info.name()))return new Linked(null,null,null,Set.of(),true,"Class hierarchy could not be completely resolved");
        Set<String> alternatives=new TreeSet<>();for(Member member:info.members())if(member.kind().equals(ref.kind())&&member.name().equals(ref.name())){if(member.descriptor().equals(ref.descriptor()))return new Linked(null,member,info,Set.of(),false,"");alternatives.add(member.descriptor());}
        if(ref.name().equals("<init>")||ref.name().equals("<clinit>")||(ref.kind().equals("METHOD")&&ref.isStatic()&&(info.access()&Opcodes.ACC_INTERFACE)!=0))return new Linked(null,null,null,alternatives,false,"");
        List<String> parents=new ArrayList<>();if(ref.kind().equals("FIELD")){parents.addAll(info.interfaces());if(info.superName()!=null)parents.add(info.superName());}else{if(info.superName()!=null)parents.add(info.superName());if(!ref.isStatic())parents.addAll(info.interfaces());}
        boolean incomplete=false;List<Linked> interfaceMethods=new ArrayList<>();for(String parent:parents){
            if(parent.equals("java/lang/Object")){if(ref.kind().equals("METHOD")&&!ref.isStatic()&&objectMethod(ref.name(),ref.descriptor()))return new Linked(null,new Member("METHOD",ref.name(),ref.descriptor(),Opcodes.ACC_PUBLIC),info,Set.of(),incomplete,incomplete?"A required ancestor could not be resolved":"");continue;}
            Result definition=lookup.lookup(parent);if(definition.state()!=State.FOUND){incomplete=true;continue;}
            Linked found=resolveMember(lookup,definition.info(),ref,new HashSet<>(visited),depth+1,memo);alternatives.addAll(found.alternatives());incomplete|=found.incomplete();
            if(found.member()!=null){
                if(ref.kind().equals("METHOD")&&(definition.info().access()&Opcodes.ACC_INTERFACE)!=0){if((found.member().access()&(Opcodes.ACC_STATIC|Opcodes.ACC_PRIVATE))==0)interfaceMethods.add(found);}
                else return new Linked(null,found.member(),found.declaring(),alternatives,incomplete,incomplete?"A required ancestor could not be resolved":found.detail());
            }
        }
        if(!interfaceMethods.isEmpty()){
            Map<String,Linked> unique=new TreeMap<>();interfaceMethods.forEach(m->unique.put(m.declaring().name(),m));
            List<Linked> maximal=new ArrayList<>(unique.values());
            for(Linked candidate:unique.values())for(Linked other:unique.values())if(candidate!=other){Boolean sub=subtype(lookup,other.declaring().name(),candidate.declaring().name(),new HashSet<>());if(Boolean.TRUE.equals(sub))maximal.remove(candidate);else if(sub==null)incomplete=true;}
            List<Linked> concrete=maximal.stream().filter(m->(m.member().access()&Opcodes.ACC_ABSTRACT)==0).toList();
            if(maximal.isEmpty())return new Linked(null,null,null,alternatives,true,"Interface hierarchy is cyclic or ambiguous");
            if(concrete.size()>1)return new Linked(null,null,null,alternatives,true,"Multiple unrelated default interface methods prevent unique linkage");
            Linked chosen=concrete.isEmpty()?maximal.get(0):concrete.get(0);
            return new Linked(null,chosen.member(),chosen.declaring(),alternatives,incomplete,incomplete?"A required interface hierarchy could not be resolved":"");
        }
        return new Linked(null,null,null,alternatives,incomplete,incomplete?"A required parent or interface could not be resolved":"");
    }
    /** Null means the supplied hierarchy cannot safely establish the relationship. */
    private static Boolean subtype(Lookup lookup,String child,String parent,Set<String> visited){
        if(child.equals(parent))return true;if(child.equals("java/lang/Object"))return false;if(visited.size()>=128||!visited.add(child))return null;
        Result result=lookup.lookup(child);if(result.state()!=State.FOUND)return null;boolean unknown=false;List<String> ancestors=new ArrayList<>(result.info().interfaces());if(result.info().superName()!=null)ancestors.add(result.info().superName());
        for(String ancestor:ancestors){Boolean match=subtype(lookup,ancestor,parent,new HashSet<>(visited));if(Boolean.TRUE.equals(match))return true;unknown|=match==null;}return unknown?null:false;
    }
    private static Resolution classify(Symbol symbol,Linked current,Linked target,List<Source> sources,Lookup targetLookup){
        if(target.owner().state()==State.INCOMPLETE||target.owner().state()==State.AMBIGUOUS||target.incomplete())return Resolution.UNKNOWN;
        boolean currentExact=current.owner().state()==State.FOUND&&!current.incomplete()&&(symbol.kind().equals("CLASS")||current.member()!=null&&current.member().isStatic()==symbol.reference().isStatic());
        if(target.owner().state()==State.ABSENT)return currentExact?Resolution.MISSING_CLASS:Resolution.UNKNOWN;
        if(target.owner().info().majorVersion()>61||target.declaring()!=null&&target.declaring().majorVersion()>61)return Resolution.UNKNOWN;
        if((target.owner().info().access()&Opcodes.ACC_PUBLIC)==0&&sources.stream().anyMatch(s->!packageName(s.sourceClass()).equals(packageName(symbol.owner()))))return Resolution.ACCESS_INCOMPATIBLE;
        if(symbol.kind().equals("METHOD")){
            Boolean expected=symbol.ownerInterface();if(expected==null&&current.owner().state()==State.FOUND)expected=(current.owner().info().access()&Opcodes.ACC_INTERFACE)!=0;
            if(expected!=null&&expected!=((target.owner().info().access()&Opcodes.ACC_INTERFACE)!=0))return Resolution.INVOCATION_MISMATCH;
        }
        if(symbol.kind().equals("CLASS"))return Resolution.COMPATIBLE;
        if(target.member()==null){if(!currentExact)return Resolution.UNKNOWN;if(!target.alternatives().isEmpty())return Resolution.DESCRIPTOR_MISMATCH;return symbol.kind().equals("FIELD")?Resolution.MISSING_FIELD:Resolution.MISSING_METHOD;}
        if(target.member().isStatic()!=symbol.reference().isStatic())return currentExact?Resolution.INVOCATION_MISMATCH:Resolution.UNKNOWN;
        if(symbol.opcode()==Opcodes.INVOKEINTERFACE&&(target.owner().info().access()&Opcodes.ACC_INTERFACE)==0||symbol.opcode()==Opcodes.INVOKEVIRTUAL&&(target.owner().info().access()&Opcodes.ACC_INTERFACE)!=0)return currentExact?Resolution.INVOCATION_MISMATCH:Resolution.UNKNOWN;
        int access=target.member().access();if((access&(Opcodes.ACC_PUBLIC|Opcodes.ACC_PRIVATE|Opcodes.ACC_PROTECTED))==0&&sources.stream().anyMatch(s->!packageName(s.sourceClass()).equals(packageName(target.declaring().name()))))return Resolution.ACCESS_INCOMPATIBLE;
        if((access&Opcodes.ACC_PRIVATE)!=0&&sources.stream().anyMatch(s->!s.sourceClass().equals(target.declaring().name())))return Resolution.UNKNOWN;
        if((access&Opcodes.ACC_PROTECTED)!=0)for(Source source:sources)if(!packageName(source.sourceClass()).equals(packageName(target.declaring().name()))){Boolean sub=subtype(targetLookup,source.sourceClass(),target.declaring().name(),new HashSet<>());if(Boolean.FALSE.equals(sub))return Resolution.ACCESS_INCOMPATIBLE;if(sub==null||!symbol.reference().isStatic())return Resolution.UNKNOWN;}
        return Resolution.COMPATIBLE;
    }
    private static Proof proof(Linked linked,Symbol symbol){
        String owner=linked.owner().state()==State.FOUND?"found":linked.owner().state()==State.ABSENT?"absent":"unknown";
        String member=symbol.kind().equals("CLASS")?"not-applicable":linked.incomplete()?"unknown":linked.member()!=null?"found":!linked.alternatives().isEmpty()?"descriptor-mismatch":"absent";
        return new Proof(owner,member,linked.owner().origins(),linked.declaring()==null?"":linked.declaring().name(),List.copyOf(linked.alternatives()),linked.detail(),linked.owner().winningOrigin(),linked.owner().shadowedOrigins(),linked.owner().precedenceEvidence());
    }
    private static CompatibilityAnalyzer.CompatibilityIssue finding(SymbolResult result){
        String id=result.resolution()==Resolution.MISSING_CLASS?"LP-API-006":result.resolution()==Resolution.UNKNOWN?"LP-API-003":result.resolution()==Resolution.ACCESS_INCOMPATIBLE?"LP-API-005":"LP-API-001";
        String message=switch(result.resolution()){
            case MISSING_METHOD -> "Historical CorDapp requires an exact method present in the current runtime but missing from the target class hierarchy";
            case MISSING_FIELD -> "Historical CorDapp requires an exact field present in the current runtime but missing from the target class hierarchy";
            case MISSING_CLASS -> "Historical CorDapp requires a class present in the current runtime but absent after complete targeted target lookup";
            case DESCRIPTOR_MISMATCH -> "Required member name exists in the target runtime with an incompatible JVM descriptor";
            case INVOCATION_MISMATCH -> "Required member has incompatible static/instance or class/interface invocation semantics";
            case ACCESS_INCOMPATIBLE -> "Required class or member is inaccessible to the historical CorDapp caller";
            default -> "A required CorDapp compatibility question could not be completely resolved";
        };
        boolean verifierOnly=result.contexts().stream().anyMatch(c->c.context()==ExecutionContext.TARGET_VERIFIER&&blocked(c.resolution()))&&result.contexts().stream().noneMatch(c->c.context()==ExecutionContext.TARGET_NODE_RUNTIME&&blocked(c.resolution()));
        if(verifierOnly)message=switch(result.resolution()){
            case MISSING_METHOD -> "Historical CorDapp requires an exact method present in the current runtime but missing from the target external verifier class hierarchy";
            case MISSING_FIELD -> "Historical CorDapp requires an exact field present in the current runtime but missing from the target external verifier class hierarchy";
            case MISSING_CLASS -> "Historical CorDapp requires a class present in the current runtime but absent after complete targeted external verifier lookup";
            case DESCRIPTOR_MISMATCH -> "Required member name exists in the target external verifier with an incompatible JVM descriptor";
            case INVOCATION_MISMATCH -> "Required member has incompatible invocation semantics in the target external verifier";
            case ACCESS_INCOMPATIBLE -> "Required class or member is inaccessible to the historical CorDapp caller in the target external verifier";
            default -> message;
        };
        return issue(id,result.resolution()==Resolution.UNKNOWN?"UNKNOWN":"BLOCKED",message,evidence(result),result.resolution()==Resolution.UNKNOWN?"Supply the missing current/target runtime or required dependency evidence, then validate again.":verifierOnly?"Use a compatible target external verifier or supported compatibility fix, then validate historical transactions again with TVU.":"Use a compatible target runtime or supported compatibility fix, then validate again with TVU.");
    }
    private static Map<String,String> evidence(SymbolResult result){
        Symbol symbol=result.symbol();List<Source> affected=affectedSources(result);Map<String,String> data=new TreeMap<>();data.put("sourceScope","active-current-cordapp");data.put("ownerInterface",Objects.toString(symbol.ownerInterface(),"unknown"));int n=0;for(String artifact:affected.stream().map(Source::sourceArtifact).distinct().sorted().toList())data.put(++n==1?"sourceArtifact":"sourceArtifact."+n,artifact);
        if(!affected.isEmpty()){Source source=affected.get(0);data.put("jar",source.sourceArtifact());data.put("class",source.sourceClass());data.put("sourceClass",source.sourceClass());data.put("sourceMethod",source.sourceMethod());data.put("referenceType",source.referenceType());}
        data.put("owner",symbol.owner());data.put("member",symbol.member());data.put("descriptor",symbol.descriptor());data.put("kind",symbol.kind());data.put("symbol",symbol.display());data.put("invocationOpcode",Integer.toString(symbol.opcode()));data.put("referencedClasses",Long.toString(affected.stream().map(s->s.sourceArtifact()+"!/"+s.sourceClass()).distinct().count()));data.put("referenceSites",Integer.toString(affected.size()));
        data.put("currentClass",result.current().classStatus());data.put("currentMember",result.current().memberStatus());data.put("currentArtifact",String.join("; ",result.current().artifacts()));data.put("currentDeclaringClass",result.current().declaringClass());data.put("targetClass",result.target().classStatus());data.put("targetMember",result.target().memberStatus());data.put("targetJar",String.join("; ",result.target().artifacts()));data.put("targetDeclaringClass",result.target().declaringClass());data.put("targetAvailableDescriptors",result.target().availableDescriptors().toString());data.put("requiredMember",result.target().memberStatus().equals("found")?"present":result.target().memberStatus().equals("unknown")?"unknown":"absent");data.put("resolution",resolutionName(result.resolution()));data.put("currentResolutionDetail",result.current().detail());data.put("targetResolutionDetail",result.target().detail());
        data.put("blockedContexts",contextNames(result,c->blocked(c.resolution())));data.put("unknownContexts",contextNames(result,c->c.resolution()==Resolution.UNKNOWN));
        for(ContextResult context:result.contexts()){
            String prefix=switch(context.context()){case CURRENT_NODE_RUNTIME->"current";case TARGET_NODE_RUNTIME->"target";case TARGET_VERIFIER->"verifier";};
            data.put(prefix+"Resolution",resolutionName(context.resolution()));data.put(prefix+"WinningArtifact",context.proof().winningArtifact());data.put(prefix+"ShadowedArtifacts",String.join("; ",context.proof().shadowedArtifacts()));data.put(prefix+"PrecedenceEvidence",context.proof().precedenceEvidence());
            if(context.context()==ExecutionContext.TARGET_NODE_RUNTIME)data.put("nodeResolution",resolutionName(context.resolution()));
            if(context.context()==ExecutionContext.TARGET_VERIFIER){Proof proof=context.proof();data.put("verifierClass",proof.classStatus());data.put("verifierMember",proof.memberStatus());data.put("verifierJar",String.join("; ",proof.artifacts()));data.put("verifierDeclaringClass",proof.declaringClass());data.put("verifierAvailableDescriptors",proof.availableDescriptors().toString());data.put("verifierResolutionDetail",proof.detail());data.put("verifierReferenceSites",Integer.toString(context.sources().size()));}
        }
        return data;
    }
    private static List<Source> affectedSources(SymbolResult result){
        List<Source> affected=result.contexts().stream().filter(c->c.context()!=ExecutionContext.CURRENT_NODE_RUNTIME).filter(c->blocked(result.resolution())?blocked(c.resolution()):c.resolution()==Resolution.UNKNOWN).flatMap(c->c.sources().stream()).distinct().toList();
        return affected.isEmpty()?result.sources():affected;
    }
    private static String contextNames(SymbolResult result,Predicate<ContextResult> selected){return String.join(",",result.contexts().stream().filter(c->c.context()!=ExecutionContext.CURRENT_NODE_RUNTIME).filter(selected).map(c->c.context().name()).toList());}
    private static String resolutionName(Resolution resolution){return resolution.name().toLowerCase(Locale.ROOT).replace('_','-');}
    private static String physical(String artifact){int nested=artifact.indexOf("!/");return nested<0?artifact:artifact.substring(0,nested);}
    private static String packageName(String name){int slash=name.lastIndexOf('/');return slash<0?"":name.substring(0,slash);}
    private static boolean internal(String name){return name.startsWith("net/corda/")&&Arrays.stream(name.split("/")).anyMatch(s->s.equalsIgnoreCase("internal"));}
    private static boolean platform(String name){return name.startsWith("java/")||name.startsWith("jdk/")||name.startsWith("sun/")||List.of("javax/crypto/","javax/net/","javax/security/","javax/management/","javax/naming/","javax/sql/","javax/swing/","javax/imageio/","javax/print/","javax/sound/","javax/tools/","javax/lang/model/","javax/annotation/processing/","javax/xml/parsers/","javax/xml/transform/","javax/xml/xpath/","javax/xml/validation/","javax/xml/datatype/","javax/xml/namespace/","javax/xml/stream/").stream().anyMatch(name::startsWith);}
    private static boolean objectMethod(String name,String descriptor){return Set.of("toString()Ljava/lang/String;","hashCode()I","equals(Ljava/lang/Object;)Z","getClass()Ljava/lang/Class;","notify()V","notifyAll()V","wait()V","wait(J)V","wait(JI)V").contains(name+descriptor);}
    private static String referenceType(Reference ref){return switch(ref.opcode()){case Opcodes.INVOKESTATIC->"INVOKESTATIC";case Opcodes.INVOKEVIRTUAL->"INVOKEVIRTUAL";case Opcodes.INVOKEINTERFACE->"INVOKEINTERFACE";case Opcodes.INVOKESPECIAL->"INVOKESPECIAL";case Opcodes.GETSTATIC->"GETSTATIC";case Opcodes.PUTSTATIC->"PUTSTATIC";case Opcodes.GETFIELD->"GETFIELD";case Opcodes.PUTFIELD->"PUTFIELD";default->ref.kind();};}
    private static CompatibilityAnalyzer.CompatibilityIssue issue(String id,String severity,String message,Map<String,String> evidence,String action){return new CompatibilityAnalyzer.CompatibilityIssue(id,severity,message,Collections.unmodifiableMap(new TreeMap<>(evidence)),action);}
}
