package io.ledgerpreflight.bytecode;

import java.util.*;
import org.objectweb.asm.Opcodes;
import static io.ledgerpreflight.bytecode.BytecodeScanner.*;

/** Conservative symbolic linkage checks; runtime bytes take precedence over version guesses. */
public final class CompatibilityAnalyzer {
    public record CompatibilityIssue(String id,String severity,String message,Map<String,String> evidence,String nextAction) {}
    private record Located(JarInventory jar,ClassInfo info) {}
    private record Resolution(Member member,ClassInfo declaring,boolean incomplete) {}
    public List<CompatibilityIssue> analyze(List<JarInventory> consumers,List<JarInventory> runtime,List<JarInventory> legacy,boolean runtimePrecedenceProven){
        List<CompatibilityIssue> findings=new EvidenceList();Map<String,List<Located>> runtimeIndex=index(runtime),legacyIndex=index(legacy);
        Map<String,List<Located>> consumerIndex=index(consumers);
        Map<String,List<Located>> all=index(runtime); merge(all,consumerIndex);merge(all,legacyIndex);
        for(var entry:consumerIndex.entrySet())if(entry.getValue().size()>1||runtimeIndex.containsKey(entry.getKey()))findings.add(issue("LP-API-004","WARNING","Consumer class has multiple supplied definitions; actual class loading must be established",Map.of("class",entry.getKey(),"consumerArtifacts",entry.getValue().stream().map(l->l.jar.path()).sorted().toList().toString()),"Remove duplicate classes or establish actual class-loader selection with supplied runtime evidence."));
        for(var entry:runtimeIndex.entrySet())if(entry.getValue().size()>1)findings.add(issue("LP-API-004","WARNING","Multiple target artifacts define the same class; runtime selection is unresolved",Map.of("class",entry.getKey(),"artifacts",entry.getValue().stream().map(l->l.jar.path()).sorted().toList().toString()),"Supply the external verifier's actual classpath and selected runtime artifacts."));
        for(JarInventory jar:consumers)for(ClassInfo source:jar.classes().values()){
            if(source.majorVersion()>61)findings.add(issue("LP-JAVA-003","BLOCKED","Class bytecode requires a JVM newer than Java 17",Map.of("jar",jar.path(),"class",source.name(),"majorVersion",Integer.toString(source.majorVersion())),"Rebuild this artifact for the target Java 17 runtime."));
            Set<String> internalSeen=new HashSet<>();
            for(Reference ref:source.references()){
                Map<String,String> evidence=evidence(jar,source,ref);
                if(internal(ref.owner())&&internalSeen.add(ref.symbol()))findings.add(issue("LP-INTERNAL-001","WARNING","CorDapp references an internal Corda API; internal APIs have no normal stability guarantee",evidence,"Replace internal API use with a supported API, or validate the exact supplied runtime and historical transactions with TVU."));
                if(jdk(ref.owner())||ref.owner().startsWith("["))continue;
                List<Located> definitions=all.get(ref.owner());
                if(definitions==null){
                    if(!ref.kind().equals("CLASS")||ref.owner().startsWith("net/corda/"))findings.add(issue("LP-API-003","WARNING","Referenced class is absent from supplied inventories; runtime completeness is unknown",evidence,"Supply the complete target/verifier dependency classpath and rerun assessment."));
                    continue;
                }
                if(ref.kind().equals("CLASS"))continue;
                List<Located> targetDefinitions=runtimeIndex.get(ref.owner());
                if(targetDefinitions!=null&&targetDefinitions.size()>1)continue;
                Located selected=definitions.get(0);Resolution resolution=resolve(selected.info,ref,all,new HashSet<>(),0);
                if(resolution.member==null){
                    Map<String,String> enriched=new TreeMap<>(evidence);enriched.put("targetJar",selected.jar.path());enriched.put("targetClass","present");enriched.put("requiredMember","absent");
                    findings.add(issue("LP-API-001",resolution.incomplete?"WARNING":"BLOCKED",resolution.incomplete?"Exact member was not found, but an ancestor is unavailable; linkage cannot be fully determined":"Required exact JVM member is absent from the supplied target class hierarchy; transaction verification may fail",enriched,resolution.incomplete?"Supply missing parent/interface bytecode before concluding the member was removed.":"Resolve the missing member with a supported runtime or rebuilt CorDapp, then rerun TVU."));
                }else if(resolution.member.isStatic()!=ref.isStatic())findings.add(issue("LP-API-001","BLOCKED","Required member has incompatible static/instance invocation semantics",evidence,"Use a supported runtime and compile against its exact member signature."));
                else if((resolution.member.access()&Opcodes.ACC_PRIVATE)!=0&&!source.name().equals(resolution.declaring.name()))findings.add(issue("LP-API-005","WARNING","Referenced member is private; access requires valid nestmate metadata or will fail",evidence,"Verify nestmate access and validate linkage in the supplied runtime."));
                else if((resolution.member.access()&(Opcodes.ACC_PUBLIC|Opcodes.ACC_PRIVATE|Opcodes.ACC_PROTECTED))==0&&!packageName(source.name()).equals(packageName(resolution.declaring.name())))findings.add(issue("LP-API-005","BLOCKED","Referenced member is package-private in a different package",evidence,"Rebuild against supported public APIs."));
            }
        }
        for(var entry:legacyIndex.entrySet()){
            if(entry.getValue().size()>1)findings.add(issue("LP-LEGACY-002","WARNING","Multiple legacy artifacts define the same class; loading order selects one whole definition",Map.of("class",entry.getKey(),"legacyJars",entry.getValue().stream().map(l->l.jar.path()).sorted().toList().toString()),"Remove unnecessary duplicate dependencies and verify external verifier classpath order."));
            List<Located> targets=runtimeIndex.get(entry.getKey());if(targets==null)continue;
            for(Located shim:entry.getValue())for(Located target:targets){
                Set<Member> additions=new TreeSet<>(Comparator.comparing(Member::kind).thenComparing(Member::name).thenComparing(Member::descriptor));
                for(Member member:shim.info.members())if(target.info.members().stream().noneMatch(m->same(m,member)))additions.add(member);
                Map<String,String> evidence=new TreeMap<>();evidence.put("class",entry.getKey());evidence.put("runtimeJar",target.jar.path());evidence.put("legacyJar",shim.jar.path());evidence.put("legacyOnlyMembers",additions.toString());evidence.put("classpathOrder",runtimePrecedenceProven?"runtime precedes legacy (user-supplied evidence)":"unproven");
                boolean augmentation=!additions.isEmpty();
                findings.add(issue("LP-LEGACY-001",runtimePrecedenceProven&&augmentation?"BLOCKED":"WARNING",runtimePrecedenceProven&&augmentation?"Legacy remediation is shadowed: Java loads a whole class and cannot add members from the later duplicate":"Potential duplicate-class shadowing: Java does not merge members from multiple definitions",evidence,"Use a vendor-supported runtime fix; establish actual verifier classpath order and class-load origin before relying on a legacy shim."));
            }
        }
        return completed(findings).stream().distinct().sorted(Comparator.comparing(CompatibilityIssue::id).thenComparing(CompatibilityIssue::message).thenComparing(i->i.evidence().toString())).toList();
    }
    public List<CompatibilityIssue> compare(List<JarInventory> source,List<JarInventory> target){
        List<CompatibilityIssue> result=new EvidenceList();Map<String,List<Located>> targetIndex=index(target);
        for(JarInventory jar:source)for(ClassInfo cls:jar.classes().values()){
            List<Located> found=targetIndex.get(cls.name());
            if(found==null){result.add(issue("LP-DELTA-001","INFO","Class absent from target inventory",Map.of("sourceJar",jar.path(),"class",cls.name()),"Check whether consuming bytecode references this class."));continue;}
            for(Member member:cls.members())if(found.get(0).info.members().stream().noneMatch(m->same(m,member)))result.add(issue("LP-DELTA-002","INFO","Declared member absent from target class (may have moved to an ancestor)",Map.of("sourceJar",jar.path(),"class",cls.name(),"member",member.name(),"descriptor",member.descriptor(),"kind",member.kind()),"Assess consuming bytecode for effective inherited-member compatibility."));
        }
        return completed(result).stream().sorted(Comparator.comparing(i->i.evidence().toString())).toList();
    }
    private static final class EvidenceList extends ArrayList<CompatibilityIssue> {
        boolean limited;long evidenceBytes;
        @Override public boolean add(CompatibilityIssue issue){long size=issue.evidence().entrySet().stream().mapToLong(e->2L*(e.getKey().length()+e.getValue().length())).sum();if(size()>=512||evidenceBytes+size>1024*1024){limited=true;return false;}evidenceBytes+=size;return super.add(issue);}
    }
    private static List<CompatibilityIssue> completed(List<CompatibilityIssue> list){
        if(list instanceof EvidenceList bounded&&bounded.limited){var result=new ArrayList<>(list);result.add(issue("LP-ANALYSIS-LIMIT","UNKNOWN","Compatibility finding count/size limit reached; remaining findings were not retained",Map.of("retainedFindings",Integer.toString(list.size()),"maximumFindingBytes","1048576"),"Review supplied artifacts and complete bounded compatibility analysis before upgrading."));return result;}return list;
    }
    private static boolean same(Member left,Member right){return left.kind().equals(right.kind())&&left.name().equals(right.name())&&left.descriptor().equals(right.descriptor())&&left.isStatic()==right.isStatic();}
    private static Resolution resolve(ClassInfo info,Reference ref,Map<String,List<Located>> classes,Set<String> visited,int depth){
        if(depth>128)return new Resolution(null,null,true);
        if(!visited.add(info.name()))return new Resolution(null,null,false);
        for(Member member:info.members())if(member.kind().equals(ref.kind())&&member.name().equals(ref.name())&&member.descriptor().equals(ref.descriptor()))return new Resolution(member,info,false);
        if(ref.name().equals("<init>")||ref.name().equals("<clinit>")||(ref.isStatic()&&(info.access()&Opcodes.ACC_INTERFACE)!=0))return new Resolution(null,null,false);
        boolean incomplete=false;List<String> parents=new ArrayList<>();
        if(ref.kind().equals("FIELD")){parents.addAll(info.interfaces());if(info.superName()!=null)parents.add(info.superName());}else{if(info.superName()!=null)parents.add(info.superName());if(!ref.isStatic())parents.addAll(info.interfaces());}
        for(String parent:parents){
            if(parent.equals("java/lang/Object")){
                if(ref.kind().equals("METHOD")&&!ref.isStatic()&&objectMethod(ref.name(),ref.descriptor()))return new Resolution(new Member("METHOD",ref.name(),ref.descriptor(),Opcodes.ACC_PUBLIC),info,false);
                continue;
            }
            List<Located> definitions=classes.get(parent);if(definitions==null||definitions.size()>1){incomplete=true;continue;}
            Resolution found=resolve(definitions.get(0).info,ref,classes,visited,depth+1);if(found.member!=null)return found;incomplete|=found.incomplete;
        }
        return new Resolution(null,null,incomplete);
    }
    private static boolean objectMethod(String name,String descriptor){return Set.of("toString()Ljava/lang/String;","hashCode()I","equals(Ljava/lang/Object;)Z","getClass()Ljava/lang/Class;","notify()V","notifyAll()V","wait()V","wait(J)V","wait(JI)V").contains(name+descriptor);}
    private static String packageName(String name){int slash=name.lastIndexOf('/');return slash<0?"":name.substring(0,slash);}
    private static boolean jdk(String name){return name.startsWith("java/")||name.startsWith("jdk/")||name.startsWith("sun/")||List.of("javax/crypto/","javax/net/","javax/security/","javax/management/","javax/naming/","javax/sql/","javax/swing/","javax/imageio/","javax/print/","javax/sound/","javax/tools/","javax/lang/model/","javax/annotation/processing/","javax/xml/parsers/","javax/xml/transform/","javax/xml/xpath/","javax/xml/validation/","javax/xml/datatype/","javax/xml/namespace/","javax/xml/stream/").stream().anyMatch(name::startsWith);}
    private static boolean internal(String name){return name.startsWith("net/corda/")&&name.toLowerCase(Locale.ROOT).contains("internal");}
    private static Map<String,List<Located>> index(List<JarInventory> jars){Map<String,List<Located>> result=new TreeMap<>();for(JarInventory jar:jars)for(ClassInfo cls:jar.classes().values())result.computeIfAbsent(cls.name(),key->new ArrayList<>()).add(new Located(jar,cls));return result;}
    private static void merge(Map<String,List<Located>> into,Map<String,List<Located>> extra){extra.forEach((name,values)->into.computeIfAbsent(name,key->new ArrayList<>()).addAll(values));}
    private static Map<String,String> evidence(JarInventory jar,ClassInfo source,Reference ref){Map<String,String> data=new TreeMap<>();data.put("jar",jar.path());data.put("class",source.name());data.put("sourceMethod",ref.sourceMethod());data.put("owner",ref.owner());data.put("member",ref.name());data.put("descriptor",ref.descriptor());data.put("kind",ref.kind());data.put("symbol",ref.symbol());return data;}
    private static CompatibilityIssue issue(String id,String severity,String message,Map<String,String> evidence,String nextAction){return new CompatibilityIssue(id,severity,message,Collections.unmodifiableMap(new TreeMap<>(evidence)),nextAction);}
}
