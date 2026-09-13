package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import java.util.*;
import java.util.regex.*;

/** Artifact identity is derived from metadata and bytecode, never customer names or filenames. */
public final class Discovery {
    public record Artifact(String path,String role,String version,String confidence,String sha256,int classes,int maxBytecode,Map<String,String> manifest,List<String> signatureFiles) {}
    public static List<Artifact> inventory(ScanResult scan) {
        return scan.jars().stream().map(j->new Artifact(j.path(),role(j),version(j),confidence(j),j.sha256(),j.classes().size(),j.classes().values().stream().mapToInt(ClassInfo::majorVersion).max().orElse(0),safeManifest(j.manifest()),j.signatureFiles())).toList();
    }
    public static String role(JarInventory j) {
        String path=j.path().toLowerCase(Locale.ROOT),main=(attr(j,"Main-Class")+" "+attr(j,"Application-Class")+" "+attr(j,"Start-Class")+" "+attr(j,"Application-ID")).toLowerCase(Locale.ROOT);
        if(path.startsWith("drivers/")||attr(j,"Physical-Scope").equals("drivers"))return "DRIVER";
        if(path.startsWith("legacy-jars/"))return "LEGACY";
        if(path.startsWith("legacy-contracts/"))return "LEGACY_CONTRACT";
        if(!attr(j,"Cordapp-Contract-Name").isBlank()||!attr(j,"Cordapp-Workflow-Name").isBlank())return attr(j,"Physical-Scope").equals("root")?"SUPPORT":"CORDAPP";
        if(attr(j,"TVU-Entry-Evidence").equals("true")||main.contains("net.corda.transactionvalidator.") || main.contains("net.corda.tools.transactionvalidator") || main.contains("net.corda.tools.transaction.validator") || j.classes().keySet().stream().anyMatch(c->c.startsWith("net/corda/transactionvalidator/")||c.startsWith("net/corda/tools/transactionvalidator/")||c.equals("net/corda/tools/TransactionValidator")))return "TVU";
        if(main.contains("verifier") || j.classes().containsKey("net/corda/verifier/Main"))return "VERIFIER";
        if(main.contains("net.corda.node.") || j.classes().containsKey("net/corda/node/Corda") || j.classes().containsKey("net/corda/node/internal/Node"))return "RUNTIME";
        if(!j.cordappEntrypoints().isEmpty() || j.classes().keySet().stream().anyMatch(c->!c.startsWith("net/corda/core/")&&cordappType(c,j.classes(),new HashSet<>())))return attr(j,"Physical-Scope").equals("root")?"SUPPORT":"CORDAPP";
        if(j.classes().keySet().stream().anyMatch(c->c.startsWith("net/corda/core/")))return "RUNTIME_LIBRARY";
        if(path.startsWith("drivers/") || j.classes().values().stream().anyMatch(c->c.interfaces().contains("java/sql/Driver")))return "DRIVER";
        if(main.contains("shell"))return "SHELL";
        return "UNKNOWN";
    }
    public static boolean cordappHeader(ClassInfo c){return java.util.stream.Stream.concat(java.util.stream.Stream.of(c.superName()),c.interfaces().stream()).filter(Objects::nonNull).anyMatch(x->Set.of("net/corda/core/contracts/Contract","net/corda/core/contracts/UpgradedContract","net/corda/core/contracts/ContractState","net/corda/core/flows/FlowLogic").contains(x));}
    private static boolean cordappType(String name,Map<String,ClassInfo> classes,Set<String> seen){
        if(name==null)return false;Deque<String> pending=new ArrayDeque<>();pending.add(name);
        while(!pending.isEmpty()){String next=pending.removeFirst();if(!seen.add(next))continue;
            if(Set.of("net/corda/core/contracts/Contract","net/corda/core/contracts/UpgradedContract","net/corda/core/contracts/ContractState","net/corda/core/flows/FlowLogic").contains(next))return true;
            ClassInfo c=classes.get(next);if(c!=null){if(c.superName()!=null)pending.add(c.superName());pending.addAll(c.interfaces());}}
        return false;
    }
    private static String confidence(JarInventory j) { return role(j).equals("UNKNOWN")?"UNKNOWN":"HIGH"; }
    public static String version(JarInventory j) {
        List<String> explicit=new ArrayList<>();
        for(String key:List.of("Corda-Release-Version","Corda-Version","Application-Version")){if(attr(j,"Metadata-Conflict").toLowerCase(Locale.ROOT).contains(key.toLowerCase(Locale.ROOT)))return "unknown";String value=release(attr(j,key));if(!value.equals("unknown"))explicit.add(value);}
        if(!explicit.isEmpty())return explicit.stream().distinct().count()==1?explicit.get(0):"unknown";
        for(String key:List.of("Implementation-Version","Bundle-Version")) {
            String value=release(attr(j,key));if(!value.equals("unknown"))return value;
        }
        return "unknown";
    }
    private static String release(String value){
            Matcher m=Pattern.compile("(?<![0-9])(4\\.\\d+(?:\\.\\d+)?)(?:[-.][A-Za-z0-9]+)*").matcher(value);
            if(m.find())return m.group();
        return "unknown";
    }
    public static String attr(JarInventory j,String key){return j.manifest().entrySet().stream().filter(e->e.getKey().equalsIgnoreCase(key)).map(Map.Entry::getValue).findFirst().orElse("");}
    private static Map<String,String> safeManifest(Map<String,String> manifest) {
        Map<String,String> safe=new TreeMap<>();
        Set<String> allowed=new TreeSet<>(String.CASE_INSENSITIVE_ORDER);allowed.addAll(List.of("Physical-Scope","Identity-Class-Names-Truncated","TVU-Entry-Evidence","Manifest-Version","Main-Class","Application-Class","Application-ID","Application-Version","Min-Java-Version","Corda-OpenCore-Version","Corda-Revision","Start-Class","Implementation-Version","Corda-Platform-Version","Platform-Version","Corda-Vendor","Implementation-Vendor","Metadata-Origin","Metadata-Conflict","Corda-Release-Version","Corda-Version","Multi-Release","Cordapp-Contract-Name","Cordapp-Contract-Version","Cordapp-Contract-Vendor","Cordapp-Workflow-Name","Cordapp-Workflow-Version","Cordapp-Workflow-Vendor","Min-Platform-Version","Target-Platform-Version"));
        for(var e:manifest.entrySet())if(allowed.contains(e.getKey()))safe.put(e.getKey(),e.getValue());
        return safe;
    }
    public static String platform(JarInventory j){if(attr(j,"Metadata-Conflict").contains("Platform-Version"))return "unknown";String value=attr(j,"Corda-Platform-Version");return value.isEmpty()?attr(j,"Platform-Version"):value;}
    public static List<JarInventory> topLevel(List<JarInventory> jars){return jars.stream().filter(j->jars.stream().noneMatch(parent->j.path().startsWith(parent.path()+"!/"))).toList();}
    public static String uniqueVersion(List<JarInventory> jars){var physical=topLevel(jars);return physical.size()==1?version(physical.get(0)):"unknown";}
    public static List<JarInventory> otherJars(ScanResult scan){return topLevel(scan.jars()).stream().filter(j->!Set.of("RUNTIME","TVU","CORDAPP","LEGACY_CONTRACT").contains(role(j))).toList();}
    public record Model(String sourceVersion,String targetVersion,String sourcePlatform,String targetPlatform,String sourceMinimumJava,String targetMinimumJava,int currentCordappJars,int targetCordappJars,int currentOtherJars,int targetOtherJars,String confidence,List<String> confidenceReasons){}
    /** Optional business role and safely excluded external links do not erase established identity. */
    public static Model model(ScanResult current,ScanResult target,List<JarInventory> oldRuntime,List<JarInventory> runtime,List<JarInventory> tvu,List<JarInventory> apps,Map<String,Object> config){
        String source=uniqueVersion(oldRuntime),destination=uniqueVersion(runtime);List<String> reasons=new ArrayList<>();
        if(source.equals("unknown")||destination.equals("unknown"))reasons.add("Current and target runtime identities must each be unambiguous");
        boolean unknown=!reasons.isEmpty();
        if(!"HIGH".equals(config.get("schemaConfidence")))reasons.add("Schema is not corroborated by matching explicit declarations");
        if(!"HIGH".equals(config.get("configurationConfidence"))||"Unknown".equals(config.getOrDefault("databaseVendor","Unknown")))reasons.add("Configuration or database vendor evidence is incomplete");
        if(topLevel(tvu).size()!=1||!uniqueVersion(tvu).equals(destination))reasons.add("One matching target TVU has not been established");
        int oldApps=topLevel(select(current,"CORDAPP","LEGACY_CONTRACT")).size(),newApps=topLevel(apps).size();
        if(oldApps==0||newApps==0)reasons.add("CorDapp evidence is incomplete; a node with no applications requires review");
        return new Model(source,destination,metadata(oldRuntime,true),metadata(runtime,true),metadata(oldRuntime,false),metadata(runtime,false),oldApps,newApps,otherJars(current).size(),otherJars(target).size(),unknown?"UNKNOWN":reasons.isEmpty()?"HIGH":"MEDIUM",List.copyOf(reasons));
    }
    private static String metadata(List<JarInventory> jars,boolean platform){var physical=topLevel(jars);if(physical.size()!=1)return "Unknown";String value=platform?platform(physical.get(0)):attr(physical.get(0),"Min-Java-Version");return value.isBlank()?"Unknown":value;}
    public static String displayName(Map<String,Object> settings,String fallback){
        try{var name=new javax.naming.ldap.LdapName(Objects.toString(settings.get("myLegalName"),""));for(String field:List.of("CN","O"))for(var rdn:name.getRdns())if(rdn.getType().equalsIgnoreCase(field))return rdn.getValue().toString();}catch(javax.naming.InvalidNameException ignored){}return fallback;
    }
    public static List<JarInventory> select(ScanResult scan,String... roles) {Set<String> accepted=Set.of(roles);return scan.jars().stream().filter(j->accepted.contains(role(j))).filter(j->scan.jars().stream().noneMatch(parent->j.path().startsWith(parent.path()+"!/")&&Set.of("RUNTIME","TVU","CORDAPP","LEGACY","LEGACY_CONTRACT","VERIFIER","DRIVER","SHELL").contains(role(parent))&&!accepted.contains(role(parent)))).toList();}
}
