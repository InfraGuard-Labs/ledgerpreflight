package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import java.util.*;
import java.util.regex.*;

/** Classification combines bytecode, manifest and directory context; names alone are hints. */
public final class Discovery {
    public record Artifact(String path,String role,String version,String confidence,String sha256,int classes,int maxBytecode,Map<String,String> manifest,List<String> signatureFiles) {}
    public static List<Artifact> inventory(ScanResult scan) {
        return scan.jars().stream().map(j->new Artifact(j.path(),role(j),version(j),confidence(j),j.sha256(),j.classes().size(),j.classes().values().stream().mapToInt(ClassInfo::majorVersion).max().orElse(0),safeManifest(j.manifest()),j.signatureFiles())).toList();
    }
    public static String role(JarInventory j) {
        String path=j.path().toLowerCase(Locale.ROOT),main=(attr(j,"Main-Class")+" "+attr(j,"Application-Class")+" "+attr(j,"Start-Class")).toLowerCase(Locale.ROOT);
        if(path.startsWith("legacy-jars/"))return "LEGACY";
        if(path.startsWith("legacy-contracts/"))return "LEGACY_CONTRACT";
        if(("/"+path.split("!",2)[0]).contains("/cordapps/"))return "CORDAPP";
        if(attr(j,"Implementation-Title").toLowerCase(Locale.ROOT).contains("transaction-validator") || main.contains("transactionvalidator") || main.contains("transaction.validator") || j.classes().keySet().stream().anyMatch(c->c.toLowerCase(Locale.ROOT).contains("transactionvalidator")))return "TVU";
        if(main.contains("verifier") || j.classes().containsKey("net/corda/verifier/Main"))return "VERIFIER";
        if(main.contains("corda") && (main.contains("node") || main.contains("capsule")) || j.classes().containsKey("net/corda/node/Corda") || j.classes().containsKey("net/corda/node/internal/Node"))return "RUNTIME";
        if(j.manifest().keySet().stream().anyMatch(k->k.toLowerCase(Locale.ROOT).startsWith("cordapp-")) || j.classes().values().stream().anyMatch(c->c.interfaces().contains("net/corda/core/contracts/Contract") || "net/corda/core/flows/FlowLogic".equals(c.superName())))return "CORDAPP";
        if(path.startsWith("drivers/") || j.classes().values().stream().anyMatch(c->c.interfaces().contains("java/sql/Driver")))return "DRIVER";
        if(main.contains("shell"))return "SHELL";
        if(j.classes().keySet().stream().anyMatch(c->c.startsWith("net/corda/core/")))return "RUNTIME_LIBRARY";
        return "UNKNOWN";
    }
    private static String confidence(JarInventory j) { return role(j).equals("UNKNOWN")?"UNKNOWN":"HIGH"; }
    public static String version(JarInventory j) {
        if(attr(j,"Metadata-Conflict").contains("Corda-Release-Version"))return "unknown";
        for(String key:List.of("Corda-Release-Version","Corda-Version","Application-Version","Implementation-Version","Bundle-Version")) {
            String value=attr(j,key);Matcher m=Pattern.compile("(?<![0-9])(4\\.\\d+(?:\\.\\d+)?)(?:[-.][A-Za-z0-9]+)*").matcher(value);
            if(m.find())return m.group();
        }
        return "unknown";
    }
    public static String attr(JarInventory j,String key){return j.manifest().entrySet().stream().filter(e->e.getKey().equalsIgnoreCase(key)).map(Map.Entry::getValue).findFirst().orElse("");}
    private static Map<String,String> safeManifest(Map<String,String> manifest) {
        Map<String,String> safe=new TreeMap<>();
        for(var e:manifest.entrySet())if(Set.of("Manifest-Version","Main-Class","Application-Class","Application-Version","Start-Class","Implementation-Version","Corda-Platform-Version","Platform-Version","Corda-Vendor","Implementation-Vendor","Metadata-Origin","Metadata-Conflict","Corda-Release-Version","Corda-Version","Multi-Release","Cordapp-Contract-Name","Cordapp-Contract-Version","Cordapp-Workflow-Name","Cordapp-Workflow-Version","Min-Platform-Version","Target-Platform-Version").contains(e.getKey()))safe.put(e.getKey(),e.getValue());
        return safe;
    }
    public static String platform(JarInventory j){if(attr(j,"Metadata-Conflict").contains("Platform-Version"))return "unknown";String value=attr(j,"Corda-Platform-Version");return value.isEmpty()?attr(j,"Platform-Version"):value;}
    public static List<JarInventory> topLevel(List<JarInventory> jars){return jars.stream().filter(j->jars.stream().noneMatch(parent->j.path().startsWith(parent.path()+"!/"))).toList();}
    public static String displayName(Map<String,Object> settings,String fallback){
        try{var name=new javax.naming.ldap.LdapName(Objects.toString(settings.get("myLegalName"),""));for(String field:List.of("CN","O"))for(var rdn:name.getRdns())if(rdn.getType().equalsIgnoreCase(field))return rdn.getValue().toString();}catch(javax.naming.InvalidNameException ignored){}return fallback;
    }
    public static List<JarInventory> select(ScanResult scan,String... roles) {Set<String> accepted=Set.of(roles);return scan.jars().stream().filter(j->accepted.contains(role(j))).filter(j->scan.jars().stream().noneMatch(parent->j.path().startsWith(parent.path()+"!/")&&Set.of("RUNTIME","TVU","CORDAPP","LEGACY","LEGACY_CONTRACT","VERIFIER","DRIVER","SHELL").contains(role(parent))&&!accepted.contains(role(parent)))).toList();}
}
