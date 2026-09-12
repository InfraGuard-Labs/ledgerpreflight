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
        String path=j.path().toLowerCase(Locale.ROOT),main=attr(j,"Main-Class").toLowerCase(Locale.ROOT);
        if(path.startsWith("legacy-jars/"))return "LEGACY";
        if(path.startsWith("legacy-contracts/"))return "LEGACY_CONTRACT";
        if(path.startsWith("cordapps/"))return "CORDAPP";
        if(main.contains("transactionvalidator") || main.contains("transaction.validator") || j.classes().keySet().stream().anyMatch(c->c.toLowerCase(Locale.ROOT).contains("transactionvalidator")))return "TVU";
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
        for(String key:List.of("Corda-Release-Version","Corda-Version","Implementation-Version","Bundle-Version")) {
            String value=attr(j,key);Matcher m=Pattern.compile("(?<![0-9])(4\\.\\d+(?:\\.\\d+)?)(?:[-.][A-Za-z0-9]+)*").matcher(value);
            if(m.find())return m.group();
        }
        return "unknown";
    }
    public static String attr(JarInventory j,String key){return j.manifest().entrySet().stream().filter(e->e.getKey().equalsIgnoreCase(key)).map(Map.Entry::getValue).findFirst().orElse("");}
    private static Map<String,String> safeManifest(Map<String,String> manifest) {
        Map<String,String> safe=new TreeMap<>();
        for(var e:manifest.entrySet())if(Set.of("Manifest-Version","Main-Class","Implementation-Version","Corda-Release-Version","Corda-Version","Multi-Release","Cordapp-Contract-Name","Cordapp-Contract-Version","Cordapp-Workflow-Name","Cordapp-Workflow-Version","Min-Platform-Version","Target-Platform-Version").contains(e.getKey()))safe.put(e.getKey(),e.getValue());
        return safe;
    }
    public static List<JarInventory> select(ScanResult scan,String... roles) {Set<String> accepted=Set.of(roles);return scan.jars().stream().filter(j->accepted.contains(role(j))).toList();}
}
