package io.ledgerpreflight.core;

import io.ledgerpreflight.evidence.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Bounded node selection beneath one operator-supplied root; never scans adjacent trees. */
public final class NodeDiscovery {
    public record Node(Path root,List<Path> configs,String type,String notaryMode,String confidence){}
    public record Result(List<Node> nodes,List<String> issues,List<String> supportingArtifacts){}
    public static Result discover(Path supplied)throws IOException {
        var tree=BoundedPaths.discover(supplied,8,10000);List<Path> candidates=new ArrayList<>(),fallback=new ArrayList<>();
        Set<Path> seen=new HashSet<>(),included=new HashSet<>();
        for(Path path:tree.files())if((path.toString().endsWith(".conf")||path.toString().endsWith(".hocon"))&&seen.add(path.toRealPath())){
            // CorDapp application settings are not node launch configurations.
            if(tree.root().relativize(path).toString().replace((char)92,'/').contains("cordapps/config/"))continue;
            fallback.add(path);
            if(fallback.size()>64)throw new IOException("Configuration candidate limit exceeded; supply a specific node directory");
            boolean node=path.getFileName().toString().equals("node.conf");
            try{var config=new ConfigAnalyzer().analyze(path,tree.root());node|=config.safeSettings().containsKey("myLegalName")||"Notary".equals(config.safeSettings().get("nodeType"));
                if(config.safeSettings().get("configurationIncludes") instanceof List<?> includes)for(Object name:includes)included.add(path.getParent().resolve(name.toString()).toRealPath());
            }catch(IOException ignored){}
            if(node)candidates.add(path);
        }
        if(candidates.isEmpty())candidates.addAll(fallback);
        candidates.removeIf(p->{try{return included.contains(p.toRealPath());}catch(IOException e){return false;}});
        Map<Path,List<Path>> grouped=new TreeMap<>();
        for(Path path:candidates){Path base=path.getParent();
            // Do not merge sibling nodes merely because a shared parent contains a JAR.
            if(Set.of("config","conf","settings","etc","configuration").contains(base.getFileName().toString())&&base.getParent()!=null&&base.getParent().startsWith(tree.root())){
                try(var entries=Files.newDirectoryStream(base.getParent())){for(Path jar:entries)if(Files.isRegularFile(jar)&&ArtifactDiscovery.isArchive(jar)&&!Discovery.select(new ArtifactDiscovery().scan(jar),"RUNTIME").isEmpty()){base=base.getParent();break;}}
            }
            grouped.computeIfAbsent(base,k->new ArrayList<>()).add(path);
        }
        if(grouped.isEmpty())grouped.put(tree.root(),List.of());
        List<Node> nodes=new ArrayList<>();
        for(var entry:grouped.entrySet()){
            String type="Unknown",mode="Unknown",confidence="UNKNOWN";
            if(entry.getValue().size()==1)try{var cfg=new ConfigAnalyzer().analyze(entry.getValue().get(0),entry.getKey());type=Objects.toString(cfg.safeSettings().get("nodeType"),"Unknown");mode=Objects.toString(cfg.safeSettings().get("notaryMode"),"Unknown");confidence=Objects.toString(cfg.safeSettings().get("nodeTypeConfidence"),"UNKNOWN");}catch(IOException ignored){}
            nodes.add(new Node(entry.getKey(),List.copyOf(entry.getValue()),type,mode,confidence));
        }
        var supporting=tree.files().stream().filter(p->p.getFileName().toString().equals("network-parameters")||p.getFileName().toString().startsWith("nodeInfo-")).map(p->tree.root().relativize(p).toString()).toList();
        return new Result(List.copyOf(nodes),tree.issues(),supporting);
    }
    public static List<io.ledgerpreflight.bytecode.BytecodeScanner.JarInventory> matches(io.ledgerpreflight.bytecode.BytecodeScanner.JarInventory source,List<io.ledgerpreflight.bytecode.BytecodeScanner.JarInventory> target){
        for(String key:List.of("Cordapp-Contract-Name","Cordapp-Workflow-Name")){
            String name=Discovery.attr(source,key);if(!name.isEmpty()){var matches=target.stream().filter(t->name.equals(Discovery.attr(t,key))).toList();if(!matches.isEmpty())return matches;}
        }
        var hashes=target.stream().filter(t->t.sha256().equals(source.sha256())).toList();if(!hashes.isEmpty())return hashes;
        // Exact class sets support renamed artifacts; overlapping utility packages alone do not.
        if(Discovery.attr(source,"Identity-Class-Names-Truncated").equals("true"))return List.of();
        return target.stream().filter(t->!Discovery.attr(t,"Identity-Class-Names-Truncated").equals("true")&&!source.classes().isEmpty()&&t.classes().keySet().equals(source.classes().keySet())).toList();
    }
}
