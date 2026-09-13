package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

/** Current-node active location is distinct from an inventory of valid historical runtimes. */
public final class ActiveRuntime {
    private ActiveRuntime(){}
    public record Selection(ScanResult inputs,JarInventory selected,List<JarInventory> candidates,
                            List<JarInventory> inactive,String origin){
        public Map<String,Object> evidence(){
            return Map.of("origin",origin,"selected",selected==null?List.of():Discovery.inventory(new ScanResult(List.of(selected),List.of())),
                "inactiveRuntimeCount",inactive.size(),"inactiveRuntimes",Discovery.inventory(new ScanResult(inactive,List.of())),
                "candidates",Discovery.inventory(new ScanResult(candidates,List.of())));
        }
    }
    public static Selection select(ScanResult identity,String requested)throws IOException {
        List<JarInventory> runtimes=identity.jars().stream().filter(j->!j.path().contains("/")&&!j.path().contains("!/")&&Discovery.role(j).equals("RUNTIME")).toList();
        List<JarInventory> strong=runtimes.stream().filter(ActiveRuntime::strong).toList();
        JarInventory active=null;String origin="NOT_FOUND";
        if(requested!=null){
            active=strong.stream().filter(j->j.path().equals(requested)).findFirst().orElseThrow(()->new IOException("Selected current runtime no longer has a strong Corda identity"));
            origin="USER_SELECTED";
        }else{
            active=strong.stream().filter(j->j.path().equals("corda.jar")).findFirst().orElse(null);
            if(active!=null)origin="CANONICAL_ACTIVE_LOCATION";
            else if(strong.size()==1){active=strong.get(0);origin="SINGLE_STRONG_CANDIDATE";}
            else if(strong.size()>1)origin="AMBIGUOUS";
        }
        JarInventory chosen=active;
        List<JarInventory> excluded=runtimes.stream().filter(j->j!=chosen).toList();
        Set<String> excludedPaths=new HashSet<>();excluded.forEach(j->excludedPaths.add(j.path()));
        ScanResult inputs=new ScanResult(identity.jars().stream().filter(j->!excludedPaths.contains(j.path())).toList(),
            identity.issues().stream().filter(i->!excludedPaths.contains(i.path())).toList());
        return new Selection(inputs,active,strong,active==null?List.of():excluded,origin);
    }
    public static String requestedPath(Path root,ScanResult identity,Path selected)throws IOException {
        if(selected==null)return null;Path real=selected.toRealPath(),base=root.toRealPath();
        if(!real.startsWith(base))throw new IOException("Selected current runtime is outside the supplied node");
        for(JarInventory j:identity.jars())if(!j.path().contains("/")&&base.resolve(j.path()).toRealPath().equals(real))return j.path();
        return base.relativize(real).toString().replace('\\','/');
    }
    private static boolean strong(JarInventory j){
        if(Discovery.version(j).equals("unknown"))return false;
        String entry=Discovery.attr(j,"Application-Class")+" "+Discovery.attr(j,"Application-ID")+" "+Discovery.attr(j,"Main-Class");
        return Arrays.stream(entry.split(" ")).anyMatch(s->s.startsWith("net.corda.node."))
            ||(j.classes().containsKey("net/corda/node/Corda")&&!Discovery.attr(j,"Corda-Release-Version").isBlank());
    }
}
