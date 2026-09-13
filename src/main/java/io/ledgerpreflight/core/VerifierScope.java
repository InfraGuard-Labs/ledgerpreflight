package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.Source;
import java.util.*;
import java.util.function.Predicate;

/** Bounded contract/state dependency closure; workflow-only APIs do not execute in the verifier. */
public final class VerifierScope implements Predicate<Source> {
    private static final Set<String> CONTRACT_TYPES=Set.of("net/corda/core/contracts/Contract","net/corda/core/contracts/UpgradedContract","net/corda/core/contracts/ContractState","net/corda/core/contracts/CommandData");
    private final Set<String> classes;
    private final boolean complete;
    private VerifierScope(Set<String> classes,boolean complete){this.classes=Set.copyOf(classes);this.complete=complete;}
    public boolean complete(){return complete;}
    public int classCount(){return classes.size();}
    @Override public boolean test(Source source){return classes.contains(source.sourceClass());}
    public static VerifierScope inspect(List<JarInventory> apps){
        Map<String,List<ClassInfo>> local=new HashMap<>();
        for(var app:apps)for(var c:app.classes().values()){
            if(local.size()>=30000&&!local.containsKey(c.name()))return new VerifierScope(Set.of(),false);
            local.computeIfAbsent(c.name(),ignored->new ArrayList<>()).add(c);
        }
        Set<String> selected=new HashSet<>();Deque<String> pending=new ArrayDeque<>();
        for(var app:apps){
            boolean seed=false;
            for(var c:app.classes().values())if(c.superName()!=null&&CONTRACT_TYPES.contains(c.superName())||c.interfaces().stream().anyMatch(CONTRACT_TYPES::contains)){pending.add(c.name());seed=true;}
            // Explicit historical-contract metadata may identify older code without a direct marker.
            if(!seed&&(!Discovery.attr(app,"Cordapp-Contract-Name").isBlank()||Discovery.role(app).equals("LEGACY_CONTRACT")))pending.addAll(app.classes().keySet());
        }
        // First include local subclasses/implementations of contract and state types.
        Map<String,List<String>> children=new HashMap<>();
        for(var values:local.values())for(var c:values){
            if(c.superName()!=null&&local.containsKey(c.superName()))children.computeIfAbsent(c.superName(),ignored->new ArrayList<>()).add(c.name());
            for(String face:c.interfaces())if(local.containsKey(face))children.computeIfAbsent(face,ignored->new ArrayList<>()).add(c.name());
        }
        long edges=0;Set<String> hierarchy=new HashSet<>();Deque<String> hierarchyPending=new ArrayDeque<>(pending);
        while(!hierarchyPending.isEmpty()){
            String name=hierarchyPending.removeFirst();if(!hierarchy.add(name))continue;
            if(hierarchy.size()>4096)return new VerifierScope(hierarchy,false);
            for(String child:children.getOrDefault(name,List.of())){if(++edges>65536)return new VerifierScope(hierarchy,false);hierarchyPending.addLast(child);}
        }
        pending.clear();pending.addAll(new TreeSet<>(hierarchy));
        while(!pending.isEmpty()){
            String name=pending.removeFirst();if(!selected.add(name))continue;
            if(selected.size()>4096)return new VerifierScope(selected,false);
            for(var c:local.getOrDefault(name,List.of())){
                if(c.superName()!=null&&local.containsKey(c.superName()))pending.addLast(c.superName());
                for(String face:c.interfaces())if(local.containsKey(face))pending.addLast(face);
                for(var ref:c.references()){if(++edges>65536)return new VerifierScope(selected,false);if(local.containsKey(ref.owner()))pending.addLast(ref.owner());}
            }
        }
        return new VerifierScope(selected,true);
    }
}
