package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.evidence.ConfigAnalyzer;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** A short selection gate before compatibility analysis; no processes or database calls. */
final class DiscoverySession {
    static AssessmentService.Options prepare(AssessmentService.Options o,SessionTerminal terminal)throws IOException {
        terminal.text("Discovering supplied node and upgrade kit…");
        var found=NodeDiscovery.discover(o.node());int selection=0;
        if(found.nodes().size()>1){terminal.screen();selection=terminal.choose(found.nodes().size()+" Corda nodes discovered · Which node would you like to assess?",found.nodes().stream().map(n->n.root().getFileName()+(n.type().equals("Notary")?" · "+n.notaryMode()+" notary":"")).toList());if(selection<0)return null;}
        var node=found.nodes().get(selection);Path config=o.nodeConf();
        if(config==null&&node.configs().size()==1)config=node.configs().get(0);
        else if(config==null&&node.configs().size()>1){int n=terminal.choose("Select the active node configuration",node.configs().stream().map(p->node.root().relativize(p).toString()).toList());if(n<0)return null;config=node.configs().get(n);}
        var scanner=new BytecodeScanner();var current=scanner.scan(node.root());var target=scanner.scan(o.kit());
        Path runtime=o.targetCorda(),tvu=o.tvuJar();
        if(runtime==null&&Discovery.topLevel(Discovery.select(target,"RUNTIME")).size()>1){runtime=selectArtifact(o.kit(),Discovery.topLevel(Discovery.select(target,"RUNTIME")),"Select target Corda runtime",terminal);if(runtime==null)return null;}
        if(tvu==null&&Discovery.topLevel(Discovery.select(target,"TVU")).size()>1){tvu=selectArtifact(o.kit(),Discovery.topLevel(Discovery.select(target,"TVU")),"Select target TVU artifact",terminal);if(tvu==null)return null;}
        Map<String,Object> settings=Map.of();String schema="Unknown";
        try{var cfg=new ConfigAnalyzer().analyze(config,config!=null&&config.toRealPath().startsWith(node.root())?node.root():config==null?null:config.toRealPath().getParent());settings=cfg.safeSettings();schema=Objects.toString(settings.get("effectiveSchema"),"Unknown");}catch(IOException ignored){}
        String source=version(Discovery.topLevel(Discovery.select(current,"RUNTIME"))),destination=version(runtime==null?Discovery.topLevel(Discovery.select(target,"RUNTIME")):Discovery.topLevel(scanner.scan(runtime).jars()));
        String summary="LedgerPreflight 0.1.0\n────────────────────────────────────────\nNODE DISCOVERED\n\n"+Discovery.displayName(settings,node.root().getFileName().toString())+"\n\nType       "+settings.getOrDefault("nodeType","Unknown")+"\nRole       Unknown\n"+("Notary".equals(settings.get("nodeType"))?"Mode       "+settings.getOrDefault("notaryMode","Unknown")+" · "+settings.getOrDefault("notaryModeConfidence","UNKNOWN")+"\n":"")+"Corda      "+source+"\nJava       "+HostEnvironment.inspect(o.hostEnvironment()).currentJava()+"\nDatabase   "+settings.getOrDefault("databaseVendor","Unknown")+"\nSchema     "+schema+(schema.equals("Unknown")?" ("+settings.getOrDefault("schemaExplanation","Evidence not established")+")":"")+"\nArtifacts  "+Discovery.topLevel(Discovery.select(current,"CORDAPP","LEGACY_CONTRACT")).size()+" current → "+Discovery.topLevel(Discovery.select(target,"CORDAPP")).size()+" target CorDapp JARs\nTarget     "+destination+"\nTVU        "+version(tvu==null?Discovery.topLevel(Discovery.select(target,"TVU")):Discovery.topLevel(scanner.scan(tvu).jars()))+" "+((tvu!=null||!Discovery.select(target,"TVU").isEmpty())?"found":"not found")+"\n\nDiscovery confidence: "+("HIGH".equals(settings.get("configurationConfidence"))&&!source.equals("Unknown")&&!destination.equals("Unknown")&&found.issues().stream().allMatch(i->i.startsWith("Symbolic link outside supplied root skipped:"))?"HIGH":"UNKNOWN")+"\n";
        while(true){terminal.screen();terminal.text(summary);int action=terminal.choose("",List.of("Continue assessment","Review discovered details","Exit"));if(action<0||action==2){terminal.text("Discovery complete. Assessment was not run.");return null;}if(action==0)break;
            terminal.screen();terminal.text("DISCOVERED DETAILS\nNode root: "+node.root()+"\nConfiguration: "+Objects.toString(config,"Not discovered")+"\nUpgrade kit: "+o.kit()+"\nBusiness role: Unknown; no business role inferred.\nVersion provenance: runtime metadata; multiple or missing identities remain unknown.\nSchema confidence: "+settings.getOrDefault("schemaConfidence","UNKNOWN")+"\nSchema declarations: "+settings.getOrDefault("schemaDeclarations",Map.of())+"\nCurrent runtime metadata: "+Discovery.topLevel(Discovery.select(current,"RUNTIME")).stream().map(j->Discovery.version(j)+" · platform "+Discovery.platform(j)+" · "+Discovery.attr(j,"Corda-Vendor")).toList()+"\nTarget runtime metadata: "+Discovery.topLevel(Discovery.select(target,"RUNTIME")).stream().map(j->Discovery.version(j)+" · platform "+Discovery.platform(j)+" · "+Discovery.attr(j,"Corda-Vendor")).toList()+"\n"+concerns(found.issues())+"\nBytecode coverage concerns: "+java.util.stream.Stream.concat(current.issues().stream(),target.issues().stream()).filter(i->!i.message().startsWith("Symbolic link outside supplied root skipped:")).count()+" (see full assessment evidence)\nInputs are inspected read-only. No database connection is made.");if(found.issues().stream().anyMatch(i->i.startsWith("Symbolic link outside supplied root skipped:"))){while(terminal.choose("",List.of("Back","View skipped paths"))==1){terminal.screen();terminal.text(String.join("\n",found.issues().stream().filter(i->i.startsWith("Symbolic link outside supplied root skipped:")).toList()));}}else terminal.choose("",List.of("Back"));
        }
        return new AssessmentService.Options(node.root(),o.kit(),runtime,tvu,o.targetCordapps(),o.legacyJars(),config,o.tvuResults(),o.verifierClasspath(),o.rulePack(),o.networkMode(),o.hostEnvironment());
    }
    static String concerns(List<String> issues){long skipped=issues.stream().filter(i->i.startsWith("Symbolic link outside supplied root skipped:")).count();return (skipped==0?"":"External symlinks skipped: "+skipped+"\nReason: targets are outside the supplied node root.\n")+"Discovery concerns: "+issues.stream().filter(i->!i.startsWith("Symbolic link outside supplied root skipped:")).toList();}
    private static String version(List<BytecodeScanner.JarInventory> jars){return jars.size()==1&&!Discovery.version(jars.get(0)).equals("unknown")?Discovery.version(jars.get(0)):"Unknown";}
    private static Path selectArtifact(Path root,List<BytecodeScanner.JarInventory> jars,String title,SessionTerminal terminal)throws IOException {
        int n=terminal.choose(title,jars.stream().map(j->j.path()+" · "+Discovery.version(j)).toList());if(n<0)return null;
        if(jars.get(n).path().contains("!/")){terminal.text("Nested artifact cannot be selected directly. Supply an explicitly prepared standalone artifact.");return null;}
        return root.resolve(jars.get(n).path()).toRealPath();
    }
}
