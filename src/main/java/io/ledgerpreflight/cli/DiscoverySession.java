package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.BytecodeScanner;
import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import io.ledgerpreflight.evidence.ConfigAnalyzer;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** A short selection gate before compatibility analysis; no artifact execution or database calls. */
final class DiscoverySession {
    static AssessmentService.Options prepare(AssessmentService.Options o,SessionTerminal terminal)throws IOException {
        terminal.text("Discovering supplied node and upgrade kit…");
        var found=NodeDiscovery.discover(o.node());int selection=0;
        if(found.nodes().size()>1){terminal.screen();selection=terminal.choose(found.nodes().size()+" Corda nodes discovered · Which node would you like to assess?",found.nodes().stream().map(n->n.root().getFileName()+(n.type().equals("Notary")?" · "+n.notaryMode()+" notary":"")).toList());if(selection<0)return null;}
        var node=found.nodes().get(selection);Path config=o.nodeConf();
        if(config==null&&node.configs().size()==1)config=node.configs().get(0);
        else if(config==null&&node.configs().size()>1){int n=terminal.choose("Select the active node configuration",node.configs().stream().map(p->node.root().relativize(p).toString()).toList());if(n<0)return null;config=node.configs().get(n);}
        var scanner=new ArtifactDiscovery();var current=scanner.scanLayout(node.root());var target=scanner.scanLayout(o.kit());
        Path runtime=o.targetCorda(),tvu=o.tvuJar();
        if(runtime==null&&Discovery.topLevel(Discovery.select(target,"RUNTIME")).size()>1){runtime=selectArtifact(o.kit(),Discovery.topLevel(Discovery.select(target,"RUNTIME")),"Select target Corda runtime",terminal);if(runtime==null)return null;}
        if(tvu==null&&Discovery.topLevel(Discovery.select(target,"TVU")).size()>1){tvu=selectArtifact(o.kit(),Discovery.topLevel(Discovery.select(target,"TVU")),"Select target TVU artifact",terminal);if(tvu==null)return null;}
        Map<String,Object> settings=Map.of();
        try{settings=new ConfigAnalyzer().analyze(config,config!=null&&config.toRealPath().startsWith(node.root())?node.root():config==null?null:config.toRealPath().getParent()).safeSettings();}catch(IOException ignored){}
        var oldRuntime=Discovery.topLevel(Discovery.select(current,"RUNTIME"));
        var newRuntime=runtime==null?Discovery.topLevel(Discovery.select(target,"RUNTIME")):Discovery.topLevel(Discovery.select(scanner.scan(runtime),"RUNTIME"));
        var validators=tvu==null?Discovery.topLevel(Discovery.select(target,"TVU")):Discovery.topLevel(Discovery.select(scanner.scan(tvu),"TVU"));
        var apps=o.targetCordapps()==null?Discovery.select(target,"CORDAPP"):Discovery.select(scanner.scan(o.targetCordapps()),"CORDAPP");
        var model=Discovery.model(current,target,oldRuntime,newRuntime,validators,apps,settings);
        String schema=Objects.toString(settings.get("effectiveSchema"),"Unknown");
        int schemas=settings.get("schemas") instanceof List<?> names?names.size():0;
        String schemaLines=schemas>1?"Schemas      "+("CONFIGURED".equals(settings.get("schemaResolution"))?schemas+" detected\nPrimary      "+settings.get("primarySchema"):"Multiple · configuration needs review"):"Schema       "+schema;
        String type=Objects.toString(settings.get("nodeType"),"Unknown");
        if(type.equals("Notary"))type=settings.getOrDefault("notaryMode","Unknown")+" notary";
        String summary="LedgerPreflight 0.1.0\n────────────────────────────────────────\n\nNODE DISCOVERED\n\n"+Discovery.displayName(settings,node.root().getFileName().toString())+"\n\n"+
            "Type         "+type+"\nCorda        "+human(model.sourceVersion())+" · Platform "+human(model.sourcePlatform())+
            "\nTarget       "+human(model.targetVersion())+" · Platform "+human(model.targetPlatform())+
            "\nJava         "+human(HostEnvironment.inspect(o.hostEnvironment()).currentJava())+
            "\nDatabase     "+settings.getOrDefault("databaseVendor","Unknown")+"\n"+schemaLines+
            "\nCorDapps     "+model.currentCordappJars()+" current · "+model.targetCordappJars()+" target"+
            "\nTVU          "+(validators.size()==1?"Found":validators.isEmpty()?"Not found":"Multiple · select intended artifact")+"\n";
        if(model.sourceVersion().equals("unknown"))summary+="\nCurrent Corda release could not be determined from one runtime's metadata.\n";
        if(model.targetVersion().equals("unknown"))summary+="\nTarget Corda release could not be determined from one runtime's metadata.\n";
        if(!"CONFIGURED".equals(settings.get("schemaResolution")))summary+="\nSchema configuration needs review; the effective schema is not established.\n";
        if(validators.isEmpty())summary+="\nAdd the intended target TVU artifact to the upgrade kit.\n";
        terminal.screen();terminal.text(summary);
        if(terminal.choose("",List.of("Continue","Exit"))!=0){terminal.screen();terminal.text("LedgerPreflight 0.1.0\nSession complete. Assessment was not run.");return null;}
        return new AssessmentService.Options(node.root(),o.kit(),runtime,tvu,o.targetCordapps(),o.legacyJars(),config,o.tvuResults(),o.verifierClasspath(),o.rulePack(),o.networkMode(),o.hostEnvironment());
    }
    private static List<String> runtimeDetails(List<JarInventory> jars){return jars.stream().map(j->Discovery.version(j)+" · platform "+Discovery.platform(j)+" · "+Discovery.attr(j,"Corda-Vendor")+" · minimum Java "+human(Discovery.attr(j,"Min-Java-Version"))).toList();}
    private static String human(String value){return value.isBlank()||value.equalsIgnoreCase("unknown")?"Unknown":value.equals("NOT_INSTALLED")?"Not installed":value;}
    private static List<ScanIssue> coverageIssues(ScanResult current,ScanResult target){return java.util.stream.Stream.concat(current.issues().stream(),target.issues().stream()).filter(i->!i.message().startsWith("Symbolic link outside supplied root skipped:")).toList();}
    static String coverage(ScanResult current,ScanResult target){return coverageIssues(current,target).isEmpty()?"Bytecode scan: supplied entries inspected within the safety limits.":"Bytecode scan incomplete: some supplied content could not be analyzed.\nReadiness requires reviewing the affected inputs; open bytecode coverage evidence.";}
    static String concerns(List<String> issues){long skipped=issues.stream().filter(i->i.startsWith("Symbolic link outside supplied root skipped:")).count();var remaining=issues.stream().filter(i->!i.startsWith("Symbolic link outside supplied root skipped:")).toList();return (skipped==0?"":"External symlinks skipped: "+skipped+"\nReason: targets are outside the supplied node root.\n")+(remaining.isEmpty()?"":"Discovery concerns: "+String.join("; ",remaining));}
    private static Path selectArtifact(Path root,List<JarInventory> jars,String title,SessionTerminal terminal)throws IOException {
        int n=terminal.choose(title,jars.stream().map(j->j.path()+" · "+Discovery.version(j)).toList());if(n<0)return null;
        if(jars.get(n).path().contains("!/")){terminal.text("Nested artifact cannot be selected directly. Supply an explicitly prepared standalone artifact.");return null;}
        return root.resolve(jars.get(n).path()).toRealPath();
    }
}
