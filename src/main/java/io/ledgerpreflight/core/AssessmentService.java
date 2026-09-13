package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.rules.*;
import java.nio.file.*;
import java.io.IOException;
import java.util.*;

public final class AssessmentService {
    private final BytecodeScanner.Limits analysisLimits;
    public AssessmentService(){this(BytecodeScanner.Limits.defaults());}
    public AssessmentService(BytecodeScanner.Limits limits){analysisLimits=Objects.requireNonNull(limits);}
    public record Options(Path node,Path kit,Path targetCorda,Path tvuJar,Path targetCordapps,Path legacyJars,Path nodeConf,List<Path> tvuResults,Path verifierClasspath,Path rulePack,String networkMode,Path hostEnvironment,Path currentRuntime) {
        public Options(Path node,Path kit,Path targetCorda,Path tvuJar,Path targetCordapps,Path legacyJars,Path nodeConf,List<Path> tvuResults,Path verifierClasspath,Path rulePack,String networkMode,Path hostEnvironment){this(node,kit,targetCorda,tvuJar,targetCordapps,legacyJars,nodeConf,tvuResults,verifierClasspath,rulePack,networkMode,hostEnvironment,null);}
        public Options(Path node,Path kit,Path targetCorda,Path tvuJar,Path targetCordapps,Path legacyJars,Path nodeConf,List<Path> tvuResults,Path verifierClasspath,Path rulePack){this(node,kit,targetCorda,tvuJar,targetCordapps,legacyJars,nodeConf,tvuResults,verifierClasspath,rulePack,"unknown",null);}
    }
    public Assessment assess(Options options)throws IOException {
        return assess(options, ignored -> {});
    }
    public Assessment assess(Options options,java.util.function.Consumer<String> progress)throws IOException {
        progress.accept("Discovering node…");
        NodeDiscovery.Result discovered=NodeDiscovery.discover(options.node());
        if(discovered.nodes().size()>1)return new Assessment("1","0.1.0","UNKNOWN","unknown","unknown",List.of(f("LP-NODE-001","Multiple node directories discovered","UNKNOWN","CONFIGURATION",discovered.nodes().stream().map(n->n.root().getFileName().toString()).toList(),"No node was selected; compatibility analysis was not run","Supply one discovered node path with --node, or use interactive selection.")),Map.of("node-discovery",discovered));
        NodeDiscovery.Node selected=discovered.nodes().get(0);
        Path selectedConf=options.nodeConf()!=null?options.nodeConf():selected.configs().size()==1?selected.configs().get(0):null;
        options=new Options(selected.root(),options.kit(),options.targetCorda(),options.tvuJar(),options.targetCordapps(),options.legacyJars(),selectedConf,options.tvuResults(),options.verifierClasspath(),options.rulePack(),options.networkMode(),options.hostEnvironment(),options.currentRuntime());
        HostEnvironment host=HostEnvironment.inspect(options.hostEnvironment());
        // Complete the physical identity pass before spending any deep-analysis budget.
        ArtifactDiscovery identityScanner=new ArtifactDiscovery();
        ScanResult allCurrentIdentity=identityScanner.scanLayout(options.node()),targetIdentity=identityScanner.scanLayout(options.kit());
        String requested=ActiveRuntime.requestedPath(options.node(),allCurrentIdentity,options.currentRuntime());
        ActiveRuntime.Selection active=ActiveRuntime.select(allCurrentIdentity,requested);
        ScanResult currentIdentity=active.inputs();
        ScanResult runtimeIdentity=options.targetCorda()==null?targetIdentity:identityScanner.scan(options.targetCorda());
        ScanResult tvuIdentity=options.tvuJar()==null?targetIdentity:identityScanner.scan(options.tvuJar());
        ScanResult appIdentity=options.targetCordapps()==null?targetIdentity:identityScanner.scan(options.targetCordapps());
        BytecodeScanner scanner=new BytecodeScanner(analysisLimits);
        progress.accept("Analyzing supplied compatibility evidence…");
        ScanResult current=scanner.scanLayout(options.node(),withoutDrivers(currentIdentity)),target=scanner.scanLayout(options.kit(),withoutDrivers(targetIdentity));
        current=referencedDrivers(scanner,options.node(),currentIdentity,current,List.of(current,target));
        target=referencedDrivers(scanner,options.kit(),targetIdentity,target,List.of(current,target));
        List<Finding> findings=new ArrayList<>();
        if(active.selected()==null)findings.add(f("LP-CURRENT-RUNTIME","Active current Corda runtime is not established","UNKNOWN","UPGRADE_PATH",List.of("Selection: "+active.origin(),"Strong root candidates: "+active.candidates().size()),"Current version and compatibility cannot be established","Select the active current runtime in an interactive assessment, or supply an unambiguous node directory."));
        addScanIssues(findings,current,"current-node");addScanIssues(findings,target,"upgrade-kit");
        verifySnapshot(findings,currentIdentity,current,"current-node");verifySnapshot(findings,targetIdentity,target,"upgrade-kit");
        addScanIssues(findings,currentIdentity,"current-node identity");addScanIssues(findings,targetIdentity,"upgrade-kit identity");
        List<JarInventory> runtimes=analysis(target,targetIdentity,"RUNTIME","RUNTIME_LIBRARY","VERIFIER","DRIVER","UNKNOWN");
        if(options.targetCorda()!=null){ScanResult explicit=scanner.scan(options.targetCorda());addScanIssues(findings,explicit,"runtime override");verifySnapshot(findings,runtimeIdentity,explicit,"runtime override");addScanIssues(findings,runtimeIdentity,"runtime identity");runtimes=analysis(explicit,runtimeIdentity,"RUNTIME","RUNTIME_LIBRARY","VERIFIER","DRIVER","UNKNOWN");}
        List<JarInventory> tvu=Discovery.select(tvuIdentity,"TVU");
        List<JarInventory> apps=analysis(target,appIdentity,"CORDAPP");
        if(options.targetCordapps()!=null){ScanResult explicit=scanner.scan(options.targetCordapps());addScanIssues(findings,explicit,"CorDapp override");verifySnapshot(findings,appIdentity,explicit,"CorDapp override");addScanIssues(findings,appIdentity,"CorDapp identity");apps=analysis(explicit,appIdentity,"CORDAPP");}
        if(options.targetCordapps()!=null&&options.targetCorda()==null){target=referencedDrivers(scanner,options.kit(),targetIdentity,target,List.of(current,new ScanResult(apps,List.of())));addScanIssues(findings,target,"upgrade-kit");verifySnapshot(findings,targetIdentity,target,"upgrade-kit");runtimes=analysis(target,targetIdentity,"RUNTIME","RUNTIME_LIBRARY","VERIFIER","DRIVER","UNKNOWN");}
        if(options.tvuJar()!=null){addScanIssues(findings,tvuIdentity,"TVU identity");addScanIssues(findings,scanner.scan(options.tvuJar()),"TVU override");}
        List<JarInventory> legacy=options.legacyJars()!=null?override(scanner,options.legacyJars(),findings):analysis(target,targetIdentity,"LEGACY");
        List<JarInventory> oldApps=analysis(current,currentIdentity,"CORDAPP","LEGACY_CONTRACT");
        String sourceVersion=Discovery.uniqueVersion(Discovery.select(currentIdentity,"RUNTIME")),targetVersion=Discovery.uniqueVersion(Discovery.select(runtimeIdentity,"RUNTIME"));
        if(targetVersion.matches(".*[A-Za-z].*")&&!targetVersion.equals("unknown"))findings.add(f("LP-DISCOVERY-005","Pre-release or qualified runtime version requires validation","UNKNOWN","UPGRADE_PATH",List.of(targetVersion),"Stable release rules may not apply","Supply a supported release runtime and verify version provenance."));
        if(Discovery.topLevel(Discovery.select(targetIdentity,"RUNTIME")).size()>1 && options.targetCorda()==null)findings.add(f("LP-DISCOVERY-006","Multiple target runtime artifacts were discovered","WARNING","UPGRADE_PATH",List.of("Runtime candidates="+Discovery.topLevel(Discovery.select(targetIdentity,"RUNTIME")).size()),"Intended runtime identity is ambiguous","Select the intended runtime with --target-corda and supply its dependency set."));
        if(tvu.size()>1)findings.add(f("LP-DISCOVERY-007","Multiple TVU artifacts were discovered","UNKNOWN","TVU",tvu.stream().map(JarInventory::path).toList(),"The validation artifact is ambiguous","Select the intended artifact with --tvu-jar or interactive discovery."));
        if(runtimes.isEmpty()||targetVersion.equals("unknown"))findings.add(f("LP-DISCOVERY-001","Target Corda runtime could not be uniquely identified","UNKNOWN","UPGRADE_PATH",List.of("Target version: "+targetVersion),"Assessment coverage is incomplete","Supply the intended target runtime using --target-corda with version metadata."));
        if(tvu.isEmpty())findings.add(f("LP-DISCOVERY-002","Transaction Validator Utility artifact was not found","BLOCKED","TVU",List.of("No artifact with TVU entry point or contained TVU classes discovered"),"Required upgrade validation cannot be prepared","Add the target TVU JAR to the upgrade kit or use --tvu-jar."));
        for(JarInventory j:tvu)if(!Discovery.version(j).equals("unknown")&&!targetVersion.equals("unknown")&&!Discovery.version(j).equals(targetVersion))findings.add(f("LP-DISCOVERY-003","TVU and target runtime versions disagree","WARNING","TVU",List.of(j.path(),"TVU "+Discovery.version(j),"Target "+targetVersion),"Validation may use a different runtime","Prepare matching intended target artifacts and confirm the TVU environment."));
        if(!oldApps.isEmpty()&&apps.isEmpty())findings.add(f("LP-CORDAPP-004","Target CorDapps are missing","BLOCKED","CORDAPP",List.of(oldApps.size()+" current CorDapps; zero target CorDapps"),"The prepared TVU environment is incomplete","Add rebuilt target CorDapps under upgrade-kit/cordapps."));
        for(JarInventory j:Discovery.select(targetIdentity,"UNKNOWN"))findings.add(f("LP-DISCOVERY-004","Unclassified target JAR","WARNING","DEPENDENCY",List.of(j.path()),"Artifact role is uncertain; classes are included in the provisional target inventory","Verify artifact purpose and the actual verifier classpath."));
        progress.accept("Analyzing CorDapps and checking legacy-jars…");
        ClasspathEvidence.Result classpath=ClasspathEvidence.read(options.verifierClasspath(),runtimes,legacy);
        progress.accept("Comparing JVM APIs…");
        CompatibilityAnalyzer analyzer=new CompatibilityAnalyzer();
        List<JarInventory> historical=new ArrayList<>(oldApps);historical.addAll(analysis(current,currentIdentity,"LEGACY"));
        addCompatibility(findings,analyzer.analyze(historical,runtimes,legacy,classpath.runtimePrecedenceProven()),"current/historical");
        addCompatibility(findings,analyzer.analyze(apps,runtimes,List.of(),false),"target");
        if(historical.isEmpty())addCompatibility(findings,analyzer.analyze(List.of(),runtimes,legacy,classpath.runtimePrecedenceProven()),"target");
        if(findings.stream().noneMatch(f->f.category().equals("SECURITY")))removedClasses(findings,historical,analysis(current,currentIdentity,"RUNTIME","RUNTIME_LIBRARY"),runtimes,legacy,apps);
        ConfigAnalyzer.ConfigEvidence config;
        Path conf=selectedConf;
        if(conf==null)findings.add(f("LP-CONFIG-002",selected.configs().isEmpty()?"Node configuration was not discovered":"Multiple candidate configurations discovered","UNKNOWN","CONFIGURATION",selected.configs().stream().map(p->p.getFileName().toString()).toList(),"Effective launch configuration is unknown","Select the active configuration with --node-conf or interactive discovery."));
        try{config=new ConfigAnalyzer().analyze(conf,conf!=null&&conf.toRealPath().startsWith(options.node())?options.node():conf==null?null:conf.toRealPath().getParent());}catch(IOException e){config=new ConfigAnalyzer.ConfigEvidence(null,null,null,false,false,false,List.of("Configuration parsing failed"),"# configuration unavailable\n");findings.add(f("LP-CONFIG-001","Configuration could not be safely parsed","UNKNOWN","CONFIGURATION",List.of(e.getMessage()),"Database and verifier configuration were not assessed","Provide a bounded HOCON file with safe relative includes and resolved required values."));}
        boolean schemaKnown="CONFIGURED".equals(config.safeSettings().get("schemaResolution"));
        if(config.postgresql()&&config.mixedCase())findings.add(f("LP-DB-001",schemaKnown?"Mixed-case schema / TVU compatibility risk":"Mixed-case declarations; effective schema is unresolved","WARNING","DATABASE_SCHEMA",List.of("Effective schema: "+config.safeSettings().get("effectiveSchema"),"Resolution: "+config.safeSettings().get("schemaExplanation"),"Declarations: "+config.safeSettings().get("schemaDeclarations")),schemaKnown?"PostgreSQL resolution and normal node startup can succeed while TVU/Hibernate validates a different schema":"The declarations include mixed-case names, but conflicting or unresolved evidence prevents an effective-schema claim","Reconcile declarations and validate effective TVU schema resolution on a database copy; no database connection is made by static assessment."));
        if(config.contradictory())findings.add(Finding.of("LP-DB-002","Schema declarations disagree","UNKNOWN","DATABASE_SCHEMA","UNKNOWN","CONFIGURATION","node.conf",List.of("Effective schema: Ambiguous","Declarations: "+config.safeSettings().get("schemaDeclarations")),"Node and TVU persistence paths may resolve different schemas","Reconcile intended schema and collect independent database evidence; do not infer table absence from Hibernate alone."));
        if(config.issues().stream().anyMatch(i->i.startsWith("Unresolved")||i.contains("unsupported expressions")))findings.add(f("LP-CONFIG-003","Configuration values remain unresolved","UNKNOWN","CONFIGURATION",config.issues(),"Effective configuration cannot be established safely","Supply the referenced local include or environment value; no database connection is needed."));
        progress.accept("Evaluating TVU readiness…");
        TvuAnalyzer.TvuEvidence tvuEvidence;
        try{tvuEvidence=new TvuAnalyzer().analyze(options.tvuResults());}catch(IOException e){tvuEvidence=new TvuAnalyzer.TvuEvidence(null,null,null,null,0,Map.of(),false,false,false,List.of(e.getMessage()));findings.add(f("LP-TVU-INPUT","TVU evidence could not be safely analyzed","UNKNOWN","TVU",List.of(e.getMessage()),"Validation success cannot be established","Provide complete, bounded TVU logs and error archives."));}
        if(tvuEvidence.failed()!=null&&tvuEvidence.failed()>0 || !tvuEvidence.rootCauses().isEmpty())findings.add(f("LP-TVU-002","TVU verification failure","BLOCKED","TVU",List.of(Objects.toString(tvuEvidence.processed(),"unknown")+" processed; "+Objects.toString(tvuEvidence.succeeded(),"unknown")+" succeeded; "+Objects.toString(tvuEvidence.failed(),"unknown")+" failures reported",tvuEvidence.detailedRecords()+" detailed records supplied",tvuEvidence.rootCauses().toString()),"Historical transaction verification has not passed","Resolve supplied root causes and rerun the required TVU over the complete transaction set. Detail counts do not establish causes for unsupplied records."));
        if(tvuEvidence.schemaValidationFailure())findings.add(f("LP-DB-003","TVU/Hibernate schema validation failed","BLOCKED","DATABASE_SCHEMA",List.of("Supplied TVU evidence reports schema-validation failure"),"TVU validation is incomplete; this does not prove the physical table is absent or normal node configuration is broken","Compare effective TVU schema, quoting and search_path against independent read-only database evidence on a copy; seek supported vendor guidance."));
        if(!options.tvuResults().isEmpty()&&!tvuEvidence.completeSuccess()&&(tvuEvidence.failed()==null||tvuEvidence.failed()==0))findings.add(f("LP-TVU-003","Successful complete TVU validation is not established","UNKNOWN","TVU",tvuEvidence.issues().isEmpty()?List.of("Missing, inconsistent or incomplete transaction totals"):tvuEvidence.issues(),"Final upgrade readiness cannot be established","Supply one complete TVU run with expected, processed, succeeded and failed counts, and all failure details."));
        Map<String,String> facts=new TreeMap<>();if(!host.plannedTargetJava().equals("UNKNOWN"))facts.put("target.java",host.plannedTargetJava().startsWith("17")?"17":host.plannedTargetJava());
        if(!host.plannedTargetJava().equals("UNKNOWN") && host.targetJavaReadiness().contains("UNVERIFIED"))findings.add(f("LP-HOST-003","Reported target Java is not sufficiently established","UNKNOWN","JAVA",host.observations(),"A major-only or pre-release Java declaration does not establish the supported target runtime","Provide the exact supported Java 17 patch intended for the target environment."));
        if(host.targetJavaReadiness().equals("INCOMPATIBLE"))findings.add(f("LP-HOST-002","Reported target Java does not meet the target requirement","BLOCKED","JAVA",host.observations(),"The planned target Corda environment requires a supported Java 17 patch","Prepare Java 17.0.9 or a later Java 17 patch in the target environment; LedgerPreflight does not modify system Java."));
        if(host.targetJavaReadiness().equals("UNVERIFIED") && !host.currentJava().equals("UNKNOWN") && !host.currentJava().startsWith("17"))findings.add(f("LP-HOST-001","Target Java preparation needs confirmation","WARNING","JAVA",List.of("Current host Java: "+host.currentJava(),"LedgerPreflight private/analyzer Java: "+host.analyzerJava(),"Target Corda requirement: "+host.targetRequiredJava()),"The analyzer can run with its private runtime, but that does not prepare the target node Java environment","Confirm the planned target Java independently; provide --host-environment evidence without replacing the current node Java."));
        facts.put("network.mode",options.networkMode());facts.put("source.version",sourceVersion);facts.put("target.version",targetVersion);facts.put("tvu.present",Boolean.toString(!tvu.isEmpty()));facts.put("legacyJars.present",Boolean.toString(!legacy.isEmpty()));facts.put("legacyContracts.present",Boolean.toString(!Discovery.select(targetIdentity,"LEGACY_CONTRACT").isEmpty()));
        for(JarInventory app:apps) {
            String min=Discovery.attr(app,"Min-Platform-Version");if(!min.isEmpty() && !min.equals("140"))findings.add(f("LP-CORDAPP-003","Target CorDapp minimum platform differs from 140","WARNING","CORDAPP",List.of(app.path(),"Min-Platform-Version="+min),"Target CorDapp upgrade requirements need validation","Rebuild target CorDapps according to the official 4.12 upgrade guide."));
            if(app.classes().values().stream().anyMatch(c->c.references().stream().anyMatch(r->r.owner().equals("net/corda/core/contracts/HashAttachmentConstraint"))))facts.put("constraints.hashDetected","true");
        }
        List<JarInventory> allApps=new ArrayList<>(historical);allApps.addAll(apps);
        if(allApps.stream().anyMatch(j->j.classes().values().stream().anyMatch(c->c.references().stream().anyMatch(r->r.owner().equals("net/corda/core/contracts/HashAttachmentConstraint")))))facts.put("constraints.hashDetected","true");
        if(allApps.stream().anyMatch(j->j.classes().values().stream().anyMatch(c->c.references().stream().anyMatch(r->r.owner().contains("ContractUpgradeFlow")||r.owner().equals("net/corda/core/contracts/UpgradedContract")))))facts.put("constraints.explicitUpgradeDetected","true");
        for(JarInventory runtime:Discovery.select(runtimeIdentity,"RUNTIME")){String platform=Discovery.platform(runtime);if(!platform.isEmpty()&&!platform.equals("unknown")&&!platform.equals("140"))facts.put("target.platform",platform);}
        if(historical.stream().anyMatch(AssessmentService::legacyVerifyPattern)||apps.stream().anyMatch(AssessmentService::legacyVerifyPattern))facts.put("verification.legacyPattern","true");
        RuleEngine engine=options.rulePack()==null?new RuleEngine():new RuleEngine().load(options.rulePack());
        for(RuleFinding r:engine.evaluate(facts))findings.add(new Finding(r.id(),r.title(),r.severity(),r.category(),r.status(),r.confidence(),r.source(),r.affectedArtifact(),r.evidence(),r.impact(),r.explanation(),r.nextAction(),r.documentationReference()));
        compareCorDapps(findings,Discovery.select(currentIdentity,"CORDAPP","LEGACY_CONTRACT"),Discovery.select(appIdentity,"CORDAPP"));
        Map<String,Object> evidence=new TreeMap<>();evidence.put("node-discovery",discovered);evidence.put("environment",Map.of("nodeName",Discovery.displayName(config.safeSettings(),options.node().toAbsolutePath().normalize().getFileName().toString()),"current",Discovery.inventory(currentIdentity),"sourceVersion",sourceVersion,"targetVersion",targetVersion,"offline",true,"host",host,"rulePackVersion",RuleEngine.PACK_VERSION));evidence.put("upgrade-kit",Discovery.inventory(targetIdentity));evidence.put("cordapps-current",Discovery.select(currentIdentity,"CORDAPP","LEGACY_CONTRACT").stream().map(j->Map.of("path",j.path(),"sha256",j.sha256())).toList());evidence.put("cordapps-target",Discovery.select(appIdentity,"CORDAPP").stream().map(j->Map.of("path",j.path(),"sha256",j.sha256())).toList());var runtimeDelta=analyzer.compare(analysis(current,currentIdentity,"RUNTIME","RUNTIME_LIBRARY"),runtimes);evidence.put("runtime-api-delta",runtimeDelta);addCompatibility(findings,runtimeDelta.stream().filter(i->i.id().equals("LP-ANALYSIS-LIMIT")).toList(),"runtime comparison");evidence.put("internal-api-usage",findings.stream().filter(f->f.category().equals("INTERNAL_API")).toList());evidence.put("legacy-jars-analysis",findings.stream().filter(f->f.category().equals("LEGACY_JARS")).toList());evidence.put("classpath-analysis",classpath);evidence.put("schema-analysis",config);evidence.put("tvu-summary",tvuEvidence);evidence.put("sanitized-node.conf",config.sanitizedConfig());
        evidence.put("current-runtime-selection",active.evidence());evidence.put("tvu-evidence-supplied",!options.tvuResults().isEmpty());
        evidence.put("discovery",Discovery.model(currentIdentity,targetIdentity,Discovery.select(currentIdentity,"RUNTIME"),Discovery.select(runtimeIdentity,"RUNTIME"),tvu,Discovery.select(appIdentity,"CORDAPP"),config.safeSettings()));
        evidence.put("other-jars-current",Discovery.otherJars(currentIdentity).stream().map(JarInventory::path).toList());
        evidence.put("other-jars-target",Discovery.otherJars(targetIdentity).stream().map(JarInventory::path).toList());
        evidence.put("analysis-coverage",Map.of("status",findings.stream().anyMatch(f->f.category().equals("SECURITY"))?"PARTIAL":"COMPLETE_WITHIN_LIMITS","currentIssues",current.issues(),"targetIssues",target.issues(),"limitsPerPhysicalArtifact",analysisLimits,"retainedSymbolMemoryLimitBytes",BytecodeScanner.MAX_RETAINED_BYTES,"currentInventory",Discovery.inventory(current),"targetInventory",Discovery.inventory(target)));
        findings=findings.stream().distinct().sorted().toList();
        return new Assessment("1","0.1.0",Assessment.readiness(findings,tvuEvidence.completeSuccess(),!options.tvuResults().isEmpty()),sourceVersion,targetVersion,findings,evidence);
    }
    private static ScanResult withoutDrivers(ScanResult identity){return new ScanResult(identity.jars().stream().filter(j->!Discovery.role(j).equals("DRIVER")).toList(),List.of());}
    /** Drivers enter the bounded signature scan only when supplied code requires their classes. */
    private static ScanResult referencedDrivers(BytecodeScanner scanner,Path root,ScanResult identity,ScanResult scanned,List<ScanResult> consumers){
        List<JarInventory> jars=new ArrayList<>(scanned.jars());List<ScanIssue> issues=new ArrayList<>(scanned.issues());
        List<JarInventory> pending=new ArrayList<>(Discovery.select(identity,"DRIVER").stream().filter(j->scanned.jars().stream().noneMatch(done->done.path().equals(j.path()))).toList());
        while(!pending.isEmpty()){
            Set<String> required=new HashSet<>();
            List<JarInventory> inspected=new ArrayList<>(jars);consumers.forEach(s->inspected.addAll(s.jars()));
            for(JarInventory j:inspected)for(ClassInfo c:j.classes().values()){if(c.superName()!=null)required.add(c.superName());required.addAll(c.interfaces());c.references().forEach(ref->required.add(ref.owner()));}
            List<JarInventory> needed=pending.stream().filter(j->Discovery.attr(j,"Identity-Class-Names-Truncated").equals("true")||j.classes().keySet().stream().anyMatch(required::contains)).toList();
            if(needed.isEmpty())break;pending.removeAll(needed);
            ScanResult extra=scanner.scanLayout(root,new ScanResult(needed,List.of()));jars.addAll(extra.jars());issues.addAll(extra.issues());
        }
        return new ScanResult(List.copyOf(jars),List.copyOf(issues));
    }
    private static void verifySnapshot(List<Finding> findings,ScanResult identity,ScanResult analysis,String scope) {
        for(JarInventory artifact:identity.jars())for(JarInventory scanned:analysis.jars())
            if(artifact.path().equals(scanned.path())&&!artifact.sha256().equals(scanned.sha256()))
                findings.add(f("LP-INPUT-CHANGED","Artifact changed during assessment","UNKNOWN","SECURITY",List.of(scope+"/"+artifact.path()),"Discovery and analysis inspected different bytes","Assess an immutable snapshot or isolated consistent copy."));
    }
    /** Select deep results by the independently established physical role. Never substitute headers for method bodies. */
    private static List<JarInventory> analysis(ScanResult deep,ScanResult identity,String...roles) {
        List<JarInventory> result=new ArrayList<>();
        for(JarInventory artifact:Discovery.select(identity,roles)) {
            boolean root=false;
            for(JarInventory jar:deep.jars())if(jar.path().equals(artifact.path())||jar.path().startsWith(artifact.path()+"!/")) {
                if(jar.path().equals(artifact.path())){root=true;result.add(new JarInventory(jar.path(),artifact.sha256(),artifact.manifest(),jar.classes(),artifact.signatureFiles(),artifact.cordappEntrypoints()));}
                else result.add(jar);
            }
            if(!root)result.add(new JarInventory(artifact.path(),artifact.sha256(),artifact.manifest(),Map.of(),artifact.signatureFiles(),artifact.cordappEntrypoints()));
        }
        return List.copyOf(result);
    }
    private static boolean legacyVerifyPattern(JarInventory app){return app.classes().values().stream().anyMatch(c->c.references().stream().anyMatch(r->r.name().equals("toLedgerTransaction") && Set.of("net/corda/core/transactions/SignedTransaction","net/corda/core/transactions/WireTransaction","net/corda/core/transactions/TransactionBuilder").contains(r.owner()))&&c.references().stream().anyMatch(r->r.owner().equals("net/corda/core/transactions/LedgerTransaction")&&r.name().equals("verify")));}
    private static void compareCorDapps(List<Finding> findings,List<JarInventory> old,List<JarInventory> target){
        for(JarInventory a:old){String name=Discovery.attr(a,"Cordapp-Contract-Name");List<JarInventory> matches=NodeDiscovery.matches(a,target);
            if(matches.size()!=1){findings.add(f("LP-CORDAPP-005","Current CorDapp has no unique target match","WARNING","CORDAPP",List.of(a.path()),"Rebuild and signing continuity coverage is uncertain","Supply unambiguous manifest identity or matching class-content evidence for target artifacts."));continue;}
            JarInventory b=matches.get(0);
            if(a.sha256().equals(b.sha256()))findings.add(f("LP-CORDAPP-008","Current and target CorDapp bytes are identical","WARNING","CORDAPP",List.of(a.path(),b.path()),"Target rebuild evidence is absent","Confirm the CorDapp has been upgraded appropriately for Corda 4.12 and Java 17."));
            if(!name.isEmpty() && (a.signatureFiles().isEmpty()||b.signatureFiles().isEmpty()))findings.add(f("LP-SIGNING-002","Contract signing continuity is unproven","WARNING","SIGNING",List.of(a.path(),b.path(),"Signature metadata missing"),"Signing-key continuity cannot be established","Verify signed current and target CorDapps and the documented attachment-constraint requirements."));
            if(!a.signatureFiles().equals(b.signatureFiles()))findings.add(f("LP-SIGNING-003","CorDapp signature metadata differs","WARNING","SIGNING",List.of(a.path(),b.path(),"Signature block names differ; signer identity has not been cryptographically established"),"Signing-key continuity requires verification","Verify signatures and compare trusted signer public keys using the official procedure."));
            else if(!a.signatureFiles().isEmpty())findings.add(f("LP-SIGNING-004","Signing continuity needs cryptographic validation","WARNING","SIGNING",List.of(a.path(),"Signature block names are present but do not prove same signing keys"),"Static metadata cannot establish trusted signing identity","Verify current and target JAR signatures and compare signer public keys."));
            if(!name.isEmpty()){try{int av=Integer.parseInt(Discovery.attr(a,"Cordapp-Contract-Version")),bv=Integer.parseInt(Discovery.attr(b,"Cordapp-Contract-Version"));if(bv<=av)findings.add(f("LP-CORDAPP-006","Target contract version did not increase","BLOCKED","CORDAPP",List.of(name+": "+av+" -> "+bv),"Target contracts do not meet the documented upgrade version increment","Increase contract version as required by the official 4.12 upgrade guide."));}catch(NumberFormatException e){findings.add(f("LP-CORDAPP-007","Contract version metadata is incomplete","WARNING","CORDAPP",List.of(name),"Contract version increment cannot be checked","Provide contract version metadata and verify the required increment."));}}
        }
    }
    private static void removedClasses(List<Finding> findings,List<JarInventory> consumers,List<JarInventory> oldRuntime,List<JarInventory> runtime,List<JarInventory> legacy,List<JarInventory> targetApps){Set<String> before=new HashSet<>(),after=new HashSet<>();oldRuntime.forEach(j->before.addAll(j.classes().keySet()));for(var list:List.of(runtime,legacy,targetApps))list.forEach(j->after.addAll(j.classes().keySet()));for(JarInventory j:consumers)for(ClassInfo c:j.classes().values())for(Reference r:c.references())if(before.contains(r.owner())&&!after.contains(r.owner())){if(findings.size()>=2048){findings.add(f("LP-ANALYSIS-LIMIT","Compatibility analysis incomplete","UNKNOWN","SECURITY",List.of("Finding limit reached"),"Remaining linkage evidence was not retained","Complete bounded analysis before upgrading."));return;}findings.add(f("LP-API-006","Previously supplied runtime class is absent from the target kit","BLOCKED","API_COMPATIBILITY",List.of(j.path(),c.name(),r.owner()),"Required historical linkage is unavailable in the supplied target inventory","Supply the complete supported target runtime/dependencies and rerun TVU."));}}
    private static List<JarInventory> override(BytecodeScanner s,Path path,List<Finding> findings){ScanResult r=s.scan(path);addScanIssues(findings,r,"override");return r.jars();}
    private static void addScanIssues(List<Finding> findings,ScanResult scan,String root){for(ScanIssue i:scan.issues())findings.add(f(i.code(),i.message().toLowerCase(Locale.ROOT).contains("limit")?"Compatibility analysis incomplete":"Input could not be completely scanned","UNKNOWN","SECURITY",List.of(root+"/"+i.path(),i.message()),"Assessment coverage is incomplete","Correct or remove malformed/unsafe supplied inputs and rerun."));}
    private static void addCompatibility(List<Finding> findings,List<CompatibilityAnalyzer.CompatibilityIssue> issues,String scope){for(var i:issues){String category=i.id().equals("LP-ANALYSIS-LIMIT")?"SECURITY":i.id().startsWith("LP-LEGACY")?"LEGACY_JARS":i.id().startsWith("LP-INTERNAL")?"INTERNAL_API":"API_COMPATIBILITY";findings.add(Finding.of(i.id(),i.message(),i.severity(),category,i.severity().equals("BLOCKED")?"HIGH":"POTENTIAL","RUNTIME_DISCOVERY",scope+"/"+i.evidence().getOrDefault("jar",i.evidence().getOrDefault("legacyJar","runtime")),i.evidence().entrySet().stream().map(e->e.getKey()+": "+e.getValue()).toList(),"Historical or target linkage/verification may fail",i.nextAction()));}}
    private static Finding f(String id,String title,String severity,String category,List<String> evidence,String impact,String next){return Finding.of(id,title,severity,category,severity.equals("BLOCKED")?"HIGH":"POTENTIAL",id.startsWith("LP-DB")?"HEURISTIC":"RUNTIME_DISCOVERY","assessment",evidence,impact,next);}
}
