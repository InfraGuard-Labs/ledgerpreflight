package io.ledgerpreflight.cli;

import picocli.CommandLine;
import picocli.CommandLine.*;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.evidence.*;
import io.ledgerpreflight.reporting.Reports;
import io.ledgerpreflight.rules.RuleEngine;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Callable;

@Command(name="ledger-preflight",version="LedgerPreflight 0.1.0",mixinStandardHelpOptions=true,
 description="Know what will break before you upgrade Corda. Offline, read-only preflight.",
 subcommands={Main.Assess.class,Main.Inventory.class,Main.AnalyzeJar.class,Main.CompareRuntime.class,Main.AnalyzeTvu.class,Main.Explain.class,Main.Bundle.class,Main.Rules.class,Main.Version.class})
public final class Main implements Callable<Integer> {
    @Spec Model.CommandSpec rootSpec;
    public static void main(String[] args){try{CommandLine cli=command();int code=cli.execute(args);cli.getOut().flush();cli.getErr().flush();System.exit(code);}catch(VirtualMachineError fatal){if(System.console()!=null&&System.getenv("CI")==null)System.err.print("\u001b[?25h");System.err.println("LedgerPreflight could not complete analysis safely. No upgrade readiness was established.");System.err.flush();System.exit(3);}}
    public static CommandLine command(){return new CommandLine(new Main()).setExecutionExceptionHandler((e,c,p)->{c.getErr().println("Assessment error: "+Sanitizer.redact(Objects.toString(e.getMessage(),e.getClass().getSimpleName())).replaceAll("[\\p{Cntrl}]"," "));return 3;});}
    public Integer call(){
        Console console=System.console();
        if(console==null || System.getenv("CI")!=null){
            rootSpec.commandLine().getOut().println("LedgerPreflight — Corda upgrade preflight\n\nSupply your current node and prepared target upgrade kit:\n  ledger-preflight assess --node /path/to/node --upgrade-kit /path/to/target\n\nRun in a terminal for guided setup. Use --help for all commands.");
            return 0;
        }
        console.printf("LedgerPreflight — Corda upgrade preflight%n%nPrepare your current node directory and a separate target upgrade kit.%nAssessment reads these inputs without changing the node or database.%nLeave a path blank to exit.%n%n");
        String node=console.readLine("Current node directory: ");
        if(node==null || node.isBlank())return 0;
        String kit=console.readLine("Target upgrade-kit directory: ");
        if(kit==null || kit.isBlank())return 0;
        return command().execute("assess","--node",node.strip(),"--upgrade-kit",kit.strip());
    }
    @Command(name="assess",mixinStandardHelpOptions=true,description="Assess current node and prepared target upgrade kit without modifying inputs.")
    public static final class Assess implements Callable<Integer> {
        @Option(names="--node",required=true) Path node;
        @Option(names="--upgrade-kit",required=true) Path kit;
        @Option(names="--output",defaultValue="reports") Path output;
        @Option(names="--target-corda") Path targetCorda;
        @Option(names="--tvu-jar") Path tvuJar;
        @Option(names="--target-cordapps") Path targetCordapps;
        @Option(names="--legacy-jars") Path legacyJars;
        @Option(names="--node-conf") Path nodeConf;
        @Option(names="--tvu-results",description="Repeat for logs, error ZIPs or evidence directories.") List<Path> tvuResults=new ArrayList<>();
        @Option(names="--verifier-classpath") Path verifierClasspath;
        @Option(names="--rule-pack") Path rulePack;
        @Option(names="--host-environment",description="Optional bounded JSON evidence: sourceHostOs, currentJava, plannedTargetJava.") Path hostEnvironment;
        @Option(names="--network-mode",defaultValue="unknown",description="Planned network state: mixed, all-4.12, or unknown.") String networkMode;
        @Option(names="--offline",description="Explicit offline mode (always enabled).") boolean offline;
        @Option(names="--json",description="Emit one sanitized JSON assessment on stdout; progress stays on stderr.") boolean json;
        @Option(names="--color",defaultValue="auto",description="Terminal color: auto, always, never. Auto is disabled for redirection and CI.") String color;
        @Option(names={"--verbose","--debug"},description="Include full evidence for every finding in terminal output; secrets remain redacted.") boolean verbose;
        @Option(names="--support-bundle",description="Create sanitized support.zip after the secret safety gate.") boolean bundle;
        @Option(names="--non-interactive",description="Print assessment and exit, even in a TTY.") boolean nonInteractive;
        @Option(names="--plain-terminal",description="Use numbered menus without cursor control in a TTY.") boolean plainTerminal;
        @Spec Model.CommandSpec spec;
        public Integer call()throws Exception {
            if(!Set.of("auto","always","never").contains(color))throw new IOException("Invalid --color: use auto, always or never");
            if(!Set.of("unknown","mixed","all-4.12").contains(networkMode))throw new IOException("Invalid --network-mode: use mixed, all-4.12 or unknown");
            node=node.toRealPath();kit=kit.toRealPath();
            Path out=output.toAbsolutePath().normalize();
            for(Path root:Arrays.asList(node,kit,targetCorda,tvuJar,targetCordapps,legacyJars,nodeConf,verifierClasspath,rulePack,hostEnvironment))if(root!=null)ensureOutputSeparate(out,root);
            for(Path root:tvuResults)ensureOutputSeparate(out,root);
            boolean interactive=System.console()!=null && System.getenv("CI")==null && !json && !nonInteractive;
            var options=new AssessmentService.Options(node,kit,targetCorda,tvuJar,targetCordapps,legacyJars,nodeConf,tvuResults,verifierClasspath,rulePack,networkMode,hostEnvironment);
            SessionTerminal terminalUI=SessionTerminal.system(spec.commandLine().getOut(),plainTerminal);
            if(interactive){options=DiscoverySession.prepare(options,terminalUI);if(options==null)return 0;}
            if(!interactive)spec.commandLine().getErr().println("Inspecting supplied artifacts read-only; no network or database connections...");
            Assessment a=new AssessmentService().assess(options,interactive?terminalUI::text:ignored->{});
            Map<String,String> files=Reports.files(a);Reports.write(output,files);
            if(interactive){if(verbose){terminalUI.text(Reports.terminal(a,true));terminalUI.choose("",List.of("Continue to assessment"));}}
            else if(json)spec.commandLine().getOut().print(Reports.json(a));
            else {String terminal=Reports.terminal(a,verbose);boolean colored=color.equals("always") || color.equals("auto") && System.console()!=null && System.getenv("CI")==null && !"dumb".equals(System.getenv("TERM"));if(colored){String ansi=a.status().equals("BLOCKED")?"\u001b[31m":a.status().startsWith("READY")?"\u001b[32m":"\u001b[33m";terminal=terminal.replace(" "+a.status()+"\n"," "+ansi+a.status()+"\u001b[0m\n");}spec.commandLine().getOut().print(terminal);}
            if(bundle)new SupportBundle().create(output.resolve("support.zip"),bundleFiles(files));
            if(!json&&!interactive)spec.commandLine().getOut().println("Full details: "+Sanitizer.redact(output.toString())+"/report.html");
            if(interactive)return new InteractiveSession(options,a,output,terminalUI).run();
            return a.exitCode();
        }
    }
    static void ensureOutputSeparate(Path out,Path input)throws IOException {
        Reports.checkNoSymlink(out);
        Path in=Files.exists(input)?input.toRealPath():input.toAbsolutePath().normalize();
        if(out.startsWith(in)||in.startsWith(out))throw new IOException("Report output must be separate from all assessment inputs");
    }
    public static Map<String,String> bundleFiles(Map<String,String> files){Map<String,String> b=new TreeMap<>(files);b.remove("report.json");String html=b.remove("report.html");if(html!=null)b.put("summary.html",html);b.put("README.txt","LedgerPreflight 0.1.0 sanitized generated evidence. No JARs, keys, raw configuration or raw logs are included. Review before sharing.\n");return b;}
    @Command(name="inventory",mixinStandardHelpOptions=true,description="Inventory node JAR metadata and classes without executing them.")
    static final class Inventory implements Callable<Integer> {
        @Option(names="--node",required=true) Path node;
        @Spec Model.CommandSpec spec;
        public Integer call()throws IOException {var scan=new BytecodeScanner().scan(node);spec.commandLine().getOut().print(Reports.json(Map.of("artifacts",Discovery.inventory(scan),"issues",scan.issues())));return scan.issues().isEmpty()?0:3;}
    }
    @Command(name="analyze-jar",mixinStandardHelpOptions=true,description="Inspect classes, references and exact JVM member descriptors.")
    static final class AnalyzeJar implements Callable<Integer> {
        @Parameters(index="0") Path jar;
        @Spec Model.CommandSpec spec;
        public Integer call()throws IOException {var scan=new BytecodeScanner().scan(jar);spec.commandLine().getOut().print(Reports.json(scan));return scan.issues().isEmpty()?0:3;}
    }
    @Command(name="compare-runtime",mixinStandardHelpOptions=true,description="Report declared API delta between supplied runtime inventories.")
    static final class CompareRuntime implements Callable<Integer> {
        @Option(names="--source",required=true) Path source;
        @Option(names="--target",required=true) Path target;
        @Spec Model.CommandSpec spec;
        public Integer call()throws IOException {var scanner=new BytecodeScanner();var s=scanner.scan(source);var t=scanner.scan(target);spec.commandLine().getOut().print(Reports.json(Map.of("delta",new CompatibilityAnalyzer().compare(s.jars(),t.jars()),"sourceIssues",s.issues(),"targetIssues",t.issues())));return s.issues().isEmpty()&&t.issues().isEmpty()?0:3;}
    }
    @Command(name="analyze-tvu",mixinStandardHelpOptions=true,description="Correlate TVU summary and supplied detailed error records.")
    static final class AnalyzeTvu implements Callable<Integer> {
        @Parameters(arity="1..*") List<Path> paths;
        @Spec Model.CommandSpec spec;
        public Integer call()throws IOException {var t=new TvuAnalyzer().analyze(paths);spec.commandLine().getOut().print(Reports.json(t));return t.failed()!=null&&t.failed()>0||!t.rootCauses().isEmpty()?2:t.completeSuccess()?0:3;}
    }
    @Command(name="explain",mixinStandardHelpOptions=true,description="Explain a built-in rule or analysis finding.")
    static final class Explain implements Callable<Integer> {
        @Parameters(index="0") String id;
        @Spec Model.CommandSpec spec;
        public Integer call()throws IOException {var rule=new RuleEngine().explain(id);if(rule.isPresent()){spec.commandLine().getOut().print(Reports.json(rule.get()));return 0;}
            Map<String,String> known=Map.of("LP-API-001","Exact JVM method/field identity includes the descriptor and invocation kind. Missing members can block verification. Runtime bytes determine this finding.","LP-INTERNAL-001","Internal Corda APIs have no normal API stability guarantee. Present symbols warn; absent required members can block.","LP-LEGACY-001","Duplicate classes never merge. Proven earlier runtime definitions prevent a later legacy class from supplying additional methods.","LP-DB-001","Mixed-case schema is a heuristic TVU compatibility risk; normal node and TVU schema resolution must be investigated independently.","LP-TVU-002","TVU failures block readiness. Detailed evidence counts do not imply every summary failure has the same root cause.");
            if(known.containsKey(id)){spec.commandLine().getOut().println(id+": "+known.get(id));return 0;}spec.commandLine().getErr().println("Unknown rule ID");return 3;}
    }
    @Command(name="support-bundle",mixinStandardHelpOptions=true,description="Package only allowlisted sanitized generated assessment evidence.")
    static final class Bundle implements Callable<Integer> {
        @Option(names="--assessment",required=true) Path assessment;
        @Option(names="--output",defaultValue="support.zip") Path output;
        public Integer call()throws IOException {
            Reports.checkNoSymlink(assessment);Map<String,String> files=new TreeMap<>();
            List<String> names=List.of("execution-contexts.json","required-symbol-resolution.json","current-runtime-selection.json","analysis-coverage.json","discovery.json","tvu-evidence-supplied.json","assessment.json","summary.txt","report.html","environment.json","upgrade-kit.json","cordapps-current.json","cordapps-target.json","runtime-api-delta.json","internal-api-usage.json","legacy-jars-analysis.json","classpath-analysis.json","schema-analysis.json","tvu-summary.json","findings.json","reproduction.txt","sanitized-node.conf");
            if(!Files.isDirectory(assessment,LinkOption.NOFOLLOW_LINKS))throw new IOException("Assessment must be a generated report directory");
            for(String name:names){Path p=assessment.resolve(name);if(Files.exists(p,LinkOption.NOFOLLOW_LINKS))files.put(name,new String(SafeInputs.read(p,SafeInputs.MAX_TEXT_BYTES),StandardCharsets.UTF_8));}
            if(!files.containsKey("assessment.json"))throw new IOException("assessment.json is required");new SupportBundle().create(output,bundleFiles(files));return 0;
        }
    }
    @Command(name="rules",mixinStandardHelpOptions=true,subcommands={Rules.ListRules.class})
    static final class Rules implements Runnable {public void run(){CommandLine.usage(this,System.out);}
        @Command(name="list",mixinStandardHelpOptions=true)static final class ListRules implements Callable<Integer>{@Spec Model.CommandSpec spec;public Integer call()throws IOException{spec.commandLine().getOut().print(Reports.json(new RuleEngine().catalog()));return 0;}}
    }
    @Command(name="version")static final class Version implements Runnable {public void run(){System.out.println("LedgerPreflight 0.1.0; report schema 1; rule pack "+RuleEngine.PACK_VERSION);}}
}
