package io.ledgerpreflight.reporting;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.Sanitizer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class Reports {
    public static final ObjectMapper JSON=new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    public static String json(Object value)throws IOException {JsonNode node=JSON.valueToTree(value);return JSON.writeValueAsString(sanitize(node))+"\n";}
    private static JsonNode sanitize(JsonNode node){
        if(node.isTextual())return TextNode.valueOf(Sanitizer.redact(node.textValue()));
        if(node.isObject()){ObjectNode out=JSON.createObjectNode();node.fields().forEachRemaining(e->out.set(Sanitizer.redact(e.getKey()),Sanitizer.isSensitiveKey(e.getKey())?TextNode.valueOf("[REDACTED]"):sanitize(e.getValue())));return out;}
        if(node.isArray()){ArrayNode out=JSON.createArrayNode();node.forEach(n->out.add(sanitize(n)));return out;}
        return node;
    }
    public static String terminal(Assessment a){return terminal(a,false);}
    public static String findingSummary(Finding finding){return finding.id()+" · "+executiveTitle(finding)+"\n"+executiveWhy(finding);}
    public static String terminal(Assessment a,boolean verbose){
        if(!verbose){StringBuilder out=new StringBuilder();for(String line:ProductView.result(a).split("\n",-1))terminalLine(out,line);return out.toString();}
        StringBuilder out=new StringBuilder("LedgerPreflight 0.1.0\nKnow what will break before you upgrade Corda.\n\nUpgrade: ").append(a.sourceVersion()).append(" -> ").append(a.targetVersion()).append("\nOVERALL STATUS: ").append(a.status()).append("\n");
        JsonNode host=JSON.valueToTree(a.evidence().getOrDefault("environment",Map.of())).path("host");
        out.append("\nExecution host OS: ").append(host.path("executionOs").asText("UNKNOWN")).append(" (").append(host.path("executionArch").asText("UNKNOWN")).append(")\n")
            .append("Source host OS: ").append(host.path("sourceHostOs").asText("UNKNOWN")).append('\n')
            .append("Current Java: ").append(host.path("currentJava").asText("UNKNOWN")).append(" [").append(host.path("currentJavaSource").asText("NOT_SUPPLIED")).append("]\n")
            .append("Analyzer Java: ").append(host.path("analyzerJava").asText("UNKNOWN")).append(" (this process)\n")
            .append("Target required Java: ").append(host.path("targetRequiredJava").asText("UNKNOWN")).append("; planned: ").append(host.path("plannedTargetJava").asText("UNKNOWN")).append('\n')
            .append("Target Java readiness: ").append(host.path("targetJavaReadiness").asText("UNVERIFIED")).append('\n')
            .append("Execution host and analyzer Java do not establish the current node's runtime.\n");
        for(Finding f:a.findings()) {
            if(!verbose && f.severity().equals("INFO"))continue;
            out.append("\n[").append(f.severity()).append("] ").append(f.id()).append(" — ").append(f.title()).append('\n');
            List<String> details=f.technicalEvidence();
            if(!verbose)details=details.stream().sorted(Comparator.comparing((String e)->!(e.toLowerCase(Locale.ROOT).contains("descriptor")||e.toLowerCase(Locale.ROOT).startsWith("member:")))).limit(3).toList();
            for(String e:details)out.append("  ").append(e).append('\n');
            if(!verbose && f.technicalEvidence().size()>details.size())out.append("  Additional evidence is in the HTML/JSON report.\n");
            out.append("  Impact: ").append(f.impact()).append("\n  Next action: ").append(f.recommendedNextAction()).append('\n');
        }
        out.append("\n").append(a.findings().stream().filter(f->Set.of("BLOCKED","ERROR").contains(f.severity())).count()).append(" blockers; ").append(a.findings().stream().filter(f->f.severity().equals("WARNING")).count()).append(" warnings; ").append(passedGates(a)).append("/").append(JSON.valueToTree(a.gates()).size()).append(" readiness gates passed\n");
        out.append("\nStatic preflight does not modify the node. Continue the official R3 upgrade guide and required validation.\n");
        return Sanitizer.redact(out.toString()).replaceAll("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]", "");
    }
    private static String conciseTerminal(Assessment a) {
        StringBuilder out=new StringBuilder();
        JsonNode environment=JSON.valueToTree(a.evidence().getOrDefault("environment",Map.of()));
        terminalLine(out,"LedgerPreflight "+a.productVersion());
        terminalLine(out,"Node: "+shortText(environment.path("nodeName").asText("supplied current node"),48));
        terminalLine(out,shortText(a.sourceVersion(),24)+" → "+shortText(a.targetVersion(),24));
        out.append('\n');terminalLine(out,marker(a.status())+" "+a.status());
        List<Finding> blockers=a.findings().stream().filter(f->Set.of("BLOCKED","ERROR").contains(f.severity())).toList();
        List<Finding> warnings=a.findings().stream().filter(f->f.severity().equals("WARNING")).toList();
        terminalLine(out,"✕ BLOCKED "+blockers.size()+" · ! WARNING "+warnings.size()+" · ✓ PASS "+passedGates(a)+"/"+JSON.valueToTree(a.gates()).size()+" checks");
        List<Finding> priority=blockers.isEmpty()?a.findings().stream().filter(f->f.severity().equals("UNKNOWN")).toList():blockers;
        List<Finding> shown=new ArrayList<>();
        out.append('\n');terminalLine(out,"WHAT STOPS THIS UPGRADE");
        for(Finding finding:priority.stream().limit(2).toList()) {
            shown.add(finding);
            terminalLine(out,marker(finding.severity())+" "+finding.id()+" · "+shortText(executiveTitle(finding),83));
            terminalLine(out,"  "+shortText(executiveWhy(finding),140));
        }
        if(priority.isEmpty())terminalLine(out,a.status().equals("READY TO UPGRADE")?"✓ PASS Assessed gates passed; continue the official upgrade procedure.":a.status().equals("READY FOR TVU")?"? UNKNOWN Complete TVU validation is still required.":"! WARNING Review the outstanding warnings before proceeding.");
        if(!warnings.isEmpty()) {
            Finding finding=warnings.get(0);shown.add(finding);out.append('\n');
            terminalLine(out,"! WARNING "+finding.id()+" · "+shortText(executiveTitle(finding),76));
            terminalLine(out,"  "+shortText(executiveWhy(finding),120));
        }
        long hidden=a.findings().size()-shown.size();
        if(hidden>0){out.append('\n');terminalLine(out,hidden+" additional findings are available in the full report.");}
        out.append('\n');terminalLine(out,"NEXT");
        List<String> actions=shown.stream().filter(f->!f.id().equals("LP-TVU-002")).map(Reports::executiveAction).distinct().limit(2).toList();
        int step=1;
        for(String action:actions)terminalLine(out,(step++)+". "+shortText(action,128));
        terminalLine(out,step+". "+(a.status().equals("READY TO UPGRADE")?"Continue the official R3 procedure and your change approval process.":"Rerun complete TVU validation, then reassess with its results."));
        out.append('\n');terminalLine(out,"Read-only assessment. Final readiness requires successful TVU evidence.");
        return out.toString();
    }
    private static String marker(String status) { return switch(status){case "BLOCKED","ERROR"->"✕";case "WARNING"->"!";case "READY TO UPGRADE","PASS"->"✓";default->"?";}; }
    private static void terminalLine(StringBuilder out,String text) {
        String remaining=Sanitizer.redact(text).replaceAll("[\\p{Cntrl}]"," ").replaceAll("\\s+"," ").strip();
        while(remaining.length()>76){int split=remaining.lastIndexOf(' ',76);if(split<30)split=76;out.append(remaining,0,split).append('\n');remaining=remaining.substring(split).stripLeading();}
        out.append(remaining).append('\n');
    }
    public static String html(Assessment a){
        List<Finding> blockers=a.findings().stream().filter(f->Set.of("BLOCKED","ERROR").contains(f.severity())).toList();
        List<Finding> unknown=a.findings().stream().filter(f->f.severity().equals("UNKNOWN")).toList();
        long warnings=a.findings().stream().filter(f->f.severity().equals("WARNING")).count();
        JsonNode gates=JSON.valueToTree(a.gates()); long passed=0;
        for(JsonNode gate:gates)if(gate.asText().equals("PASS"))passed++;
        String tone=!blockers.isEmpty()?"blocked":a.status().equals("READY TO UPGRADE")?"ready":"review";
        String disposition=switch(a.status()) {
            case "BLOCKED" -> "Do not proceed to final upgrade validation until the blockers below are resolved.";
            case "READY TO UPGRADE" -> "Supplied evidence passes the assessed gates. Continue the official upgrade procedure and change approvals.";
            case "READY FOR TVU" -> "Static checks passed. Complete the required TVU validation before proceeding with the upgrade.";
            case "UNKNOWN" -> "Readiness is unproven. Resolve the missing or incomplete evidence before proceeding.";
            default -> "Review the warnings and complete outstanding validation before proceeding.";
        };
        StringBuilder h=new StringBuilder("""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>LedgerPreflight — Upgrade assessment</title><style>
            :root{color-scheme:light;--ink:#182b3c;--muted:#586a77;--line:#dce3e7;--red:#a52e35;--amber:#885916;--green:#1b6954}*{box-sizing:border-box}body{margin:0;background:#edf0f2;color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:1120px;margin:28px auto;background:white;padding:34px 48px 28px;box-shadow:0 4px 28px #182b3c0b;border-top:5px solid var(--ink)}header{display:flex;align-items:flex-start;justify-content:space-between;gap:24px}h1{font-size:30px;letter-spacing:-1px;line-height:1.1;margin:0 0 7px}h2{font-size:12px;letter-spacing:1.3px;margin:0 0 18px;text-transform:uppercase}h3{font-size:16px;line-height:1.4;margin:4px 0}p{margin:6px 0 12px}.eyebrow,.meta,.quiet{color:var(--muted);font-size:12px}.eyebrow{text-transform:uppercase;letter-spacing:1.4px}.meta{text-align:right}.meta strong{display:block;font-size:17px;color:var(--ink);margin-bottom:3px}.decision{margin-top:24px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:18px 0;display:flex;justify-content:space-between;align-items:center;gap:24px}.state{font-size:23px;font-weight:750;letter-spacing:.3px;line-height:1.2}.blocked{color:var(--red)}.review{color:var(--amber)}.ready{color:var(--green)}.disposition{max-width:610px;font-size:14px;margin:8px 0 0}.counts{display:flex;gap:24px;flex-shrink:0;text-align:center}.counts strong{display:block;font-size:27px;line-height:1.2;font-weight:650}.counts span{display:block;font-size:11px;white-space:nowrap;color:var(--muted)}.first-page{display:grid;grid-template-columns:1.15fr 1fr;gap:42px;padding:25px 0 23px}.action-panel{border-left:1px solid var(--line);padding-left:30px}.stop-list{list-style:none;padding:0;margin:0}.stop-list li{margin-bottom:15px}.rule{font:11px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--red)}.stop-list p{font-size:13px;color:var(--muted);margin:4px 0}.actions{padding-left:20px;margin:0}.actions li{padding-left:5px;margin-bottom:14px;font-size:14px}.actions li::marker{font-weight:700;color:var(--ink)}a{color:#225e7a;text-decoration-thickness:1px;text-underline-offset:3px}.review-note{font-size:12px;color:var(--muted);margin:12px 0 0}.technical{border-top:2px solid var(--ink);padding-top:22px}.technical>p{font-size:13px;color:var(--muted);margin-top:-9px;margin-bottom:19px}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-size:14px;font-weight:600;padding-right:12px}summary::marker{color:#607b8b}details[open]>summary{margin-bottom:14px}.finding{padding:12px 0;border-bottom:1px solid var(--line)}.finding:last-child{border-bottom:0}.finding p{font-size:13px}.finding .quiet{font-size:11px}pre{font:12px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f7;padding:16px;border-left:2px solid #ccd8df;margin:12px 0}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace}footer{border-top:1px solid var(--line);padding-top:18px;margin-top:12px;font-size:11px;line-height:1.6;color:var(--muted)}.page-id{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px;margin-top:10px;overflow-wrap:anywhere}@media(max-width:760px){main{margin:0;padding:26px 22px;box-shadow:none}header{display:block}.meta{text-align:left;margin-top:16px}.decision{display:block}.counts{justify-content:flex-start;margin-top:18px}.first-page{grid-template-columns:1fr;gap:24px}.action-panel{padding-left:0;border-left:0;border-top:1px solid var(--line);padding-top:22px}}@media print{body{background:white}main{margin:0;max-width:none;padding:20px;box-shadow:none}details,.finding{break-inside:avoid}a{color:inherit}.first-page{break-inside:avoid}}
            </style></head><body><main><header><div><h1>LedgerPreflight</h1><div class="eyebrow">Upgrade assurance report</div></div><div class="meta"><strong>
            """);
        h.append(escape(a.sourceVersion())).append(" → ").append(escape(a.targetVersion())).append("</strong>Current environment → prepared target<br>Offline assessment · read-only inputs</div></header>");
        h.append("<section class=\"decision\" aria-label=\"Assessment decision\"><div><div class=\"state ").append(tone).append("\">").append(escape(ProductView.state(a))).append("</div><p class=\"disposition\">").append(disposition).append("</p></div><div class=\"counts\"><div><strong class=\"blocked\">").append(blockers.size()).append("</strong><span>Blockers</span></div><div><strong class=\"review\">").append(warnings).append("</strong><span>Warnings</span></div><div><strong class=\"ready\">").append(passed).append("</strong><span>Passed checks</span><span>of ").append(gates.size()).append(" readiness gates</span></div></div></section>");
        h.append("<div class=\"first-page\"><section aria-labelledby=\"stops-heading\"><h2 id=\"stops-heading\">What stops this upgrade</h2><ul class=\"stop-list\">");
        List<Finding> priority=blockers.isEmpty()?unknown:blockers;
        List<ProductView.Issue> grouped=ProductView.issues(a);
        for(var issue:grouped.stream().limit(3).toList())h.append("<li><h3>").append(issue.warning()?"! ":"").append(escape(issue.title())).append("</h3><p><strong>What happened:</strong> ").append(escape(issue.happened())).append("</p><p><strong>Why it matters:</strong> ").append(escape(issue.matters())).append("</p><p><strong>What to do:</strong> ").append(escape(issue.action())).append("</p></li>");
        if(grouped.isEmpty())h.append("<li><h3>").append(a.status().equals("READY TO UPGRADE")?"No blockers in the supplied evidence":a.status().equals("READY FOR TVU")?"Required TVU validation is outstanding":"Warning review is outstanding").append("</h3><p>").append(disposition).append("</p></li>");
        h.append("</ul>");
        if(grouped.size()>3)h.append("<p class=\"review-note\">Showing 3 of ").append(grouped.size()).append(" issue groups. <a href=\"#technical\">Review all technical findings below.</a></p>");
        if(!unknown.isEmpty()&&!blockers.isEmpty())h.append("<p class=\"review-note\">").append(unknown.size()).append(" additional findings have incomplete evidence.</p>");
        h.append("</section><section class=\"action-panel\" aria-labelledby=\"actions-heading\"><h2 id=\"actions-heading\">What to do next</h2><ol class=\"actions\">");
        List<String> actions=grouped.stream().filter(i->!i.title().equals("TVU validation")).map(ProductView.Issue::action).distinct().limit(2).toList();
        for(String action:actions)h.append("<li>").append(escape(shortText(action,215))).append("</li>");
        h.append("<li>").append(a.status().equals("READY TO UPGRADE")?"Continue the official R3 upgrade procedure, lower-environment validation and your production change process.":"Rerun the complete TVU validation, then reassess with its results.").append("</li></ol><p class=\"review-note\">Full instructions and supporting evidence are retained below.</p></section></div>");
        h.append("<section class=\"technical\" id=\"technical\"><h2>Technical evidence</h2><p>Expand the sections needed for engineering review or a change request. Descriptors, inventories and traces are secondary to the decision above.</p><details><summary>All findings — blockers, warnings and evidence gaps (").append(a.findings().size()).append(")</summary>");
        for(Finding f:a.findings())h.append("<div class=\"finding\"><div class=\"quiet\">").append(escape(f.id()+" · "+f.severity()+" · "+f.confidence()+" · "+f.source())).append("</div><h3>").append(escape(f.title())).append("</h3><p><strong>Impact:</strong> ").append(escape(f.impact())).append("</p><p><strong>Next action:</strong> ").append(escape(f.recommendedNextAction())).append("</p><pre>").append(escape(String.join("\n",f.technicalEvidence()))).append("</pre></div>");
        h.append("</details>");
        appendEvidence(h,"Readiness gates",a.gates());
        String[][] sections={{"Node discovery and selection","node-discovery"},{"Current environment and source inventory","environment"},{"Target upgrade kit","upgrade-kit"},{"Current CorDapps","cordapps-current"},{"Target CorDapps","cordapps-target"},{"API compatibility and member descriptors","runtime-api-delta"},{"Internal API usage","internal-api-usage"},{"legacy-jars and duplicate classes","legacy-jars-analysis"},{"Verifier classpath evidence","classpath-analysis"},{"Schema and configuration analysis","schema-analysis"},{"TVU summary and supplied failure records","tvu-summary"}};
        for(String[] section:sections)appendEvidence(h,section[0],a.evidence().getOrDefault(section[1],"Evidence unavailable"));
        appendEvidence(h,"Artifact integrity — SHA-256",a.hashes());
        appendEvidence(h,"Complete sanitized assessment record",a);
        h.append("<details><summary>Support escalation</summary><p>Package the generated evidence for your approved support channel. Review the archive before sharing.</p><pre>ledger-preflight support-bundle --assessment /reports --output support.zip</pre><p class=\"quiet\">The bundle contains allowlisted sanitized evidence. LedgerPreflight does not upload it.</p></details></section><footer>Independent analysis; not affiliated with, endorsed by, or supported by R3. Corda and R3 trademarks belong to their respective owners. Static preflight does not modify the node or replace R3’s upgrade guide. Final readiness requires successful required TVU evidence. Reflection, dynamic loading and historical attachment coverage require operator validation.<div class=\"page-id\">Assessment ").append(escape(a.assessmentId())).append(" · ").append(escape(a.timestamp())).append(" · LedgerPreflight ").append(escape(a.productVersion())).append("</div></footer></main></body></html>\n");
        return h.toString();
    }
    private static long passedGates(Assessment assessment) { long count=0;for(JsonNode gate:JSON.valueToTree(assessment.gates()))if(gate.asText().equals("PASS"))count++;return count; }
    private static String executiveTitle(Finding finding) {
        return switch(finding.id()) {
            case "LP-API-001" -> finding.title().contains("static/instance")?"CorDapp requires an incompatible runtime member":"Historical CorDapp requires a missing runtime member";
            case "LP-LEGACY-001" -> "Legacy compatibility shim is shadowed";
            case "LP-TVU-002" -> "Historical transaction validation failed";
            default -> finding.title();
        };
    }
    private static String executiveWhy(Finding finding) {
        if(finding.id().equals("LP-API-001")) {
            String owner=evidenceValue(finding,"owner"),member=evidenceValue(finding,"member");
            if(owner!=null && member!=null) {
                owner=owner.replace('/','.');owner=owner.substring(owner.lastIndexOf('.')+1);
                return shortText(owner+"."+member,90)+" is unavailable in the required form. Historical verification may fail.";
            }
            return "The target runtime does not provide the member the CorDapp requires. Historical verification may fail.";
        }
        if(finding.id().equals("LP-LEGACY-001"))return "Java selects one whole class. The earlier runtime class cannot gain methods from a later compatibility shim.";
        if(finding.id().equals("LP-TVU-002")) {
            for(String evidence:finding.technicalEvidence()) {
                var counts=java.util.regex.Pattern.compile("(\\d+|unknown) processed; (\\d+|unknown) succeeded; (\\d+|unknown) failures reported").matcher(evidence);
                if(counts.find())return counts.group(1)+" processed · "+counts.group(2)+" succeeded · "+counts.group(3)+" failures reported. Supplied details are below.";
            }
            return "Supplied TVU evidence reports a verification failure. Review the available totals and failure records below.";
        }
        return finding.impact();
    }
    private static String executiveAction(Finding finding) {
        return switch(finding.id()) {
            case "LP-API-001" -> "Resolve the required member with a supported target runtime or CorDapp fix.";
            case "LP-LEGACY-001" -> "Validate the verifier's selected classes; remove or replace the ineffective shim.";
            default -> finding.recommendedNextAction();
        };
    }
    private static String evidenceValue(Finding finding,String key) { for(String value:finding.technicalEvidence())if(value.startsWith(key+": "))return value.substring(key.length()+2);return null; }
    private static String shortText(String text,int limit) { if(text.length()<=limit)return text;int end=text.lastIndexOf(' ',limit-1);return text.substring(0,end>limit/2?end:limit-1)+"…"; }
    private static void appendEvidence(StringBuilder h,String title,Object value) { h.append("<details><summary>").append(escape(title)).append("</summary><pre>").append(escape(jsonView(value))).append("</pre></details>"); }
    private static String jsonView(Object value) { try{return json(value);}catch(IOException e){throw new IllegalStateException("Generated report evidence could not be serialized",e);} }
    private static String escape(String text){return Sanitizer.redact(text).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}
    public static Map<String,String> files(Assessment a)throws IOException {
        Map<String,String> out=new TreeMap<>();out.put("assessment.json",json(a));out.put("report.json",json(a));out.put("report.html",html(a));out.put("findings.json",json(a.findings()));out.put("summary.txt",terminal(a));
        for(var e:a.evidence().entrySet()) if(!e.getKey().equals("sanitized-node.conf"))out.put(e.getKey()+".json",json(e.getValue()));
        out.put("sanitized-node.conf",Sanitizer.redact(Objects.toString(a.evidence().get("sanitized-node.conf"),"# unavailable\n")));
        out.put("reproduction.txt","ledger-preflight assess --node /node --upgrade-kit /upgrade-kit --output /reports --offline\nSupply optional TVU and verifier evidence with --tvu-results and --verifier-classpath. Inputs are never bundled.\n");
        return out;
    }
    public static void write(Path directory,Map<String,String> files)throws IOException {
        Path root=directory.toAbsolutePath().normalize();checkNoSymlink(root);Files.createDirectories(root);
        for(var entry:files.entrySet()){
            Path p=root.resolve(entry.getKey()).normalize();if(!p.startsWith(root))throw new IOException("Unsafe report path");checkNoSymlink(p);
            Files.writeString(p,entry.getValue(),StandardCharsets.UTF_8,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,LinkOption.NOFOLLOW_LINKS);
        }
    }
    public static void checkNoSymlink(Path path)throws IOException {for(Path p=path.toAbsolutePath();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Symbolic-link path rejected");}
}
