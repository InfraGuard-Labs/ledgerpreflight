package io.ledgerpreflight.core;

import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import java.util.*;

/** The short product answer; complete evidence remains in the assessment record. */
public final class ProductView {
    public record Issue(String title,String happened,String matters,String action,boolean warning,List<String> findingIds,boolean blocking){
        private boolean unresolvedSchema(){return blocking&&title.equals("Schema configuration")&&findingIds.contains("LP-DB-001");}
        public String summaryHappened(){return unresolvedSchema()?"The node uses a mixed-case PostgreSQL schema and the required TVU schema configuration is not proven.":happened;}
        public String summaryMatters(){return unresolvedSchema()?"TVU may fail or validate against the wrong schema.":matters;}
        public String summaryAction(){return unresolvedSchema()?"Configure the intended TVU Hibernate default schema and rerun validation.":action;}
    }
    public static String state(Assessment a){return a.status().startsWith("READY ")?a.status():"NOT READY TO UPGRADE";}
    private static boolean attention(Finding f){return Set.of("BLOCKED","ERROR","UNKNOWN","WARNING").contains(f.severity());}
    public static List<Issue> issues(Assessment a) {
        Map<String,List<Finding>> groups=new LinkedHashMap<>();
        for(Finding f:a.findings())if(attention(f)) {
            String group=switch(f.category()){
                case "API_COMPATIBILITY"->f.severity().equals("UNKNOWN")&&value(f,"resolution").equals("unknown")?"Compatibility analysis incomplete":"CorDapp compatibility";
                case "CORDAPP"->f.id().equals("LP-CORDAPP-005")?"Target CorDapp mapping":"CorDapp compatibility";
                case "INTERNAL_API","LEGACY_JARS","SIGNING"->"CorDapp compatibility";
                case "TVU"->"TVU validation";
                case "DATABASE_SCHEMA"->"Schema configuration";
                case "SECURITY"->"Compatibility analysis incomplete";
                case "JAVA"->"Target Java";
                case "CONFIGURATION"->"Environment configuration";
                default->"Upgrade preparation";
            };
            groups.computeIfAbsent(group,k->new ArrayList<>()).add(f);
            if(blockedApi(f)&&!value(f,"unknownContexts").isEmpty())groups.computeIfAbsent("Compatibility analysis incomplete",k->new ArrayList<>()).add(f);
        }
        boolean confirmedCompatibility=a.findings().stream().anyMatch(ProductView::blockedApi);
        List<Issue> result=new ArrayList<>();
        for(var group:groups.entrySet()) {
            List<Finding> fs=group.getValue();boolean warning=fs.stream().allMatch(f->f.severity().equals("WARNING"));
            String happened,matters,action;
            Finding first=fs.get(0);
            switch(group.getKey()) {
                case "CorDapp compatibility" -> {
                    boolean absent=fs.stream().anyMatch(ProductView::blockedApi);
                    boolean shadow=fs.stream().anyMatch(f->f.id().equals("LP-LEGACY-001")&&f.severity().equals("BLOCKED"));
                    String scope=fs.stream().filter(ProductView::blockedApi).allMatch(f->value(f,"sourceScope").equals("active-current-cordapp")||f.affectedArtifact().startsWith("current/historical/"))?"A historical CorDapp":"A supplied CorDapp";
                    boolean nodeBlocked=fs.stream().filter(ProductView::blockedApi).anyMatch(f->value(f,"blockedContexts").isEmpty()||context(f,"blockedContexts","TARGET_NODE_RUNTIME"));
                    boolean verifierBlocked=fs.stream().filter(ProductView::blockedApi).anyMatch(f->context(f,"blockedContexts","TARGET_VERIFIER"));
                    String target=nodeBlocked?(verifierBlocked?"target Corda runtime and its verifier":"target Corda runtime"):"target verifier";
                    happened=absent?scope+" uses an API that is not available in the "+target+".":first.title()+".";
                    if(shadow)happened+=" The verifier selects an earlier class, so the compatibility JAR cannot supply the fix.";
                    matters="Historical transactions using this CorDapp may fail re-verification after the upgrade.";
                    action=absent?(!nodeBlocked&&verifierBlocked?"Use a compatible target verifier or supported compatibility fix, then validate again.":"Use a compatible target runtime or supported compatibility fix, then validate again."):first.recommendedNextAction();
                }
                case "Target CorDapp mapping" -> {
                    happened="Target CorDapp mapping: unresolved.";
                    matters="Replacement and signing continuity checks need a clear current-to-target CorDapp pairing.";
                    action="Confirm which target CorDapp replaces the current CorDapp, then validate again.";
                }
                case "TVU validation" -> {
                    GuidedFailure execution=guidedFailure(a);
                    if(execution!=null) {
                        happened=execution.happened();matters="Successful complete validation is required before upgrading.";action=execution.action();
                    } else if(a.evidence().get("tvu-summary") instanceof TvuEvidence t && t.failed()!=null&&t.failed()>0) {
                        happened=Objects.toString(t.processed(),"Unconfirmed")+" processed · "+Objects.toString(t.succeeded(),"unconfirmed")+" passed · "+t.failed()+" failed.";
                        String correlation=correlation(a,t);if(!correlation.isEmpty())happened+="\n  "+correlation;
                        matters="Required historical transaction validation has not passed.";
                        action=correlation.isEmpty()?"Resolve the supplied failure causes and rerun complete TVU.":"Resolve the compatibility problem first, then rerun complete TVU.";
                    } else {happened=first.title()+".";matters="Successful complete validation is required before upgrading.";action=first.recommendedNextAction();}
                }
                case "Schema configuration" -> {
                    boolean ambiguous=fs.stream().anyMatch(f->f.id().equals("LP-DB-002"));
                    happened=ambiguous?"Schema declarations disagree; the effective schema is not established.":fs.stream().anyMatch(f->f.id().equals("LP-DB-003"))?"TVU reported a schema-validation failure.":"The node uses a mixed-case PostgreSQL schema.";
                    matters=ambiguous?"Node and TVU may select different schemas.":"TVU may require an explicit Hibernate default schema for this setup.";
                    action="Confirm/configure the intended TVU schema and rerun validation.";
                }
                case "Compatibility analysis incomplete" -> {
                    happened=confirmedCompatibility?"Additional compatibility analysis is incomplete.":"A required compatibility question could not be resolved safely.";
                    matters="Compatibility remains unproven for the affected source CorDapp.";
                    action="Export the full technical report for the affected inputs. Complete compatibility analysis before upgrading.";
                }
                default -> {happened=first.title()+".";matters=first.impact();action=first.recommendedNextAction();}
            }
            boolean blocking=fs.stream().anyMatch(f->Set.of("BLOCKED","ERROR").contains(f.severity())&&!(group.getKey().equals("Compatibility analysis incomplete")&&blockedApi(f)));
            result.add(new Issue(group.getKey(),happened,matters,action,warning,fs.stream().map(Finding::id).distinct().toList(),blocking));
        }
        result.sort(Comparator.comparing((Issue i)->!i.blocking()).thenComparing(Issue::warning).thenComparingInt(i->switch(i.title()){case "CorDapp compatibility"->0;case "TVU validation"->1;case "Schema configuration"->2;case "Compatibility analysis incomplete"->3;default->4;}));
        return List.copyOf(result);
    }
    private static boolean blockedApi(Finding f){return f.category().equals("API_COMPATIBILITY")&&f.severity().equals("BLOCKED");}
    private static boolean context(Finding f,String key,String context){return Arrays.stream(value(f,key).split(",")).map(String::trim).anyMatch(context::equals);}
    /** Exact owner/member/descriptor correlation, scoped strictly to supplied detailed records. */
    public static String correlation(Assessment a,TvuEvidence tvu) {
        long matching=0;
        for(var root:tvu.rootCauses().entrySet()) {
            boolean match=a.findings().stream().filter(f->f.category().equals("API_COMPATIBILITY")&&f.severity().equals("BLOCKED")).anyMatch(f->matches(f,root.getKey()));
            if(match)matching+=root.getValue();
        }
        if(matching==0)return "";
        if(tvu.consistent()&&tvu.failed()!=null&&matching==tvu.failed()&&tvu.detailedRecords()==tvu.failed())
            return matching+" supplied failures match the compatibility problem.";
        return matching+" supplied failure details match the compatibility problem; other reported failures are unclassified.";
    }
    private static boolean matches(Finding f,String root) {
        String resolution=value(f,"resolution");
        if(!resolution.isEmpty()&&!Set.of("missing-method","descriptor-mismatch").contains(resolution))return false;
        String owner=value(f,"owner"),member=value(f,"member"),descriptor=value(f,"descriptor");
        if(owner.isEmpty()||member.isEmpty()||descriptor.isEmpty()||!root.contains("NoSuchMethodError"))return false;
        String dotted=owner.replace('/','.');
        if(root.contains(dotted+"."+member+descriptor)||root.contains(owner+"."+member+descriptor))return true;
        try {
            org.objectweb.asm.Type type=org.objectweb.asm.Type.getMethodType(descriptor);
            String args=String.join(",",Arrays.stream(type.getArgumentTypes()).map(org.objectweb.asm.Type::getClassName).toList());
            return root.contains(type.getReturnType().getClassName()+" "+dotted+"."+member+"("+args+")");
        }catch(IllegalArgumentException ignored){return false;}
    }
    private static String value(Finding f,String key){return f.technicalEvidence().stream().filter(s->s.startsWith(key+": ")).map(s->s.substring(key.length()+2)).findFirst().orElse("");}
    public static String schemaSetupStatus(Assessment a) {
        Object cfg=a.evidence().get("schema-analysis");
        Object settings=cfg instanceof io.ledgerpreflight.evidence.ConfigAnalyzer.ConfigEvidence c?c.safeSettings():cfg instanceof Map<?,?> map?map.get("safeSettings"):null;
        Object readiness=settings instanceof Map<?,?> map?map.get("tvuSchemaReadiness"):null;
        if(a.findings().stream().anyMatch(f->Set.of("LP-DB-003","LP-DB-004").contains(f.id())&&f.severity().equals("BLOCKED")))return "FAILED";
        return readiness instanceof io.ledgerpreflight.evidence.ConfigAnalyzer.TvuSchemaReadiness r?r.status():readiness instanceof Map<?,?> map?Objects.toString(map.get("status"),""):"";
    }
    private static String schemaSetup(Assessment a) {
        return switch(schemaSetupStatus(a)){
            case "AUTO_CONFIGURABLE" -> "\nSchema setup\nMixed-case PostgreSQL schema detected.\nLedgerPreflight can configure the required TVU schema automatically\nin the guided validation workspace.\n";
            case "HANDLED" -> a.evidence().containsKey("tvu-run")?"\nSchema setup\n✓ LedgerPreflight configured the required TVU schema for this run.\n":"\nSchema setup\n✓ The supplied TVU evidence confirms the required schema.\n";
            case "CONFIGURATION_PROVEN" -> "\nSchema setup\nThe selected configuration explicitly defines the intended schema.\n";
            default -> "";
        };
    }
    private static String tvuOutcome(Assessment a) {
        Object value=a.evidence().get("tvu-run");if(!(value instanceof Map<?,?> run))return "";
        String description=switch(Objects.toString(run.get("failureKind"),"")){
            case "SETUP_FAILURE" -> "TVU setup could not be completed. Review the reported setup problem.";
            case "DATABASE_CONNECTION_FAILURE" -> "TVU could not connect to the confirmed isolated database.";
            case "EXECUTION_FAILURE" -> "The TVU run did not complete successfully.";
            case "USER_CANCELLATION" -> "TVU run cancelled. Partial evidence was saved.";
            default -> "";
        };
        return description.isEmpty()?"":"\nTVU\n"+description+"\n";
    }
    private record GuidedFailure(String happened,String action){}
    private static GuidedFailure guidedFailure(Assessment a) {
        // Preserve actually observed transaction failures even if execution later stops.
        if(a.evidence().get("tvu-summary") instanceof TvuEvidence t&&t.failed()!=null&&t.failed()>0)return null;
        Object value=a.evidence().get("tvu-run");if(!(value instanceof Map<?,?> run))return null;
        return switch(Objects.toString(run.get("failureKind"),"")) {
            case "USER_CANCELLATION" -> new GuidedFailure("TVU run cancelled. Partial evidence was saved.","Run TVU again when ready to complete validation.");
            case "DATABASE_CONNECTION_FAILURE" -> new GuidedFailure("TVU could not connect to the confirmed isolated database.","Check the confirmed isolated database connection, then run TVU again.");
            case "SETUP_FAILURE" -> new GuidedFailure("TVU setup could not be completed.","Review the reported setup problem, correct it, then run TVU again.");
            case "EXECUTION_FAILURE" -> new GuidedFailure("The TVU run did not complete successfully.","Review the captured execution and cleanup evidence, then run TVU again.");
            default -> null;
        };
    }
    public static String result(Assessment a) {
        Object env=a.evidence().get("environment");String node=env instanceof Map<?,?> map?Objects.toString(map.get("nodeName"),"Selected node"):"Selected node";
        StringBuilder out=new StringBuilder("LedgerPreflight "+a.productVersion()+"\n────────────────────────────────────────\n\n"+node+"\nCorda "+a.sourceVersion()+" → "+a.targetVersion()+"\n\n"+(a.status().startsWith("READY ")?"✓ ":"✕ ")+state(a)+"\n");
        if(a.status().equals("READY FOR TVU"))return out+"\nStatic compatibility checks passed.\nNo blocking configuration problems were found.\n"+schemaSetup(a)+"\nNEXT STEP\nRun the Transaction Validator Utility before upgrading.\n";
        if(a.status().equals("READY TO UPGRADE"))return out+"\nStatic checks passed · CorDapps compatible · TVU passed\n"+schemaSetup(a)+"\nFollow your normal supported Corda upgrade procedure.\n";
        if(a.status().equals("UNKNOWN"))out.append("Readiness is unproven: some required evidence is incomplete.\n");
        if(a.status().equals("WARNING"))out.append("Required reviews remain before upgrading.\n");
        List<Issue> issues=issues(a);long blocking=issues.stream().filter(Issue::blocking).count();
        out.append("\n").append(blocking).append(blocking==1?" blocker":" blockers");
        long unresolved=issues.stream().filter(i->!i.blocking()&&!i.warning()).count();
        if(unresolved>0)out.append(" · ").append(unresolved).append(unresolved==1?" unresolved review":" unresolved reviews");
        else if(blocking==0&&!issues.isEmpty())out.append(" · ").append(issues.size()).append(issues.size()==1?" review required":" reviews required");
        out.append("\n");
        int ordinal=0,details=0;List<Issue> selected=new ArrayList<>();
        for(Issue issue:issues)if(!issue.warning())selected.add(issue);
        issues.stream().filter(Issue::warning).findFirst().ifPresent(selected::add);
        for(Issue issue:selected) {
            out.append("\n").append(issue.blocking()?(++ordinal)+". ":issue.warning()?"! ":"? ").append(issue.title()).append("\n");
            if(details++>=3){out.append("Details and recommended action are in the exported technical report.\n");continue;}
            out.append("WHAT HAPPENED  ").append(issue.summaryHappened()).append("\n");
            out.append("WHY IT MATTERS  ").append(issue.summaryMatters()).append("\n");
            out.append("WHAT TO DO  ").append(issue.summaryAction()).append("\n");
        }
        if(issues.size()>selected.size())out.append("\nAdditional issues are explained in the exported technical report.\n");
        GuidedFailure execution=guidedFailure(a);
        boolean executionExplained=execution!=null&&selected.stream().limit(3).anyMatch(i->i.title().equals("TVU validation"));
        if(!executionExplained)out.append(tvuOutcome(a));
        out.append(schemaSetup(a));
        out.append("\nNEXT STEP\n");
        boolean compatibility=issues.stream().anyMatch(i->i.title().equals("CorDapp compatibility")&&i.blocking());
        boolean schema=issues.stream().anyMatch(i->i.title().equals("Schema configuration")&&i.blocking());
        boolean tvu=issues.stream().anyMatch(i->i.title().equals("TVU validation")&&i.blocking());
        if(execution!=null&&issues.stream().allMatch(i->i.title().equals("TVU validation")))out.append(execution.action()).append("\n");
        else if(compatibility&&schema&&blocking==2&&unresolved==0&&!Boolean.TRUE.equals(a.evidence().get("tvu-evidence-supplied")))out.append("Resolve both blockers, then run TVU.\n");
        else if(compatibility&&schema&&tvu&&blocking==3&&unresolved==0)out.append("Resolve the CorDapp and schema blockers.\nThen rerun LedgerPreflight and TVU.\n");
        else if(compatibility&&tvu&&blocking==2&&unresolved==0)out.append("Resolve the compatibility blocker, then run TVU again.\n");
        else if(blocking>1)out.append("Resolve all ").append(blocking).append(" blockers").append(unresolved>0?" and complete the unresolved reviews":"").append(".\nThen rerun LedgerPreflight and TVU.\n");
        else if(compatibility)out.append("Resolve the CorDapp compatibility blocker").append(unresolved>0?" and complete the unresolved reviews":"").append(".\nThen rerun LedgerPreflight and TVU.\n");
        else if(blocking==1)out.append("Resolve the blocker").append(unresolved>0?" and complete the unresolved reviews":"").append(".\nThen rerun LedgerPreflight and TVU.\n");
        else if(issues.stream().anyMatch(i->i.title().equals("Compatibility analysis incomplete")))out.append("Complete compatibility analysis before upgrading.\n");
        else out.append("Resolve the outstanding reviews, then rerun LedgerPreflight and TVU.\n");
        return out.toString();
    }
    private ProductView(){}
}
