package io.ledgerpreflight.core;

import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import java.util.*;

/** The short product answer; complete evidence remains in the assessment record. */
public final class ProductView {
    public record Issue(String title,String happened,String matters,String action,boolean warning,List<String> findingIds){}
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
                    if(a.evidence().get("tvu-summary") instanceof TvuEvidence t && t.failed()!=null&&t.failed()>0) {
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
            result.add(new Issue(group.getKey(),happened,matters,action,warning,fs.stream().map(Finding::id).distinct().toList()));
        }
        result.sort(Comparator.comparing(Issue::warning).thenComparingInt(i->switch(i.title()){case "CorDapp compatibility"->0;case "TVU validation"->1;case "Schema configuration"->2;case "Compatibility analysis incomplete"->3;default->4;}));
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
    public static String result(Assessment a) {
        Object env=a.evidence().get("environment");String node=env instanceof Map<?,?> map?Objects.toString(map.get("nodeName"),"Selected node"):"Selected node";
        StringBuilder out=new StringBuilder("LedgerPreflight "+a.productVersion()+"\n────────────────────────────────────────\n\n"+node+"\nCorda "+a.sourceVersion()+" → "+a.targetVersion()+"\n\n"+(a.status().startsWith("READY ")?"✓ ":"✕ ")+state(a)+"\n");
        if(a.status().equals("READY FOR TVU"))return out+"\nStatic compatibility checks passed.\nNo blocking configuration problems were found.\n\nNEXT STEP\nRun the Transaction Validator Utility before upgrading.\n";
        if(a.status().equals("READY TO UPGRADE"))return out+"\nStatic checks passed · CorDapps compatible · TVU passed\n\nFollow your normal supported Corda upgrade procedure.\n";
        if(a.status().equals("UNKNOWN"))out.append("Readiness is unproven: some required evidence is incomplete.\n");
        if(a.status().equals("WARNING"))out.append("Required reviews remain before upgrading.\n");
        List<Issue> issues=issues(a);long blocking=issues.stream().filter(i->!i.warning()).count();
        out.append("\n").append(blocking==0?issues.size()+(issues.size()==1?" review needs attention":" reviews need attention"):blocking+(blocking==1?" issue needs attention":" issues need attention"));
        out.append("\n");
        int shown=0,ordinal=0;List<Issue> selected=new ArrayList<>();
        for(Issue issue:issues)if(!issue.warning()&&shown++<2)selected.add(issue);
        issues.stream().filter(Issue::warning).findFirst().ifPresent(selected::add);
        for(Issue issue:selected) {
            out.append("\n").append(issue.warning()?"! ":(++ordinal)+". ").append(issue.title()).append("\n");
            out.append("WHAT HAPPENED  ").append(issue.happened()).append("\n");
            out.append("WHY IT MATTERS  ").append(issue.matters()).append("\n");
            out.append("WHAT TO DO  ").append(issue.action()).append("\n");
        }
        if(issues.size()>selected.size())out.append("\nAdditional issues are explained in the exported technical report.\n");
        out.append("\nNEXT STEP\n");
        out.append(issues.stream().anyMatch(i->i.title().equals("CorDapp compatibility")&&!i.warning())?"Resolve the CorDapp compatibility issue first.\nThen rerun LedgerPreflight and TVU.\n":issues.stream().anyMatch(i->i.title().equals("Compatibility analysis incomplete"))?"Complete compatibility analysis before upgrading.\n":"Resolve the outstanding reviews, then rerun LedgerPreflight and TVU.\n");
        return out.toString();
    }
    private ProductView(){}
}
