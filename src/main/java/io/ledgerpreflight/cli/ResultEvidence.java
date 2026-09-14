package io.ledgerpreflight.cli;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.ConfigAnalyzer.ConfigEvidence;
import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import java.util.*;

/** Short explanations of the current findings; raw diagnostic data belongs in exported reports. */
final class ResultEvidence {
    private static final Set<String> COMPATIBILITY=Set.of("API_COMPATIBILITY","INTERNAL_API","LEGACY_JARS","CORDAPP","SIGNING");
    private static boolean attention(Finding f){return Set.of("BLOCKED","ERROR","UNKNOWN","WARNING").contains(f.severity());}
    static boolean hasCompatibility(Assessment a){return a.findings().stream().anyMatch(f->attention(f)&&COMPATIBILITY.contains(f.category()));}
    static boolean hasSchema(Assessment a){return a.findings().stream().anyMatch(f->attention(f)&&f.category().equals("DATABASE_SCHEMA"));}
    static boolean hasTvu(Assessment a){
        if(Boolean.TRUE.equals(a.evidence().get("tvu-evidence-supplied")))return true;
        return a.evidence().get("tvu-summary") instanceof TvuEvidence t&&(t.processed()!=null||t.failed()!=null||t.detailedRecords()>0||!t.rootCauses().isEmpty());
    }
    static String compatibility(Assessment a){
        List<Finding> findings=a.findings().stream().filter(f->attention(f)&&COMPATIBILITY.contains(f.category())).sorted().toList();
        var issue=ProductView.issues(a).stream().filter(i->i.title().equals("CorDapp compatibility")||i.title().equals("Target CorDapp mapping")).findFirst();
        List<Finding> referenced=findings.stream().filter(f->f.category().equals("API_COMPATIBILITY")&&!api(f).isEmpty()).toList();
        List<Finding> confirmed=referenced.stream().filter(f->f.severity().equals("BLOCKED")).toList();
        List<String> artifacts=(!confirmed.isEmpty()?confirmed:referenced.isEmpty()?findings:referenced).stream().flatMap(f->sourceArtifacts(f).stream()).map(ResultEvidence::filename).distinct().limit(3).toList();
        Map<String,Finding> roots=new LinkedHashMap<>();
        for(Finding f:referenced)roots.putIfAbsent(kind(f)+"\n"+field(f,"owner")+"\n"+field(f,"member")+"\n"+field(f,"descriptor"),f);
        StringBuilder out=new StringBuilder("COMPATIBILITY EVIDENCE\n\nAffected CorDapp\n"+(artifacts.isEmpty()?"Source artifact not established":String.join("\n",artifacts)));
        int shown=0;
        for(Finding root:roots.values()){
            if(shown++==3)break;
            out.append("\n\nReferenced API\n").append(api(root));
            String classes=field(root,"referencedClasses");
            if(classes.matches("[0-9]{1,9}")&&Integer.parseInt(classes)>1)out.append("\nReferenced by ").append(classes).append(" source classes");
            out.append("\n\nCurrent runtime · Corda ").append(a.sourceVersion()).append("\n").append(proof(root,"current"));
            out.append("\n\nTarget runtime · Corda ").append(a.targetVersion()).append("\n").append(proof(root,"target"));
            if(!field(root,"verifierClass").isEmpty())out.append("\n\nTarget verifier · Corda ").append(a.targetVersion()).append("\n").append(proof(root,"verifier"));
        }
        if(roots.isEmpty())out.append("\n\nProblem\n").append(issue.map(ProductView.Issue::happened).orElse("Compatibility requires review."));
        else if(roots.size()>3)out.append("\n\nAdditional API evidence is available in the exported technical report.");
        if(confirmed.isEmpty()&&findings.stream().anyMatch(f->f.id().equals("LP-CORDAPP-005")))out.append("\n\nTarget CorDapp replacements\nSome current CorDapps could not be matched to target replacements.").append(roots.isEmpty()?"":" Runtime API compatibility was checked independently.");
        if(!confirmed.isEmpty()&&findings.stream().anyMatch(f->f.severity().equals("UNKNOWN")))out.append("\n\nAdditional compatibility analysis is incomplete.\nThe confirmed incompatibility still needs resolution.");
        out.append("\n\nImpact\n").append(issue.map(ProductView.Issue::matters).orElse("Historical transactions may fail re-verification."));
        out.append("\n\nRecommended action\n").append(issue.map(ProductView.Issue::action).orElse("Review the exported report and validate again."));
        return out.toString();
    }
    /** Artifact names require positive source-bytecode provenance, never a grouping label. */
    private static List<String> sourceArtifacts(Finding f){
        if(f.category().equals("LEGACY_JARS"))return List.of();
        if(field(f,"sourceScope").equals("active-current-cordapp")&&!field(f,"sourceClass").isBlank())return f.technicalEvidence().stream()
            .filter(s->s.matches("sourceArtifact(?:\\.[0-9]+)?: .+"))
            .map(s->s.substring(s.indexOf(": ")+2)).filter(ResultEvidence::physicalArtifact).toList();
        String jar=field(f,"jar");
        return jar.startsWith("current/historical/")&&physicalArtifact(jar)?List.of(jar):List.of();
    }
    private static boolean physicalArtifact(String path){
        String normalized=path.replace('\\','/');
        return !normalized.startsWith("target/")&&!normalized.startsWith("runtime/")&&!normalized.startsWith("/")
            &&!normalized.contains("../")&&!filename(normalized).isBlank()&&!Set.of("assessment","runtime","report","report.html","report.json","summary.txt").contains(filename(normalized).toLowerCase(Locale.ROOT));
    }
    private static String proof(Finding f,String side){
        String classState=field(f,side+"Class"),memberState=field(f,side+"Member");
        if(side.equals("target")&&memberState.isEmpty())memberState=field(f,"requiredMember");
        String found=switch(classState){case "found","present"->"Class found";case "absent"->"Class missing";default->"Class lookup incomplete";};
        String kind=kind(f);
        if(kind.equals("CLASS")||field(f,"member").isEmpty())return found;
        String label=kind.equals("FIELD")?"Field":"Method";
        String member=switch(memberState){case "found","present"->label+" found";case "absent"->label+" missing";case "descriptor-mismatch"->label+" signature changed";default->label+" lookup incomplete";};
        String resolution=side.equals("target")?(field(f,"targetResolution").isEmpty()?field(f,"resolution"):field(f,"targetResolution")):side.equals("verifier")?field(f,"verifierResolution"):"";
        String linkage=switch(resolution){
            case "invocation-mismatch"->"\nInvocation is incompatible with this CorDapp.";
            case "access-incompatible"->"\nMember is not accessible from this CorDapp.";
            default->"";
        };
        return found+" · "+member+linkage;
    }
    private static String kind(Finding f){String kind=field(f,"kind");return kind.isEmpty()?field(f,"referenceType"):kind;}
    static String schema(Assessment a){
        Map<String,Object> settings=a.evidence().get("schema-analysis") instanceof ConfigEvidence c?c.safeSettings():Map.of();
        var issue=ProductView.issues(a).stream().filter(i->i.title().equals("Schema configuration")).findFirst();
        String primary=Objects.toString(settings.get("effectiveSchema"),"Not established");
        StringBuilder out=new StringBuilder("SCHEMA EVIDENCE\n\nDatabase\n"+settings.getOrDefault("databaseVendor","Not established")+"\n\nPrimary / effective schema\n"+primary);
        if(settings.get("additionalSchemas") instanceof List<?> schemas){
            List<String> additional=schemas.stream().map(Object::toString).filter(s->!s.equals(primary)).limit(4).toList();
            if(!additional.isEmpty())out.append("\n\nAdditional configured schemas\n").append(String.join("\n",additional));
        }
        String setup=ProductView.schemaSetupStatus(a);boolean handled=setup.equals("HANDLED"),configured=setup.equals("CONFIGURATION_PROVEN");
        out.append("\n\nWhat LedgerPreflight found\n").append(issue.map(ProductView.Issue::happened).orElse(handled?"The supplied TVU run loaded the intended schema.":configured?"The selected configuration explicitly names the intended schema.":"The effective schema needs confirmation."));
        out.append("\n\nWhy this matters\n").append(issue.map(ProductView.Issue::matters).orElse(handled?"The required TVU schema configuration is established for the supplied run.":configured?"Static configuration is established; actual TVU schema loading still needs validation.":"Node and TVU must use the intended schema."));
        out.append("\n\nRecommended action\n").append(issue.map(ProductView.Issue::action).orElse(handled?"Resolve any remaining validation blockers before upgrading.":"Confirm the intended schema using the official Corda TVU procedure, then import the resulting logs and error bundle."));
        return out.toString();
    }
    static String tvu(Assessment a){
        if(!(a.evidence().get("tvu-summary") instanceof TvuEvidence t))return "TVU EVIDENCE\n\nComplete TVU results could not be established.\n\nRecommended action\nReview the exported report and supply one complete TVU run.";
        String correlation=ProductView.correlation(a,t);
        String root,action;
        if(t.completeSuccess()){root="The supplied run reports complete successful verification.";action=a.status().equals("READY TO UPGRADE")?"Confirm this run covers the intended artifacts and database snapshot, then follow the supported upgrade procedure.":"Confirm this run covers the intended artifacts and database snapshot. Resolve the remaining assessment issues before upgrading.";}
        else if(!correlation.isEmpty()){root=correlation;action="Resolve the compatibility issue, rerun complete TVU separately, then import the new results.";}
        else if(t.schemaValidationFailure()){root="TVU reported a schema-validation failure. This does not establish that the physical table is absent.";action="Confirm the intended TVU schema, rerun validation separately, then import the new results.";}
        else {root="The supplied evidence does not establish a confirmed compatibility root cause.";action="Review the exported failure evidence and supply one complete TVU run.";}
        return "TVU EVIDENCE\n\nTransactions processed   "+Objects.toString(t.processed(),"Not established")+"\nPassed                   "+Objects.toString(t.succeeded(),"Not established")+"\nFailed                   "+Objects.toString(t.failed(),"Not established")+"\n\nRoot cause\n"+root+"\n\nRecommended action\n"+action;
    }
    private static String field(Finding f,String key){return f.technicalEvidence().stream().filter(s->s.startsWith(key+": ")).map(s->s.substring(key.length()+2)).findFirst().orElse("");}
    private static String filename(String path){String p=path.replace('\\','/').split("!/",2)[0];return p.substring(p.lastIndexOf('/')+1);}
    private static String api(Finding f){
        String owner=field(f,"owner"),member=field(f,"member"),descriptor=field(f,"descriptor");
        if(owner.isEmpty())return "";
        if(member.isEmpty())return owner.replace('/','.');
        if(!descriptor.startsWith("("))return owner.replace('/','.')+"."+member;
        try{
            String arguments=String.join(", ",Arrays.stream(org.objectweb.asm.Type.getArgumentTypes(descriptor)).map(org.objectweb.asm.Type::getClassName).map(s->s.substring(s.lastIndexOf('.')+1)).toList());
            return owner.replace('/','.')+"."+member+"("+arguments+")";
        }catch(IllegalArgumentException e){return owner.replace('/','.')+"."+member+"(...)";}
    }
}
