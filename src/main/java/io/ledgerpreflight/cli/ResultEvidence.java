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
        var issue=ProductView.issues(a).stream().filter(i->i.title().equals("CorDapp compatibility")).findFirst();
        List<String> artifacts=findings.stream().filter(f->!f.category().equals("LEGACY_JARS")).map(f->field(f,"jar").isEmpty()?f.affectedArtifact():field(f,"jar")).map(ResultEvidence::filename).filter(s->!s.isBlank()).distinct().limit(3).toList();
        List<String> missing=findings.stream().filter(f->f.id().equals("LP-API-001")).map(ResultEvidence::api).filter(s->!s.isEmpty()).distinct().limit(3).toList();
        boolean absent=findings.stream().anyMatch(f->f.id().equals("LP-API-001")&&f.severity().equals("BLOCKED")&&field(f,"requiredMember").equals("absent"));
        StringBuilder out=new StringBuilder("COMPATIBILITY EVIDENCE\n\nAffected CorDapp\n"+(artifacts.isEmpty()?"Supplied application or dependency":String.join("\n",artifacts)));
        out.append("\n\nProblem\n").append(issue.map(ProductView.Issue::happened).orElse("Compatibility requires review."));
        if(!missing.isEmpty())out.append(absent?"\n\nMissing API\n":"\n\nAPI requiring review\n").append(String.join("\n",missing));
        out.append("\n\nImpact\n").append(issue.map(ProductView.Issue::matters).orElse("Historical transactions may fail re-verification."));
        out.append("\n\nTarget\nCorda ").append(a.targetVersion()).append("\n\nRecommended action\n").append(issue.map(ProductView.Issue::action).orElse("Review the exported report and validate again."));
        return out.toString();
    }
    static String schema(Assessment a){
        Map<String,Object> settings=a.evidence().get("schema-analysis") instanceof ConfigEvidence c?c.safeSettings():Map.of();
        var issue=ProductView.issues(a).stream().filter(i->i.title().equals("Schema configuration")).findFirst();
        String primary=Objects.toString(settings.get("effectiveSchema"),"Not established");
        StringBuilder out=new StringBuilder("SCHEMA EVIDENCE\n\nDatabase\n"+settings.getOrDefault("databaseVendor","Not established")+"\n\nPrimary / effective schema\n"+primary);
        if(settings.get("additionalSchemas") instanceof List<?> schemas){
            List<String> additional=schemas.stream().map(Object::toString).filter(s->!s.equals(primary)).limit(4).toList();
            if(!additional.isEmpty())out.append("\n\nAdditional configured schemas\n").append(String.join("\n",additional));
        }
        out.append("\n\nWhat LedgerPreflight found\n").append(issue.map(ProductView.Issue::happened).orElse("The effective schema needs confirmation."));
        out.append("\n\nWhy this matters\n").append(issue.map(ProductView.Issue::matters).orElse("Node and TVU must use the intended schema."));
        out.append("\n\nRecommended action\n").append(issue.map(ProductView.Issue::action).orElse("Confirm the intended schema before TVU validation."));
        return out.toString();
    }
    static String tvu(Assessment a){
        if(!(a.evidence().get("tvu-summary") instanceof TvuEvidence t))return "TVU EVIDENCE\n\nComplete TVU results could not be established.\n\nRecommended action\nReview the exported report and supply one complete TVU run.";
        String correlation=ProductView.correlation(a,t);
        String root,action;
        if(t.completeSuccess()){root="The supplied run reports complete successful verification.";action="Confirm this run covers the intended artifacts and database snapshot, then follow the supported upgrade procedure.";}
        else if(!correlation.isEmpty()){root=correlation;action="Resolve the compatibility issue and rerun complete TVU.";}
        else if(t.schemaValidationFailure()){root="TVU reported a schema-validation failure. This does not establish that the physical table is absent.";action="Confirm the intended TVU schema and rerun validation.";}
        else {root="The supplied evidence does not establish a confirmed compatibility root cause.";action="Review the exported failure evidence and supply one complete TVU run.";}
        return "TVU EVIDENCE\n\nTransactions processed   "+Objects.toString(t.processed(),"Not established")+"\nPassed                   "+Objects.toString(t.succeeded(),"Not established")+"\nFailed                   "+Objects.toString(t.failed(),"Not established")+"\n\nRoot cause\n"+root+"\n\nRecommended action\n"+action;
    }
    private static String field(Finding f,String key){return f.technicalEvidence().stream().filter(s->s.startsWith(key+": ")).map(s->s.substring(key.length()+2)).findFirst().orElse("");}
    private static String filename(String path){String p=path.replace('\\','/').split("!/",2)[0];return p.substring(p.lastIndexOf('/')+1);}
    private static String api(Finding f){
        String owner=field(f,"owner"),member=field(f,"member"),descriptor=field(f,"descriptor");
        if(owner.isEmpty()||member.isEmpty())return "";
        if(!descriptor.startsWith("("))return owner.replace('/' ,'.')+"."+member;
        try{
            String arguments=String.join(", ",Arrays.stream(org.objectweb.asm.Type.getArgumentTypes(descriptor)).map(org.objectweb.asm.Type::getClassName).map(s->s.substring(s.lastIndexOf('.')+1)).toList());
            return owner.replace('/','.')+"."+member+"("+arguments+")";
        }catch(IllegalArgumentException e){return owner.replace('/','.')+"."+member+"(...)";}
    }
}
