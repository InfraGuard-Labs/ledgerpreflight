package io.ledgerpreflight.core;
import io.ledgerpreflight.bytecode.BytecodeScanner.JarInventory;
import io.ledgerpreflight.evidence.SafeInputs;
import java.nio.file.Path;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
public final class ClasspathEvidence {
    /** Explicit launch evidence bound to supplied component identities, never archive entry order. */
    public record Ordering(List<String> components,Map<String,String> selectedClassSources,List<String> observations) {
        public Ordering {components=List.copyOf(components);selectedClassSources=Map.copyOf(selectedClassSources);observations=List.copyOf(observations);}
        public boolean runtimePrecedesLegacy(List<JarInventory> runtime,List<JarInventory> legacy) {
            int pairs=0;
            for(var r:runtime)for(var l:legacy)for(String owner:r.classes().keySet())if(l.classes().containsKey(owner)){
                pairs++;int ri=rank(r.path()),li=rank(l.path());
                if(ri<0||li<0||ri>=li)return false;
                String selected=selectedClassSources.get(owner);
                if(selected!=null&&(selected.isEmpty()||!within(r.path(),selected)))return false;
            }
            return pairs>0;
        }
        private int rank(String origin){int found=-1;for(int i=0;i<components.size();i++)if(within(origin,components.get(i))){if(found>=0)return -1;found=i;}return found;}
    }
    public static Ordering bind(Path file,Collection<String> suppliedComponents)throws IOException {
        if(file==null)return new Ordering(List.of(),Map.of(),List.of("No verifier classpath evidence supplied"));
        String raw=new String(SafeInputs.read(file,1024*1024),StandardCharsets.UTF_8);
        List<String> labels=suppliedComponents.stream().distinct().sorted().toList();
        if(labels.size()>512)throw new IOException("Supplied component binding limit reached");
        Map<String,String> sources=new TreeMap<>();
        Matcher loaded=Pattern.compile("(?m)(?:^|\\s)([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*){1,100})\\s+source:\\s*([^\\r\\n]+)").matcher(raw);
        while(loaded.find()){
            String owner=loaded.group(1).replace('.','/'),source=bindOne(loaded.group(2).strip(),labels);
            String prior=sources.putIfAbsent(owner,source);if(prior!=null&&!prior.equals(source))sources.put(owner,"");
            if(sources.size()>4096)throw new IOException("Supplied class-load evidence limit reached");
        }
        Matcher cp=Pattern.compile("(?:^|\\s)(?:-cp|-classpath|--class-path)\\s+(?:\"([^\"]+)\"|'([^']+)'|(\\S+))").matcher(raw);
        if(!cp.find())return new Ordering(List.of(),sources,List.of("No single explicit classpath; only uniquely bound class-load evidence can select duplicates"));
        String value=cp.group(1)!=null?cp.group(1):cp.group(2)!=null?cp.group(2):cp.group(3);
        if(cp.find()){sources.replaceAll((owner,source)->"");return new Ordering(List.of(),sources,List.of("Multiple Java classpaths supplied; ordering and class-load origins cannot be attributed to one execution"));}
        List<String> order=new ArrayList<>();
        for(String entry:value.split(value.contains(";")?";":":",-1)){
            String label=bindOne(entry,labels);
            if(label.isEmpty()||order.contains(label)||order.size()>=256)return new Ordering(List.of(),sources,List.of("Classpath contains an unresolved, repeated, or ambiguous component; no order was inferred"));
            order.add(label);
        }
        return new Ordering(order,sources,List.of("User-supplied launch order bound uniquely to supplied component identities"));
    }
    private static boolean within(String origin,String component){return origin.equals(component)||origin.startsWith(component+"!/");}
    private static String bindOne(String value,List<String> labels){
        String path=value.replace('\\','/').replaceFirst("^jar:","").replaceFirst("^file:","");
        while(path.startsWith("./"))path=path.substring(2);
        if(path.endsWith("!/"))path=path.substring(0,path.length()-2);
        if(path.isBlank()||path.length()>2048||path.contains("*")||path.contains("?")||path.matches(".*(?:^|/)\\.\\.(?:/|$).*"))return "";
        String normalized=path;
        List<String> exact=labels.stream().filter(label->normalized.equals(label)||normalized.endsWith("/"+label)).toList();
        if(exact.size()==1)return exact.get(0);if(!exact.isEmpty())return "";
        List<String> nested=labels.stream().filter(label->label.contains("!/")&&(label.substring(label.lastIndexOf("!/")+2).equals(normalized)||normalized.endsWith("/"+label.substring(label.lastIndexOf("!/")+2))||normalized.equals(label.substring(label.lastIndexOf('/')+1)))).toList();
        return nested.size()==1?nested.get(0):"";
    }
    public record Result(boolean runtimePrecedenceProven,String confidence,List<String> entries,List<String> observations,Map<String,String> selectedClassSources) {
        public Result(boolean proven,String confidence,List<String> entries,List<String> observations){this(proven,confidence,entries,observations,Map.of());}
    }
    public static Result read(Path file,List<JarInventory> runtime,List<JarInventory> legacy)throws IOException {
        if(file==null)return new Result(false,"POTENTIAL",List.of(),List.of("No verifier classpath evidence supplied"));
        String raw=new String(SafeInputs.read(file,1024*1024),StandardCharsets.UTF_8);
        Map<String,String> sources=new TreeMap<>();boolean conflictingSources=false;
        Matcher loaded=Pattern.compile("(?m)(?:^|\\s)([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*){1,100})\\s+source:\\s*([^\\r\\n]+)").matcher(raw);
        while(loaded.find()) {String location=loaded.group(2).strip().replace('\\','/').replaceFirst("^file:","");String prior=sources.putIfAbsent(loaded.group(1),location);if(prior!=null&&!prior.equals(location))conflictingSources=true;}
        Matcher match=Pattern.compile("(?:^|\\s)(?:-cp|-classpath|--class-path)\\s+(?:\"([^\"]+)\"|'([^']+)'|(\\S+))").matcher(raw);
        if(!match.find())return new Result(false,"POTENTIAL",List.of(),List.of("No unambiguous Java classpath argument found"),sources);
        String cp=match.group(1)!=null?match.group(1):match.group(2)!=null?match.group(2):match.group(3);
        if(match.find())return new Result(false,"POTENTIAL",List.of(),List.of("Multiple Java command lines: classpath order is ambiguous"),sources);
        List<String> entries=Arrays.stream(cp.split(cp.contains(";")?";":":")).map(s->s.replace('\\','/')).toList();
        boolean proven=!runtime.isEmpty()&&!legacy.isEmpty()&&!conflictingSources,allLoaded=true;int pairs=0;
        for(JarInventory r:runtime)for(JarInventory l:legacy)for(String name:r.classes().keySet())if(l.classes().containsKey(name)) {
            pairs++;int ri=index(entries,r.path()),li=index(entries,l.path());
            if(ri<0 || li<0 || ri>=li)proven=false;
            String selected=sources.get(name.replace('/','.'));
            if(selected==null)allLoaded=false;else if(!matches(selected,r.path())){proven=false;allLoaded=false;}
        }
        proven&=pairs>0;
        return new Result(proven,proven?(allLoaded?"CONFIRMED":"HIGH"):"POTENTIAL",entries,List.of(proven?"Supplied command orders every overlapping runtime artifact before the corresponding legacy artifact; command provenance is user supplied":"Exact ordering/selection of all overlapping runtime and legacy artifacts was not established"),Collections.unmodifiableMap(sources));
    }
    private static boolean matches(String entry,String path){String normalized=path.replace('\\','/').split("!/",2)[0];return entry.equals(normalized)||entry.endsWith("/"+normalized);}
    private static int index(List<String> entries,String path){int found=-1;for(int i=0;i<entries.size();i++)if(matches(entries.get(i),path)){if(found>=0)return -1;found=i;}return found;}
}
