package io.ledgerpreflight.core;
import io.ledgerpreflight.bytecode.BytecodeScanner.JarInventory;
import io.ledgerpreflight.evidence.SafeInputs;
import java.nio.file.Path;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
public final class ClasspathEvidence {
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
