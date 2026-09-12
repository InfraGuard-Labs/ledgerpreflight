package io.ledgerpreflight.evidence;

import com.typesafe.config.*;
import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/** Only relative local includes beneath the explicitly selected configuration root. */
final class SafeHocon {
    private final Path root;private final Set<Path> active=new HashSet<>();
    private final Map<String,String> environment=new HashMap<>();private final Set<Path> parsed=new TreeSet<>();private int files,bytes;
    private SafeHocon(Path root){this.root=root;}
    record Parsed(Config config,List<String> includes){}
    static Parsed read(Path path,Path permittedRoot)throws IOException {
        Path real=path.toRealPath(),boundary=permittedRoot.toRealPath();if(!real.startsWith(boundary))throw new IOException("Configuration is outside the permitted root");SafeHocon reader=new SafeHocon(boundary);
        try{Config config=reader.parse(real).withFallback(ConfigFactory.parseMap(reader.environment)).resolve(ConfigResolveOptions.noSystem().setUseSystemEnvironment(false).setAllowUnresolved(true));return new Parsed(config,reader.parsed.stream().filter(p->!p.equals(real)).map(p->real.getParent().relativize(p).toString()).toList());}
        catch(ConfigException|IllegalArgumentException e){throw new IOException("Malformed, unresolved or unsafe HOCON input");}
    }
    private Config parse(Path path)throws IOException {
        Path real=path.toRealPath();
        if(!real.startsWith(root)||!active.add(real)||active.size()>16||++files>32)throw new IOException("Configuration include boundary, cycle or count limit exceeded");
        try{
            parsed.add(real);
            String raw=new String(SafeInputs.read(real,1024*1024),StandardCharsets.UTF_8);bytes+=raw.length();
            if(bytes>2*1024*1024||raw.chars().filter(c->c=='{'||c=='[').count()>256)throw new IOException("HOCON complexity limit exceeded");
            int depth=0;boolean quoted=false,escaped=false;
            for(char c:raw.toCharArray()){if(escaped){escaped=false;continue;}if(c=='\\'&&quoted){escaped=true;continue;}if(c=='\"')quoted=!quoted;if(!quoted&&(c=='{'||c=='[')&&++depth>64)throw new IOException("HOCON nesting limit exceeded");if(!quoted&&(c=='}'||c==']'))depth=Math.max(0,depth-1);}
            Matcher refs=Pattern.compile("\\$\\{\\??([A-Za-z_][A-Za-z0-9_]*)}").matcher(raw);
            while(refs.find()){String name=refs.group(1);if(Sanitizer.isSensitiveKey(name))continue;String value=System.getenv(name);if(value!=null&&value.length()<=4096)environment.put(name,value);}
            return ConfigFactory.parseString(raw,ConfigParseOptions.defaults().setOriginDescription(root.relativize(real).toString()).setIncluder(new Includes(real.getParent())));
        }finally{active.remove(real);}
    }
    private final class Includes implements ConfigIncluder,ConfigIncluderFile,ConfigIncluderURL,ConfigIncluderClasspath {
        private final Path base;Includes(Path base){this.base=base;}
        public ConfigIncluder withFallback(ConfigIncluder fallback){return this;}
        private ConfigObject local(String name){
            try{Path relative=Path.of(name);if(relative.isAbsolute())throw new IOException("Absolute includes are not permitted");Path path=base.resolve(relative).normalize();
                if(!Files.exists(path)&&!name.endsWith(".conf"))path=base.resolve(name+".conf").normalize();
                return parse(path).root();
            }catch(IOException e){throw new IllegalArgumentException("Unsafe or unavailable relative HOCON include");}
        }
        public ConfigObject include(ConfigIncludeContext c,String name){return local(name);}
        public ConfigObject includeFile(ConfigIncludeContext c,File file){return local(file.toString());}
        public ConfigObject includeURL(ConfigIncludeContext c,URL url){throw new IllegalArgumentException("Network includes are disabled");}
        public ConfigObject includeResources(ConfigIncludeContext c,String name){throw new IllegalArgumentException("Classpath includes are disabled");}
    }
}
