package io.ledgerpreflight.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.jar.Attributes;

/** Read only main attributes. Signed per-entry sections and unrelated capsule lists are discarded. */
public final class ManifestMetadata {
    private ManifestMetadata(){}
    private static boolean relevant(String name){return Set.of("corda-release-version","corda-version","corda-platform-version","corda-vendor","corda-opencore-version","corda-revision","cordapp-contract-name","cordapp-contract-version","cordapp-contract-vendor","cordapp-workflow-name","cordapp-workflow-version","cordapp-workflow-vendor","manifest-version","main-class","application-class","application-id","application-version","start-class","min-java-version","implementation-version","implementation-vendor","bundle-version","multi-release","min-platform-version","target-platform-version","platform-version").contains(name.toLowerCase(Locale.ROOT));}
    public static Map<String,String> read(InputStream input)throws IOException {
        Map<String,String> result=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        ByteArrayOutputStream value=new ByteArrayOutputStream();String key=null;boolean keep=false;long total=0;
        BufferedInputStream in=new BufferedInputStream(input,8192);
        while(true){
            ByteArrayOutputStream line=new ByteArrayOutputStream();int c;
            while((c=in.read())!=-1&&c!='\n'){if(++total>8L*1024*1024||line.size()>=65536)throw new IOException("Manifest main-attribute limit reached");line.write(c);}
            byte[] bytes=line.toByteArray();int length=bytes.length;if(length>0&&bytes[length-1]=='\r')length--;
            if(length>0&&bytes[0]==' '){if(key==null)throw new IOException("Manifest continuation without an attribute");if(keep)value.write(bytes,1,length-1);}
            else {
                if(keep)put(result,key,value);value.reset();
                if(length==0)break;
                int colon=0;while(colon<length&&bytes[colon]!=':')colon++;
                if(colon==length||colon+1>=length||bytes[colon+1]!=' ')throw new IOException("Invalid manifest attribute");
                key=new String(bytes,0,colon,StandardCharsets.US_ASCII);
                try{new Attributes.Name(key);}catch(IllegalArgumentException e){throw new IOException("Invalid manifest attribute name");}
                keep=relevant(key);if(keep)value.write(bytes,colon+2,length-colon-2);
            }
            if(value.size()>16384)throw new IOException("Manifest identity attribute exceeds limit");
            if(c==-1){if(keep)put(result,key,value);break;}
        }
        return result;
    }
    private static void put(Map<String,String> map,String key,ByteArrayOutputStream value)throws IOException {
        String text=value.toString(StandardCharsets.UTF_8);String prior=map.putIfAbsent(key,text);
        if(prior!=null&&!prior.equals(text))throw new IOException("Conflicting main manifest attribute: "+key);
        if(map.values().stream().mapToInt(String::length).sum()>65536)throw new IOException("Retained manifest identity limit reached");
    }
}
