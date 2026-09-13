package io.ledgerpreflight.core;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/** A node/kit has semantic boundaries: root artifacts and direct children of canonical directories. */
public final class ArtifactLayout {
    private ArtifactLayout(){}
    public record Inputs(Path root,List<Path> files,List<String> issues){}
    public static Inputs inspect(Path supplied)throws IOException {
        Path root=supplied.toRealPath();List<Path> files=new ArrayList<>();List<String> issues=new ArrayList<>();
        if(Files.isRegularFile(root))return new Inputs(root,List.of(root),List.of());
        collect(root,root,files,issues,true);
        files.sort(Comparator.comparing(Path::toString));return new Inputs(root,List.copyOf(files),List.copyOf(issues));
    }
    private static void collect(Path root,Path dir,List<Path> files,List<String> issues,boolean top)throws IOException {
        try(var entries=Files.newDirectoryStream(dir)){int count=0;for(Path p:entries){
            if(++count>10000)throw new IOException("Physical artifact directory entry limit reached");
            Path real;try{real=p.toRealPath();}catch(IOException e){issues.add("Unreadable artifact entry: "+root.relativize(p));continue;}
            if(!real.startsWith(root)){issues.add("Symbolic link outside supplied root skipped: "+root.relativize(p));continue;}
            if(Files.isRegularFile(real)&&ArtifactDiscovery.isArchive(real)){if(files.size()>=256)throw new IOException("Physical artifact count limit reached");files.add(p);}
            else if(top&&Files.isDirectory(real)&&Set.of("cordapps","drivers","legacy-jars","legacy-contracts").contains(p.getFileName().toString()))collect(root,p,files,issues,false);
        }}
    }
}
