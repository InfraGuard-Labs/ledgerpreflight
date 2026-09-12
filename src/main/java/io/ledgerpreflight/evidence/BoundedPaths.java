package io.ledgerpreflight.evidence;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/** An explicitly supplied root authorizes its canonical destination, not adjacent trees. */
public final class BoundedPaths {
    private BoundedPaths(){}
    public record Tree(Path root,List<Path> files,List<String> issues){}
    public static Tree discover(Path supplied,int maxDepth,int maxFiles)throws IOException {
        Path root=supplied.toRealPath();
        if(root.getParent()==null)throw new IOException("Supply a node or kit directory, not the filesystem root");
        List<Path> files=new ArrayList<>();List<String> issues=new ArrayList<>();Set<Path> visited=new HashSet<>();
        record Item(Path path,int depth){}
        Deque<Item> pending=new ArrayDeque<>();pending.add(new Item(root,0));int count=0;
        while(!pending.isEmpty()){
            Item item=pending.removeFirst();Path logical=item.path(),real;
            if(++count>maxFiles)throw new IOException("Discovery entry limit exceeded");
            try{real=logical.toRealPath();}catch(IOException e){issues.add("Unreadable discovery entry: "+root.relativize(logical));continue;}
            if(!real.startsWith(root)){issues.add("Symbolic link outside supplied root skipped: "+root.relativize(logical));continue;}
            if(Files.isDirectory(real)){
                if(!visited.add(real))continue;
                if(item.depth()>=maxDepth){issues.add("Discovery depth limit reached: "+root.relativize(logical));continue;}
                List<Path> children=new ArrayList<>();
                try(var entries=Files.newDirectoryStream(logical)){for(Path p:entries){if(count+pending.size()+children.size()>=maxFiles)throw new IOException("Discovery entry limit exceeded");children.add(p);}}
                children.sort(Comparator.comparing(Path::toString));for(Path p:children)pending.addLast(new Item(p,item.depth()+1));
            }else if(Files.isRegularFile(real))files.add(logical);
        }
        files.sort(Comparator.comparing(Path::toString));return new Tree(root,List.copyOf(files),List.copyOf(issues));
    }
}
