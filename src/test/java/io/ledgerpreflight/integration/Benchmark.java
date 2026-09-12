package io.ledgerpreflight.integration;

import io.ledgerpreflight.bytecode.BytecodeScanner;
import java.nio.file.*;
import java.util.*;

/** Measured in the invoking Docker container; not a vendor-runtime benchmark. */
public final class Benchmark {
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Supply a workspace benchmark output directory");Path root=Path.of(args[0]);Files.createDirectories(root);StringBuilder result=new StringBuilder("jars,classes,references,elapsed_ms,heap_used_bytes\n");
        for(int count:new int[]{10,100,500}){
            Path input=root.resolve("jars-"+count);Files.createDirectories(input);
            for(int i=0;i<count;i++){Map<String,byte[]> classes=new TreeMap<>();for(int c=0;c<20;c++){String name="synthetic/b"+i+"/Class"+c;classes.put(name+".class",SyntheticFixtureFactory.emptyClass(name));}SyntheticFixtureFactory.writeZip(input.resolve(String.format(Locale.ROOT,"library-%04d.jar",i)),classes);}
            long start=System.nanoTime();var scan=new BytecodeScanner().scan(input);long elapsed=System.nanoTime()-start;if(!scan.issues().isEmpty()||scan.jars().size()!=count)throw new IllegalStateException("Benchmark incomplete: "+scan.issues());
            long classes=scan.jars().stream().mapToLong(j->j.classes().size()).sum(),references=scan.jars().stream().flatMap(j->j.classes().values().stream()).mapToLong(c->c.references().size()).sum();long heap=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();result.append(count).append(',').append(classes).append(',').append(references).append(',').append(String.format(Locale.ROOT,"%.3f",elapsed/1_000_000.0)).append(',').append(heap).append('\n');
        }
        Files.writeString(root.resolve("benchmark.csv"),result);System.out.print(result);
    }
}
