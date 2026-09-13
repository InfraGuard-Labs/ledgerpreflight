package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.AssessmentService;
import io.ledgerpreflight.reporting.Reports;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.objectweb.asm.*;

/** Generic class-presence, inherited-method and schema-readiness acceptance fixtures. */
public final class BlockerVerifierFixtureFactory {
    public static final String CLASS_OWNER="org/example/runtime/OrdinaryType";
    public static final String CLASS_ENTRY=CLASS_OWNER+".class",VERIFIER="tools/external-verifier.jar",DUPLICATE="lib/ordinary-copy.jar";
    private BlockerVerifierFixtureFactory(){}
    public static SyntheticFixtureFactory.Fixture create(Path root,String mode,boolean partial)throws Exception{
        if(!Set.of("blocked","configured","compatible","unknown","absent").contains(mode))throw new IllegalArgumentException("Unknown synthetic fixture mode");
        boolean missing=Set.of("blocked","configured").contains(mode),proven=!mode.equals("blocked");
        var f=HierarchyFixtureFactory.create(root,missing?"blocked":"compatible",false,partial);
        byte[] ordinary=SyntheticFixtureFactory.emptyClass(CLASS_OWNER);
        RunARegressionTest.update(f.node().resolve("corda.jar"),Map.of(CLASS_ENTRY,ordinary),false);
        Path target=f.kit().resolve("renamed-runtime.bin");byte[] verifierBytes;
        try(ZipFile zip=new ZipFile(target.toFile());InputStream in=zip.getInputStream(zip.getEntry(VERIFIER))){verifierBytes=in.readAllBytes();}
        Map<String,byte[]> verifier=entries(verifierBytes);
        if(!mode.equals("absent")){
            verifier.put(CLASS_ENTRY,mode.equals("unknown")?new byte[]{0,1,2}:ordinary);
            if(!mode.equals("unknown"))verifier.put(DUPLICATE,archive(Map.of(CLASS_ENTRY,ordinary)));
        }
        RunARegressionTest.update(target,Map.of(CLASS_ENTRY,ordinary,VERIFIER,archive(verifier)),false);
        Map<String,byte[]> callers=new TreeMap<>();Path app=f.node().resolve(HierarchyFixtureFactory.SOURCE);
        try(ZipFile zip=new ZipFile(app.toFile())){
            for(var all=zip.entries();all.hasMoreElements();){ZipEntry entry=all.nextElement();if(!entry.getName().endsWith(".class"))continue;
                byte[] input;try(InputStream in=zip.getInputStream(entry)){input=in.readAllBytes();}
                ClassWriter writer=new ClassWriter(0);new ClassReader(input).accept(new ClassVisitor(Opcodes.ASM9,writer){
                    @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
                        MethodVisitor delegate=super.visitMethod(access,name,descriptor,signature,exceptions);
                        if(!name.equals("verify"))return delegate;
                        return new MethodVisitor(Opcodes.ASM9,delegate){@Override public void visitCode(){super.visitCode();super.visitLdcInsn(Type.getObjectType(CLASS_OWNER));super.visitInsn(Opcodes.POP);}};
                    }
                },0);callers.put(entry.getName(),writer.toByteArray());
            }
        }
        RunARegressionTest.update(app,callers,false);
        String schema=proven?"\"\\\"ExampleSchema\\\"\"":"\"ExampleSchema\"";
        Files.writeString(f.node().resolve("node.conf"),"myLegalName=\"CN=ExampleIssuer,O=Example Company,L=London,C=GB\"\ndatabase.schema="+schema+"\ndataSource.url=\"jdbc:postgresql://database.example/example?currentSchema=ExampleSchema\"\n");
        if(Set.of("configured","compatible").contains(mode))Files.writeString(f.log(),"HHH000205: Loaded properties from resource hibernate.properties: {hibernate.default_schema=\"ExampleSchema\"}\n",StandardOpenOption.APPEND);
        return f;
    }
    private static Map<String,byte[]> entries(byte[] bytes)throws IOException{
        Map<String,byte[]> entries=new TreeMap<>();try(ZipInputStream zip=new ZipInputStream(new ByteArrayInputStream(bytes))){for(ZipEntry e;(e=zip.getNextEntry())!=null;)if(!e.isDirectory())entries.put(e.getName(),zip.readAllBytes());}return entries;
    }
    private static byte[] archive(Map<String,byte[]> entries)throws IOException{
        var bytes=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(bytes)){for(var e:new TreeMap<>(entries).entrySet()){ZipEntry entry=new ZipEntry(e.getKey());entry.setTime(0);zip.putNextEntry(entry);zip.write(e.getValue());zip.closeEntry();}}return bytes.toByteArray();
    }
    public static void generate(Path root)throws Exception{
        for(String mode:List.of("blocked","configured","compatible","unknown")){
            var fixture=create(root.resolve(mode),mode,true);var service=new AssessmentService();
            Reports.write(root.resolve(mode+"-asserted"),Reports.files(service.assess(ProductAcceptanceFixture.options(fixture,false))));
            if(mode.equals("blocked")||mode.equals("compatible"))Reports.write(root.resolve(mode+"-tvu-asserted"),Reports.files(service.assess(ProductAcceptanceFixture.options(fixture,true))));
        }
    }
    public static void main(String[] args)throws Exception{if(args.length!=1)throw new IllegalArgumentException("Supply a workspace fixture directory");generate(Path.of(args[0]));}
}
