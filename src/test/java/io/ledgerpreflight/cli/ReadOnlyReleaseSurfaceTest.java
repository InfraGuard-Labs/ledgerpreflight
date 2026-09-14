package io.ledgerpreflight.cli;

import io.ledgerpreflight.evidence.FileHashes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.objectweb.asm.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Release boundary: existing evidence can be analyzed; no validator can be launched. */
class ReadOnlyReleaseSurfaceTest {
    @TempDir Path root;
    private static final List<String> REMOVED=List.of("--run-tvu","--confirm-isolated-db","--tvu-node-conf","--tvu-schema");

    @ParameterizedTest
    @ValueSource(strings={"--run-tvu","--confirm-isolated-db","--tvu-node-conf","--tvu-schema","--run-tvu=true","--confirm-isolated-db=true","--tvu-node-conf=/unreadable/node.conf","--tvu-schema=ExampleSchema"})
    void obsoleteExecutionFlagIsRejectedBeforeReadingInputs(String flag) {
        StringWriter out=new StringWriter(),err=new StringWriter();Path output=root.resolve("not-created");
        int code=Main.command().setOut(new PrintWriter(out)).setErr(new PrintWriter(err)).execute(
            "assess","--node",root.resolve("missing-node").toString(),"--upgrade-kit",root.resolve("missing-kit").toString(),
            "--output",output.toString(),"--json",flag);
        assertEquals(2,code);assertEquals("",out.toString());assertFalse(Files.exists(output));
        assertTrue(err.toString().contains("v0.1.0 does not run TVU"));
        assertTrue(err.toString().contains("--tvu-results"));
        assertTrue(err.toString().contains("No assessment inputs were read"));
        assertFalse(err.toString().contains("Assessment error"));
    }

    @Test void executionOptionsAreAbsentFromTheParserAndPublicHelp() {
        var command=Main.command();var assess=command.getSubcommands().get("assess");
        for(String name:REMOVED){
            assertFalse(assess.getCommandSpec().optionsMap().containsKey(name),name);
            assertFalse(assess.getUsageMessage().contains(name),name);
        }
        assertTrue(command.getUsageMessage().contains("does not run TVU"));
        assertTrue(assess.getCommandSpec().optionsMap().containsKey("--tvu-results"));
        assertTrue(command.getSubcommands().containsKey("analyze-tvu"));
    }

    @Test void releaseClassesContainNoValidatorOrVerifierProcessLauncher()throws Exception {
        ClassLoader loader=Main.class.getClassLoader();
        for(String name:List.of("GuidedTvuExecution","GuidedTvuCapture","TvuProcessTree","TvuExecution"))
            assertNull(loader.getResource("io/ledgerpreflight/cli/"+name+".class"),name);
        Path classes=Path.of(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        assertTrue(Files.isDirectory(classes),"Check all compiled production classes before packaging");
        Set<String> processCallers=new TreeSet<>();int[] inspected={0};
        try(var paths=Files.walk(classes.resolve("io/ledgerpreflight"))){
            for(Path path:paths.filter(p->p.toString().endsWith(".class")).toList()){
                inspected[0]++;
                try(InputStream input=Files.newInputStream(path)){
                    new ClassReader(input).accept(new ClassVisitor(Opcodes.ASM9){
                        private String type;
                        @Override public void visit(int v,int access,String name,String signature,String parent,String[] interfaces){type=name;}
                        @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
                            return new MethodVisitor(Opcodes.ASM9){
                                @Override public void visitMethodInsn(int opcode,String owner,String method,String desc,boolean itf){
                                    if((owner.equals("java/lang/ProcessBuilder")&&Set.of("start","startPipeline").contains(method))
                                        ||(owner.equals("java/lang/Runtime")&&method.equals("exec")))processCallers.add(type);
                                }
                            };
                        }
                    },ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
                }
            }
        }
        assertTrue(inspected[0]>30,"Inspect the full production class set");
        assertEquals(Set.of("io/ledgerpreflight/cli/SessionTerminal"),processCallers,
            "Only the fixed /bin/stty terminal adapter may start a subprocess");
    }

    @Test void supportChecksumUtilityHandlesMultipleChunksAndRejectsSymlinks()throws Exception {
        byte[] bytes="Synthetic evidence\n".repeat(12000).getBytes(StandardCharsets.UTF_8);
        Path artifact=root.resolve("evidence.bin");Files.write(artifact,bytes);
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),FileHashes.sha256(artifact));
        Path link=Files.createSymbolicLink(root.resolve("linked-evidence"),artifact);
        assertThrows(IOException.class,()->FileHashes.sha256(link));
        assertThrows(IOException.class,()->FileHashes.sha256(root));
    }
}
