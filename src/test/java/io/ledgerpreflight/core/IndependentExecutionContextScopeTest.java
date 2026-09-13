package io.ledgerpreflight.core;

import io.ledgerpreflight.bytecode.BytecodeScanner.*;
import io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.Source;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import static org.junit.jupiter.api.Assertions.*;

/** Independent adversarial cases for historical verifier relevance, not lookup precedence. */
class IndependentExecutionContextScopeTest {
    private static ClassInfo type(String name,String parent,List<String> interfaces,String... calls){
        List<Reference> references=Arrays.stream(calls).map(owner->new Reference("run()V","METHOD",owner,"use","()V",Opcodes.INVOKESTATIC)).toList();
        return new ClassInfo(name,parent,interfaces,Opcodes.ACC_PUBLIC,52,List.of(),references);
    }
    private static JarInventory app(ClassInfo... classes){
        Map<String,ClassInfo> contents=new TreeMap<>();for(var c:classes)contents.put(c.name(),c);
        return new JarInventory("cordapps/mixed.jar","",Map.of(),contents,List.of());
    }
    private static Source source(String name){return new Source("cordapps/mixed.jar",name,"run()V","example/runtime/Api","use","()V","INVOKESTATIC");}

    @Test void sharedHelperDoesNotPullUnrelatedWorkflowSubclassIntoVerifier(){
        VerifierScope scope=VerifierScope.inspect(List.of(app(
            type("example/Agreement","java/lang/Object",List.of("net/corda/core/contracts/Contract"),"example/SharedHelper"),
            type("example/SharedHelper","java/lang/Object",List.of()),
            type("example/Workflow","example/SharedHelper",List.of(),"net/corda/core/flows/FlowLogic"))));
        assertTrue(scope.complete());assertTrue(scope.test(source("example/Agreement")));assertTrue(scope.test(source("example/SharedHelper")));
        assertFalse(scope.test(source("example/Workflow")),"A common helper superclass does not establish execution of its workflow subclass in the verifier");
    }

    @Test void helperInterfaceDoesNotPullUnrelatedWorkflowImplementationIntoVerifier(){
        VerifierScope scope=VerifierScope.inspect(List.of(app(
            type("example/Agreement","java/lang/Object",List.of("net/corda/core/contracts/Contract"),"example/Helper"),
            type("example/Helper","java/lang/Object",List.of()),
            type("example/Workflow","java/lang/Object",List.of("example/Helper"),"net/corda/core/flows/FlowLogic"))));
        assertTrue(scope.test(source("example/Agreement")));assertTrue(scope.test(source("example/Helper")));
        assertFalse(scope.test(source("example/Workflow")),"A helper reference alone does not prove every local implementation executes in historical verification");
    }

    @Test void indirectContractSubclassRemainsInVerifierScope(){
        VerifierScope scope=VerifierScope.inspect(List.of(app(
            type("example/BaseContract","java/lang/Object",List.of("net/corda/core/contracts/Contract")),
            type("example/Agreement","example/BaseContract",List.of(),"example/ActualHelper"),
            type("example/ActualHelper","java/lang/Object",List.of()))));
        assertTrue(scope.complete());assertTrue(scope.test(source("example/BaseContract")));assertTrue(scope.test(source("example/Agreement")));assertTrue(scope.test(source("example/ActualHelper")));
    }

    @Test void workflowUnconnectedToContractIsExcluded(){
        VerifierScope scope=VerifierScope.inspect(List.of(app(
            type("example/Agreement","java/lang/Object",List.of("net/corda/core/contracts/Contract")),
            type("example/Workflow","net/corda/core/flows/FlowLogic",List.of()))));
        assertTrue(scope.complete());assertTrue(scope.test(source("example/Agreement")));assertFalse(scope.test(source("example/Workflow")));
    }

    @Test void contractClosureIncludesHelperFromAnotherCurrentArtifact(){
        JarInventory one=app(type("example/Agreement","java/lang/Object",List.of("net/corda/core/contracts/Contract"),"example/ExternalHelper"));
        JarInventory two=new JarInventory("cordapps/shared.jar","",Map.of(),Map.of("example/ExternalHelper",type("example/ExternalHelper","java/lang/Object",List.of())),List.of());
        VerifierScope scope=VerifierScope.inspect(List.of(one,two));assertTrue(scope.complete());assertTrue(scope.test(source("example/ExternalHelper")));
    }
}
