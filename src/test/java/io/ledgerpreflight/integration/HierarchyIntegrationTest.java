package io.ledgerpreflight.integration;

import io.ledgerpreflight.bytecode.RequiredSymbolAnalyzer.*;
import io.ledgerpreflight.core.*;
import io.ledgerpreflight.evidence.TvuAnalyzer.TvuEvidence;
import io.ledgerpreflight.reporting.Reports;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Full discovery-to-report checks for original generated facade/member hierarchies. */
class HierarchyIntegrationTest {
    @TempDir Path root;
    private static Assessment assess(SyntheticFixtureFactory.Fixture fixture,boolean tvu)throws Exception{return new AssessmentService().assess(ProductAcceptanceFixture.options(fixture,tvu));}
    static SymbolResult helper(Assessment assessment)throws Exception{
        Object raw=assessment.evidence().get("required-symbol-resolution");
        for(var item:Reports.JSON.valueToTree(raw).path("symbols"))if(item.path("symbol").path("owner").asText().equals(HierarchyFixtureFactory.OWNER)&&item.path("symbol").path("member").asText().equals(HierarchyFixtureFactory.METHOD)&&item.path("symbol").path("kind").asText().equals("METHOD"))return Reports.JSON.treeToValue(item,SymbolResult.class);
        throw new AssertionError("Required inherited helper proof was not exported");
    }
    private static void compatible(Assessment assessment)throws Exception{
        SymbolResult proof=helper(assessment);assertEquals(Resolution.COMPATIBLE,proof.resolution(),Reports.JSON.writeValueAsString(proof));assertEquals(3,proof.contexts().size());
        for(var context:proof.contexts()){
            assertEquals(Resolution.COMPATIBLE,context.resolution());assertEquals("found",context.proof().classStatus());assertEquals("found",context.proof().memberStatus());
            assertEquals(context.context()==ExecutionContext.CURRENT_NODE_RUNTIME?HierarchyFixtureFactory.CURRENT_DECLARING:HierarchyFixtureFactory.TARGET_DECLARING,context.proof().declaringClass());
            assertTrue(context.proof().declaringArtifacts().stream().anyMatch(origin->origin.endsWith("/"+context.proof().declaringClass()+".class")));
            assertTrue(context.proof().declaringArtifacts().stream().anyMatch(origin->origin.contains("!/lib/generated-helpers.jar!/")));
            assertTrue(context.proof().artifacts().stream().noneMatch(origin->origin.contains("companion-tool.jar")));
        }
        assertEquals(Set.of(HierarchyFixtureFactory.SOURCE),proof.sources().stream().map(Source::sourceArtifact).collect(java.util.stream.Collectors.toSet()));
        assertTrue(Reports.JSON.valueToTree(assessment.evidence().get("required-symbol-resolution")).path("complete").asBoolean());
        assertFalse(assessment.findings().stream().anyMatch(f->f.category().equals("API_COMPATIBILITY")&&f.technicalEvidence().contains("owner: "+HierarchyFixtureFactory.OWNER)));
        assertFalse(ProductView.result(assessment).contains("Compatibility analysis incomplete"));
    }
    @Test void publicFacadeThroughNonPublicGeneratedLayersLinksInTheJvm()throws Exception{
        for(boolean target:List.of(false,true)){
            var definitions=HierarchyFixtureFactory.hierarchy(target,"compatible",target?24:16,false);definitions.put("org/example/oracle/Probe.class",HierarchyFixtureFactory.probe());
            ClassLoader loader=new ClassLoader(HierarchyIntegrationTest.class.getClassLoader()){
                @Override protected Class<?> findClass(String name)throws ClassNotFoundException{byte[] bytes=definitions.get(name.replace('.','/')+".class");if(bytes==null)throw new ClassNotFoundException(name);return defineClass(name,bytes,0,bytes.length);}
            };
            assertEquals(7,loader.loadClass("org.example.oracle.Probe").getMethod("call").invoke(null));
        }
    }
    @Test void differentCurrentAndTargetGeneratedHierarchiesResolveExactStaticMethod()throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,"compatible",false,false);Assessment assessment=assess(fixture,false);compatible(assessment);assertEquals("READY FOR TVU",assessment.status());
    }
    @Test void defaultBoundedLookupResolvesFacadeAcrossRepeatedArchiveFrontiers()throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,"compatible",true,true);Assessment assessment=assess(fixture,false);compatible(assessment);
        assertEquals("PARTIAL",((Map<?,?>)assessment.evidence().get("analysis-coverage")).get("status"));assertEquals("READY FOR TVU",assessment.status());
    }
    @ParameterizedTest @ValueSource(strings={"helper-missing","helper-descriptor"})
    void currentInheritedMemberDoesNotHideMissingOrChangedTargetAncestor(String mode)throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,mode,false,false);Assessment assessment=assess(fixture,false);SymbolResult proof=helper(assessment);
        assertEquals(mode.equals("helper-missing")?Resolution.MISSING_METHOD:Resolution.DESCRIPTOR_MISMATCH,proof.resolution());
        assertEquals("found",proof.current().memberStatus());assertEquals(HierarchyFixtureFactory.CURRENT_DECLARING,proof.current().declaringClass());
        assertEquals("found",proof.target().classStatus());assertEquals(mode.equals("helper-missing")?"absent":"descriptor-mismatch",proof.target().memberStatus());assertEquals("BLOCKED",assessment.status());
    }
    @ParameterizedTest @ValueSource(strings={"helper-cycle","helper-parent-missing"})
    void malformedOrMissingTargetHierarchyRemainsSafelyUnknown(String mode)throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,mode,false,false);Assessment assessment=assess(fixture,false);SymbolResult proof=helper(assessment);
        assertEquals(Resolution.UNKNOWN,proof.resolution());assertEquals("UNKNOWN",assessment.status());assertFalse(assessment.findings().stream().anyMatch(f->f.category().equals("API_COMPATIBILITY")&&f.severity().equals("BLOCKED")));
    }
    @Test void noTvuKeepsOnlyConfirmedCompatibilityIssueAndSchemaReview()throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,"blocked",true,true);Assessment assessment=assess(fixture,false);compatible(assessment);
        assertEquals("BLOCKED",assessment.status());assertEquals(List.of("CorDapp compatibility"),ProductView.issues(assessment).stream().map(ProductView.Issue::title).toList());assertEquals("AUTO_CONFIGURABLE",ProductView.schemaSetupStatus(assessment));
        assertEquals(1,assessment.findings().stream().filter(f->f.category().equals("API_COMPATIBILITY")&&f.severity().equals("BLOCKED")).count());
        SymbolResult removed=RequiredCompatibilityIntegrationTest.required(assessment);assertEquals(Resolution.MISSING_METHOD,removed.resolution());
        assertEquals("found",removed.current().memberStatus());assertEquals("absent",removed.target().memberStatus());
        assertEquals("absent",removed.contexts().stream().filter(c->c.context()==ExecutionContext.TARGET_VERIFIER).findFirst().orElseThrow().proof().memberStatus());
        String text=ProductView.result(assessment);assertTrue(text.contains("1 blocker"));assertFalse(text.contains("201"));assertFalse(text.contains("TVU validation"));
        assertEquals(Boolean.FALSE,assessment.evidence().get("tvu-evidence-supplied"));
    }
    @Test void all201TvuDetailsStillCorrelateWithoutInheritedHelperNoise()throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,"blocked",true,true);Assessment assessment=assess(fixture,true);compatible(assessment);
        assertEquals(List.of("CorDapp compatibility","TVU validation","Schema configuration"),ProductView.issues(assessment).stream().map(ProductView.Issue::title).toList());
        var tvu=(TvuEvidence)assessment.evidence().get("tvu-summary");assertEquals(650L,tvu.processed());assertEquals(449L,tvu.succeeded());assertEquals(201L,tvu.failed());assertEquals(201,tvu.detailedRecords());
        assertEquals("201 supplied failures match the compatibility problem.",ProductView.correlation(assessment,tvu));
        assertEquals(1,assessment.findings().stream().filter(f->f.id().equals("LP-TVU-002")).count());assertTrue(ProductView.result(assessment).contains("3 blockers"));
    }
    @Test void facadeProofExportRetainsReferencedOwnerAndActualDeclaration()throws Exception{
        var fixture=HierarchyFixtureFactory.create(root,"compatible",false,true);Assessment assessment=assess(fixture,false);compatible(assessment);
        var files=Reports.files(assessment);assertTrue(files.containsKey("required-symbol-resolution.json"));assertTrue(files.containsKey("execution-contexts.json"));
        String json=Reports.JSON.writeValueAsString(assessment.evidence().get("required-symbol-resolution"));
        for(String exact:List.of(HierarchyFixtureFactory.OWNER,HierarchyFixtureFactory.DESC,HierarchyFixtureFactory.CURRENT_DECLARING,HierarchyFixtureFactory.TARGET_DECLARING,"CURRENT_NODE_RUNTIME","TARGET_NODE_RUNTIME","TARGET_VERIFIER",HierarchyFixtureFactory.SOURCE))assertTrue(json.contains(exact),exact);
        assertFalse(json.contains(root.toString()));
        assertEquals("READY TO UPGRADE",assess(fixture,true).status());
    }
}
