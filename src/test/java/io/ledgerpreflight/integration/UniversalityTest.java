package io.ledgerpreflight.integration;

import io.ledgerpreflight.core.*;
import io.ledgerpreflight.bytecode.*;
import io.ledgerpreflight.evidence.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class UniversalityTest {
    @TempDir Path root;
    Path config(String text)throws IOException{return Files.writeString(root.resolve("node.conf"),text);}
    @ParameterizedTest @ValueSource(strings={"usr/local/corda/node","opt/company/ledger/node","srv/apps/corda/issuer","data/with spaces/custom"})
    void arbitraryLayouts(String layout)throws Exception{
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Path node=root.resolve(layout);Files.createDirectories(node.getParent());Files.move(f.node(),node);
        var o=new AssessmentService.Options(node,f.kit(),null,null,null,null,null,List.of(),null,null);
        assertEquals("READY FOR TVU",new AssessmentService().assess(o).status());
    }
    @Test void explicitSymlinkedRootIsAssessable()throws Exception{
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Path link=Files.createSymbolicLink(root.resolve("linked"),f.node());
        assertEquals(1,NodeDiscovery.discover(link).nodes().size());assertFalse(new BytecodeScanner().scan(link).jars().isEmpty());
    }
    @Test void internalSymlinkDirectoryIsDiscoveredAndEscapeIsSkipped()throws Exception{
        var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.createSymbolicLink(f.node().resolve("internal"),f.node());Files.createSymbolicLink(f.node().resolve("external"),f.kit());
        var scan=new BytecodeScanner().scan(f.node());assertEquals(1,scan.jars().size());assertTrue(scan.issues().stream().anyMatch(i->i.message().contains("outside")));
    }
    @Test void multipleNodesRemainSeparateAndNoninteractiveDoesNotSelectOne()throws Exception{
        var a=SyntheticFixtureFactory.create(root.resolve("one"),false);var b=SyntheticFixtureFactory.create(root.resolve("two"),false);
        Files.writeString(b.node().resolve("node.conf"),"database.schema=another\nnotary.validating=false\n");
        var result=NodeDiscovery.discover(root);assertEquals(2,result.nodes().size());assertTrue(result.nodes().stream().anyMatch(n->n.notaryMode().equals("Non-validating")));
        var options=new AssessmentService.Options(root,a.kit(),null,null,null,null,null,List.of(),null,null);
        assertEquals("UNKNOWN",new AssessmentService().assess(options).status());
        assertNotEquals(new ConfigAnalyzer().analyze(a.node().resolve("node.conf")).schema(),new ConfigAnalyzer().analyze(b.node().resolve("node.conf")).schema());
    }
    @ParameterizedTest @ValueSource(strings={"true","false"})
    void notaryModeComesFromConfiguration(String value)throws Exception{
        var c=new ConfigAnalyzer().analyze(config("notary.validating="+value));assertEquals("Notary",c.safeSettings().get("nodeType"));assertEquals("CONFIRMED",c.safeSettings().get("notaryModeConfidence"));assertEquals(value.equals("true")?"Validating":"Non-validating",c.safeSettings().get("notaryMode"));
    }
    @Test void regularNodeBusinessRoleRemainsUnknown()throws Exception{var c=new ConfigAnalyzer().analyze(config("myLegalName=\"O=Issuer,L=London,C=GB\""));assertEquals("Corda node",c.safeSettings().get("nodeType"));assertEquals("Unknown",c.safeSettings().get("businessRole"));}
    @Test void unresolvedNotaryDoesNotBecomeRegularNode()throws Exception{var c=new ConfigAnalyzer().analyze(config("notary=${LP_MISSING_NOTARY_91}"));assertEquals("Unknown",c.safeSettings().get("nodeType"));assertEquals("UNKNOWN",c.safeSettings().get("nodeTypeConfidence"));}
    @ParameterizedTest @ValueSource(strings={"hibernate.default_schema","database.hibernate.default_schema","\"hibernate.default_schema\""})
    void unresolvedSchemaAliasesPreventEffectiveSchemaClaim(String alias)throws Exception{var c=new ConfigAnalyzer().analyze(config("database.schema=public\n"+alias+"=${LP_MISSING_SCHEMA_91}"));assertEquals("Unknown",c.safeSettings().get("effectiveSchema"));assertEquals("UNKNOWN",c.safeSettings().get("schemaConfidence"));}
    @Test void sharedParentRuntimeDoesNotMergeChildNodes()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("shared"),false);Path a=Files.createDirectory(f.root().resolve("A")),b=Files.createDirectory(f.root().resolve("B"));Files.move(f.node().resolve("node.conf"),a.resolve("node.conf"));Files.writeString(b.resolve("node.conf"),"database.schema=second");Files.move(f.node().resolve("corda.jar"),f.root().resolve("shared-runtime.jar"));Files.delete(f.node());assertEquals(2,NodeDiscovery.discover(f.root()).nodes().size());}
    @Test void includedIdentityIsNotASecondNodeConfiguration()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.writeString(f.node().resolve("identity.conf"),"myLegalName=\"O=Example,L=London,C=GB\"");Files.writeString(f.node().resolve("node.conf"),"include \"identity.conf\"\n",StandardOpenOption.APPEND);assertEquals(1,NodeDiscovery.discover(f.node()).nodes().get(0).configs().size());}
    @Test void relativeParentIncludeWithinSelectedNodeIsSafe()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.createDirectory(f.node().resolve("config"));Files.move(f.node().resolve("node.conf"),f.node().resolve("db.conf"));Files.writeString(f.node().resolve("config/node.conf"),"include \"../db.conf\"");assertEquals("READY FOR TVU",new AssessmentService().assess(f.options(false)).status());}
    @Test void safeRelativeIncludeAndLocalSubstitutionResolve()throws Exception{Files.writeString(root.resolve("db.conf"),"localSchema=public\ndatabase.schema=${localSchema}\n");var c=new ConfigAnalyzer().analyze(config("include \"db.conf\""));assertEquals("public",c.schema());}
    @Test void referencedEnvironmentVariableResolvesWithoutSerializingEnvironment()throws Exception{var c=new ConfigAnalyzer().analyze(config("myLegalName=${LP_DISCOVERY_TEST_IDENTITY}\ndatabase.schema=public"));assertEquals("Example Company",c.safeSettings().get("myLegalName"));assertFalse(c.toString().contains("PATH="));}
    @Test void credentialEnvironmentVariablesAreNotReadIntoPublicSignals()throws Exception{var c=new ConfigAnalyzer().analyze(config("database.schema=${LP_DISCOVERY_SECRET}\n"));assertNull(c.schema());assertFalse(c.toString().contains("CredentialFixture91"));assertEquals("UNKNOWN",c.safeSettings().get("schemaConfidence"));}
    @Test void unresolvedSchemaIsUnknownRatherThanInvented()throws Exception{var c=new ConfigAnalyzer().analyze(config("database.schema=${LP_NONEXISTENT_SCHEMA_91}"));assertNull(c.schema());assertTrue(c.issues().stream().anyMatch(i->i.startsWith("Unresolved")));}
    @Test void multipleCandidateConfigsAreVisible()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.writeString(f.node().resolve("other.conf"),"myLegalName=\"O=Other,L=London,C=GB\"\n");assertEquals(2,NodeDiscovery.discover(f.node()).nodes().get(0).configs().size());assertTrue(new AssessmentService().assess(f.options(false)).findings().stream().anyMatch(x->x.id().equals("LP-CONFIG-002")));}
    @Test void renamedConfigIsDiscovered()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.move(f.node().resolve("node.conf"),f.node().resolve("company.hocon"));assertEquals("READY FOR TVU",new AssessmentService().assess(f.options(false)).status());}
    @ParameterizedTest @ValueSource(strings={"database.schema=public","database.schema=lowercase","database.schema=MixedCase","database.url=\"jdbc:postgresql://db/db?currentSchema=issuer\"","connectionInitSql=\"SET search_path TO issuer,public\""})
    void independentSchemaSourcesAreRetained(String text)throws Exception{var c=new ConfigAnalyzer().analyze(config(text));assertEquals("CONFIGURED",c.safeSettings().get("schemaResolution"));assertEquals("MEDIUM",c.safeSettings().get("schemaConfidence"));}
    @Test void unspecifiedDefaultIsNotAssumedPublic()throws Exception{var c=new ConfigAnalyzer().analyze(config("database.url=\"jdbc:postgresql://db/db\""));assertEquals("DEFAULT_UNVERIFIED",c.safeSettings().get("schemaResolution"));assertEquals("UNKNOWN",c.safeSettings().get("schemaConfidence"));}
    @Test void matchingSchemaDeclarationsHaveHighConfidence()throws Exception{var c=new ConfigAnalyzer().analyze(config("database.schema=issuer\ndatabase.url=\"jdbc:postgresql://db/db?currentSchema=issuer\""));assertFalse(c.contradictory());assertEquals("HIGH",c.safeSettings().get("schemaConfidence"));}
    @Test void jdbcAndSearchPathConflictWithoutDatabaseSchema()throws Exception{var c=new ConfigAnalyzer().analyze(config("database.url=\"jdbc:postgresql://db/db?currentSchema=issuer\"\nconnectionInitSql=\"SET search_path TO other\""));assertTrue(c.contradictory());assertEquals("Ambiguous",c.safeSettings().get("effectiveSchema"));}
    @ParameterizedTest @ValueSource(strings={"postgresql","oracle","sqlserver","unrecognized"})
    void vendorSpecificFindingsStayRelevant(String vendor)throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.writeString(f.node().resolve("node.conf"),"database.schema=MixedCase\ndatabase.url=\"jdbc:"+vendor+"://db/db\"\n");var a=new AssessmentService().assess(f.options(false));assertEquals(vendor.equals("postgresql"),a.findings().stream().anyMatch(x->x.id().equals("LP-DB-001")));assertEquals(vendor.equals("postgresql")?"REQUIRED_UNPROVEN":"NOT_APPLICABLE",ProductView.schemaSetupStatus(a));}
    @Test void renamedCorDappsAndRuntimeMetadataAreDiscovered()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),true);Files.createDirectories(f.node().resolve("applications"));Files.move(f.node().resolve("cordapps/contracts.jar"),f.node().resolve("applications/arbitrary.jar"));Files.move(f.kit().resolve("cordapps/contracts.jar"),f.kit().resolve("changed-name.jar"));Files.move(f.kit().resolve("corda.jar"),f.kit().resolve("runtime-unrelated-name.jar"));Files.move(f.kit().resolve("transaction-validator.jar"),f.kit().resolve("tool.jar"));var a=new AssessmentService().assess(f.options(false));assertEquals("4.12.11",a.targetVersion());assertFalse(a.findings().stream().anyMatch(x->x.id().equals("LP-CORDAPP-005")||x.id().equals("LP-DISCOVERY-002")));}
    @Test void classContentMatchesWithoutCustomerFilename()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);var source=new BytecodeScanner().scan(f.node()).jars().get(0);var target=new BytecodeScanner().scan(f.kit().resolve("corda.jar")).jars();assertEquals(1,NodeDiscovery.matches(source,target).size());}
    @Test void ambiguousRuntimeAndTvuAreReported()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);Files.copy(f.kit().resolve("corda.jar"),f.kit().resolve("other.jar"));Files.copy(f.kit().resolve("transaction-validator.jar"),f.kit().resolve("second-tool.jar"));var a=new AssessmentService().assess(f.options(false));assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-DISCOVERY-006")));assertTrue(a.findings().stream().anyMatch(x->x.id().equals("LP-DISCOVERY-007")));}
    @Test void optionalFoldersAreNotRequired()throws Exception{var f=SyntheticFixtureFactory.create(root.resolve("fixture"),false);assertFalse(Files.exists(f.node().resolve("cordapps")));assertEquals("READY FOR TVU",new AssessmentService().assess(f.options(false)).status());}
    @Test void includeCycleFailsClosed()throws Exception{Files.writeString(root.resolve("a.conf"),"include \"node.conf\"");assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(config("include \"a.conf\"")));}
    @Test void relativeIncludeEscapeFailsClosed()throws Exception{Path sub=Files.createDirectory(root.resolve("sub"));Files.writeString(root.resolve("outside.conf"),"database.schema=private");Files.writeString(sub.resolve("node.conf"),"include \"../outside.conf\"");assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(sub.resolve("node.conf")));}
    @Test void symlinkIncludeEscapeFailsClosed()throws Exception{Path sub=Files.createDirectory(root.resolve("sub"));Path outside=Files.writeString(root.resolve("outside.conf"),"database.schema=private");Files.createSymbolicLink(sub.resolve("db.conf"),outside);Files.writeString(sub.resolve("node.conf"),"include \"db.conf\"");assertThrows(IOException.class,()->new ConfigAnalyzer().analyze(sub.resolve("node.conf")));}
}
