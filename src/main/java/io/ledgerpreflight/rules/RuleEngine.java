package io.ledgerpreflight.rules;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.*;
import static io.ledgerpreflight.rules.RuleDefinition.Condition;

/** Fail-closed, deterministic, additive rules. Vendor facts are scoped to the 4.12 family. */
public final class RuleEngine {
    public static final String PACK_VERSION = "2026.09.12";
    private static final String BASE = "https://docs.r3.com/en/platform/corda/4.12/enterprise/";
    private static final String GUIDE = BASE + "upgrade-guide.html";
    private static final String RELEASE = BASE + "release-notes-enterprise.html";
    public static final Set<String> FACTS = Set.of("source.version", "target.version", "target.java",
        "target.kotlin", "target.platform", "tvu.present", "network.mode", "legacyContracts.present",
        "constraints.hashDetected", "constraints.explicitUpgradeDetected", "verification.legacyPattern",
        "cordapps.recompiled", "signing.continuity", "contract.versionIncreased", "cordapps.minimumPlatform",
        "legacyDependencies.required", "legacyJars.present", "tvu.schemaVersion");
    private final List<RuleDefinition> rules;

    public RuleEngine() { this(builtins()); }
    private RuleEngine(List<RuleDefinition> rules) {
        this.rules = rules.stream().sorted(Comparator.comparing(RuleDefinition::id)).toList();
    }
    public List<RuleDefinition> catalog() { return rules; }
    public Optional<RuleDefinition> explain(String id) {
        return rules.stream().filter(rule -> rule.id().equals(id)).findFirst();
    }

    public List<RuleFinding> evaluate(Map<String, String> facts) {
        Objects.requireNonNull(facts, "facts");
        List<RuleFinding> out = new ArrayList<>();
        for (RuleDefinition rule : rules) {
            if (!rule.conditions().stream().allMatch(condition -> matches(condition, facts))) continue;
            List<String> evidence = rule.conditions().stream().map(c -> c.fact() + "=" +
                facts.getOrDefault(c.fact(), "UNKNOWN")).distinct().sorted().toList();
            out.add(new RuleFinding(rule.id(), rule.title(), rule.severity(), rule.category(),
                status(rule.severity()), rule.confidence(), rule.source(), "upgrade-kit", evidence,
                rule.impact(), rule.explanation(), rule.nextAction(), rule.documentationReference()));
        }
        return List.copyOf(out);
    }

    /** Load a pack without replacing or downgrading the built-in rules. */
    public RuleEngine load(Path path) throws IOException {
        for(Path parent=path.toAbsolutePath().normalize();parent!=null;parent=parent.getParent())if(Files.isSymbolicLink(parent))throw new IOException("Rule pack path must not contain symbolic links");
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Rule pack must be a regular non-symlink file");
        if (Files.size(path) > 1_048_576) throw new IOException("Rule pack exceeds 1 MiB limit");
        ObjectMapper mapper = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16)
                .maxStringLength(8192).maxNumberLength(20).build()).build())
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        RulePack pack;
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] data = in.readNBytes(1_048_577);
            if (data.length > 1_048_576) throw new IOException("Rule pack exceeds 1 MiB limit");
            pack = mapper.readValue(data, RulePack.class);
        } catch (IOException | RuntimeException e) { throw new IOException("Invalid declarative rule pack; check bounded JSON syntax and schema"); }
        if (pack == null || !"1".equals(pack.schemaVersion()) || pack.version() == null ||
            pack.version().isBlank() || pack.version().length() > 100 || pack.rules() == null || pack.rules().size() > 100)
            throw new IOException("Rule pack requires schemaVersion 1, version and at most 100 rules");
        List<RuleDefinition> combined = new ArrayList<>(rules);
        Set<String> ids = new HashSet<>();
        rules.forEach(r -> ids.add(r.id()));
        for (RuleDefinition r : pack.rules()) {
            validate(r);
            if (!ids.add(r.id())) throw new IOException("Duplicate rule ID: " + r.id());
            combined.add(r);
        }
        return new RuleEngine(combined);
    }
    public record RulePack(String schemaVersion, String version, List<RuleDefinition> rules) {}

    private static void validate(RuleDefinition r) throws IOException {
        if (r == null || r.id() == null || !r.id().matches("USR-[A-Z0-9-]{1,60}"))
            throw new IOException("User rule IDs must start USR- and use uppercase letters, digits or hyphens");
        if (!Set.of("WARNING", "BLOCKED", "INFO", "UNKNOWN").contains(orEmpty(r.severity())) ||
            !Set.of("USER_RULE", "VENDOR_CONFIRMED_LOCAL").contains(orEmpty(r.source())) ||
            !Set.of("CONFIRMED", "HIGH", "MEDIUM", "LOW", "POTENTIAL").contains(orEmpty(r.confidence())))
            throw new IOException("Invalid user rule severity, source or confidence");
        for (String text : Arrays.asList(r.title(), r.category(), r.impact(), r.explanation(), r.nextAction()))
            if (text == null || text.isBlank() || text.length() > 8192)
                throw new IOException("Rule text fields must be nonempty and at most 8192 characters");
        if (r.conditions() == null || r.conditions().isEmpty() || r.conditions().size() > 20)
            throw new IOException("Rule requires 1 to 20 conditions");
        for (Condition c : r.conditions()) {
            if (c == null || !FACTS.contains(orEmpty(c.fact())) ||
                !Set.of("EQUALS", "NOT_EQUALS", "PRESENT", "ABSENT", "VERSION_FAMILY").contains(orEmpty(c.operator())) ||
                c.value() == null || c.value().length() > 1024)
                throw new IOException("Invalid rule condition or unknown fact");
        }
    }
    private static String orEmpty(String s) { return s == null ? "" : s; }
    private static String status(String severity) {
        return switch (severity) { case "BLOCKED" -> "FAIL"; case "WARNING" -> "WARN";
            case "UNKNOWN" -> "UNKNOWN"; default -> "INFO"; };
    }
    private static boolean known(String value) {
        return value != null && !value.isBlank() && !value.equalsIgnoreCase("UNKNOWN");
    }
    private static boolean matches(Condition c, Map<String, String> facts) {
        String value = facts.get(c.fact());
        return switch (c.operator()) {
            case "ABSENT" -> !known(value);
            case "PRESENT" -> known(value);
            case "EQUALS" -> known(value) && value.equals(c.value());
            case "NOT_EQUALS" -> known(value) && !value.equals(c.value());
            case "VERSION_FAMILY" -> family(value).equals(c.value());
            case "NOT_VERSION_FAMILY" -> known(value) && !family(value).equals(c.value());
            case "VERSION_BELOW_411" -> known(value) && olderThan411(value);
            default -> false;
        };
    }
    public static String family(String version) {
        if (version == null || !version.matches("[0-9]{1,3}\\.[0-9]{1,3}(?:\\.[0-9]{1,6})?(?:[-+][A-Za-z0-9.-]+)?")) return "";
        String[] parts = version.split("[.\\-+]");
        return Integer.parseInt(parts[0]) + "." + Integer.parseInt(parts[1]);
    }
    private static boolean olderThan411(String version) {
        String f = family(version);
        if (f.isEmpty()) return false;
        String[] p = f.split("\\."); int major = Integer.parseInt(p[0]), minor = Integer.parseInt(p[1]);
        return major < 4 || major == 4 && minor < 11;
    }
    private static Condition c(String fact, String operator, String value) { return new Condition(fact, operator, value); }
    private static RuleDefinition rule(String id, String title, String severity, String category, String explanation,
        String action, String reference, Condition... conditions) {
        String source = id.matches("LP-UPGRADE-00[2-5]") ? "HEURISTIC" : "OFFICIAL_DOC";
        return new RuleDefinition(id, title, severity, category, "HIGH", source, title,
            explanation, action, reference, List.of(conditions));
    }
    private static List<RuleDefinition> builtins() {
        Condition target = c("target.version", "VERSION_FAMILY", "4.12");
        List<RuleDefinition> r = new ArrayList<>();
        r.add(rule("LP-UPGRADE-001", "Direct upgrade requires Corda 4.11", "BLOCKED", "UPGRADE_PATH",
            "The documented direct path to 4.12 starts at 4.11. Earlier nodes first require the 4.11 upgrade procedure.",
            "Reach Corda 4.11 using the relevant official guide, then reassess.", GUIDE, target, c("source.version", "VERSION_BELOW_411", "")));
        r.add(rule("LP-UPGRADE-002", "Target version is unknown", "UNKNOWN", "UPGRADE_PATH",
            "A verified target family is needed to select applicable rules.", "Supply an identifiable target runtime or explicit version evidence.", GUIDE, c("target.version", "ABSENT", "")));
        r.add(rule("LP-UPGRADE-003", "Target family has no bundled upgrade rule coverage", "UNKNOWN", "UPGRADE_PATH",
            "This rule pack models the 4.11 to 4.12 migration only.", "Review the correct official upgrade documentation and provide validated rules.", GUIDE, c("target.version", "NOT_VERSION_FAMILY", "4.12")));
        r.add(rule("LP-UPGRADE-004", "Current version is unknown", "UNKNOWN", "UPGRADE_PATH",
            "The starting point of the documented upgrade path is not established.", "Supply current runtime version evidence.", GUIDE, target, c("source.version", "ABSENT", "")));
        r.add(rule("LP-UPGRADE-005", "Source is outside the documented 4.11 upgrade path", "UNKNOWN", "UPGRADE_PATH",
            "The bundled migration rules do not establish readiness for this source family.", "Use the applicable patch or downgrade guidance.", GUIDE, target, c("source.version", "NOT_VERSION_FAMILY", "4.11")));
        r.add(rule("LP-JAVA-001", "Corda 4.12 requires Java 17", "INFO", "JAVA",
            "The target family requires Java 17 (17.0.9 or a later Java 17 patch); analyzer Java is not proof of node deployment Java.",
            "Verify the planned node and external verifier Java 17 runtime.", BASE + "node-upgrade-notes.html", target));
        r.add(rule("LP-JAVA-002", "Configured target Java differs from 17", "BLOCKED", "JAVA",
            "Corda 4.12 requires Java 17; Java 18 and later are not supported by this guide.",
            "Prepare a supported Java 17 runtime.", BASE + "node-upgrade-notes.html", target, c("target.java", "NOT_EQUALS", "17")));
        r.add(rule("LP-KOTLIN-001", "Corda 4.12 requires Kotlin 1.9.20", "INFO", "CORDAPP",
            "Custom CorDapps must be rebuilt with the documented Java and Kotlin toolchain.", "Rebuild and test target CorDapps with Kotlin 1.9.20 and Java 17.", RELEASE, target));
        r.add(rule("LP-KOTLIN-002", "Target Kotlin metadata differs from documented toolchain", "WARNING", "CORDAPP",
            "Declared Kotlin version differs from 1.9.20; metadata alone cannot prove compiler compatibility.", "Check the target build configuration and R3 support matrix.", RELEASE, target, c("target.kotlin", "NOT_EQUALS", "1.9.20")));
        r.add(rule("LP-PLATFORM-001", "Corda 4.12 platform version is 140", "INFO", "CORDAPP",
            "Corda 4.12 uses platform version 140.", "Use minimum platform version 140 for the upgraded CorDapps.", RELEASE, target));
        r.add(rule("LP-PLATFORM-002", "Target platform metadata contradicts 4.12", "BLOCKED", "CORDAPP",
            "Declared platform differs from the documented 140.", "Check artifact identity and rebuild the upgrade kit.", RELEASE, target, c("target.platform", "NOT_EQUALS", "140")));
        r.add(rule("LP-CORDAPP-001", "Target CorDapps require recompilation", "WARNING", "CORDAPP",
            "Target artifacts have not been evidenced as rebuilt for the 4.12 toolchain.", "Recompile custom CorDapps, increment contract versions, retain flow versions where backward compatibility requires it, and test.",
            BASE + "app-upgrade-notes-enterprise.html", target, c("cordapps.recompiled", "EQUALS", "false")));
        r.add(rule("LP-CORDAPP-002", "Target contract version was not increased", "BLOCKED", "CORDAPP",
            "The 4.12 contract version must exceed the legacy contract version.", "Increment the target contract version by at least one and rebuild.", GUIDE, target, c("contract.versionIncreased", "EQUALS", "false")));
        r.add(rule("LP-CORDAPP-003", "Target CorDapp minimum platform differs from 140", "WARNING", "CORDAPP",
            "The upgrade guide prescribes minimum platform 140 for new CorDapps.", "Review and update the target CorDapp minimum platform metadata.", GUIDE, target, c("cordapps.minimumPlatform", "NOT_EQUALS", "140")));
        r.add(rule("LP-CONSTRAINT-001", "Hash attachment constraint usage requires migration", "WARNING", "CORDAPP",
            "4.12 supports signature constraints and AlwaysAcceptAttachmentConstraint. Bytecode references do not establish the constraints of persisted states.",
            "Determine whether live states use hash constraints; migrate affected states on 4.11 before upgrading.", RELEASE, target, c("constraints.hashDetected", "EQUALS", "true")));
        r.add(rule("LP-CONSTRAINT-002", "Explicit contract upgrade usage detected", "WARNING", "CORDAPP",
            "Explicit contract upgrade is not supported in 4.12; a reference is evidence of a code path, not proof it executes.", "Review affected paths and complete any required supported migration on 4.11.", RELEASE, target, c("constraints.explicitUpgradeDetected", "EQUALS", "true")));
        r.add(rule("LP-VERIFY-001", "Legacy-incompatible ledger verification pattern detected", "WARNING", "API_COMPATIBILITY",
            "SignedTransaction, WireTransaction or TransactionBuilder conversion to LedgerTransaction followed by verify is incompatible with legacy verification. Static co-occurrence requires code review.",
            "Review the call path and use SignedTransaction.verify() as documented.", RELEASE, target, c("verification.legacyPattern", "EQUALS", "true")));
        r.add(rule("LP-SIGNING-001", "Current and target signer metadata differs", "WARNING", "SIGNING",
            "4.11 and 4.12 CorDapps require the same signing key set. Metadata comparison is not cryptographic verification of all JAR entries.",
            "Verify both artifacts with a trusted signing tool and preserve the exact signer key set.", RELEASE, target, c("signing.continuity", "EQUALS", "different")));
        r.add(rule("LP-SIGNING-002", "CorDapp signer continuity is unproven", "WARNING", "SIGNING",
            "Missing or ambiguous signer evidence cannot establish the required key continuity.", "Verify signatures and pairing of current and target CorDapps.", RELEASE, target, c("signing.continuity", "EQUALS", "unproven")));
        r.add(rule("LP-TVU-001", "Required TVU artifact is missing", "BLOCKED", "TVU",
            "The 4.12 upgrade requires historical transaction validation with TVU in a prepared 4.12 environment.", "Add the 4.12 TVU JAR obtained from R3 to the upgrade kit.", GUIDE, target, c("tvu.present", "EQUALS", "false")));
        r.add(rule("LP-TVU-004", "TVU requires a supported database schema", "BLOCKED", "TVU",
            "4.12 TVU supports 4.11 and 4.12 database schemas. It cannot validate an older schema directly.", "Follow R3 guidance to validate an appropriately upgraded copy; LedgerPreflight does not connect or migrate.", BASE + "node/operating/tvu/running-tvu.html", target, c("tvu.schemaVersion", "VERSION_BELOW_411", "")));
        r.add(rule("LP-LEGACY-003", "Mixed network requires legacy contracts", "BLOCKED", "LEGACY_JARS",
            "Mixed networks require pre-4.12 contracts for transaction building. TVU itself does not require the legacy-contracts folder.", "Prepare legacy-contracts for node deployment and retain old contract JARs.", GUIDE, target, c("network.mode", "EQUALS", "mixed"), c("legacyContracts.present", "EQUALS", "false")));
        r.add(rule("LP-LEGACY-004", "External verifier dependencies need legacy-jars", "WARNING", "LEGACY_JARS",
            "The external verifier does not inherit all older bundled libraries or drivers; legacy-jars supplies required dependencies.", "Place required compatible dependencies in legacy-jars and confirm resolution with TVU.", GUIDE, target, c("legacyDependencies.required", "EQUALS", "true"), c("legacyJars.present", "EQUALS", "false")));
        return r;
    }
}
