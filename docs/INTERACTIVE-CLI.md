# Interactive CLI

The normal flow is Environment, Result, then the actions relevant to that assessment. Discovery precedes deep compatibility analysis. The environment screen shows the node, active current runtime, target runtime, current Java evidence, database, schema and CorDapp counts. Continue and Exit remain its only actions. Ambiguous node, configuration, runtime and TVU choices require selection first.

A strongly identified root corda.jar is the active current runtime even when historical copies exist. Without a canonical runtime, one strong root candidate is selected regardless of name; multiple equally strong candidates require selection. Historical copies stay in exported diagnostics and are excluded from normal deep analysis.

The result counts grouped confirmed blockers and shows every counted heading. Unresolved questions and required reviews remain separate. Each issue explains What happened, Why it matters and What to do. Deep evidence, inventories, hashes, descriptors and raw logs remain outside the normal screen.

Before TVU results are supplied, the result offers Run TVU safely when a target validator is discovered, then Import existing TVU results, relevant compatibility/schema evidence, Export full technical report, Create R3 support package and Exit. After a run or import, relevant evidence comes first, followed by export, support, Run TVU again, import and Exit. The user stays in the same session through preparation, execution, evidence collection and reassessment.

Compatibility evidence shows the affected source CorDapp, human API name and independent current/target class and member outcomes. Repeated callers share one API root cause. Correlation uses exact member signatures only when supplied transaction records establish the match; missing details remain unclassified. Schema and TVU evidence retain concise explanations with technical depth available in the exports.

## Guided TVU safety

Static assessment reads local inputs. It never connects to a database, starts TVU, modifies the node or runs migrations. Choosing Run TVU safely first shows the target, validator, target CorDapps, database target, schema preparation, environment and exact command. Execution requires explicit confirmation that the selected database is an isolated/non-production copy. Database names such as test or copy do not establish safety.

Use a different safe node configuration accepts a configuration file for that copy. LedgerPreflight validates the database vendor, schema and available identity/role relationship. Credentials stay in the file, never in command arguments. No database cloning, cloud operation or migration is automated.

For CI, use the explicit flags together:

```sh
ledger-preflight assess --node /path/to/node --upgrade-kit /path/to/kit \
  --run-tvu --tvu-node-conf /path/to/isolated/node.conf --confirm-isolated-db
```

The guided runner prepares its own private workspace, copies selected target artifacts and uses its compatible Java runtime. Affected mixed-case PostgreSQL schemas on supported Corda 4.12 targets receive temporary Hibernate configuration. An established primary schema wins over additional search schemas. An ambiguous primary requires selection from discovered candidates; noninteractive execution requires an explicit valid selection with --tvu-schema. Inputs remain unchanged.

Run progress shows observed counts and elapsed time. Repetitive verifier messages are captured rather than printed. Cancel, Ctrl+C and SIGTERM stop the validator and verifier process group, preserve sanitized partial evidence and clean the private workspace. SIGKILL or power loss cannot execute cleanup.

A completed run is automatically imported, correlated and reassessed. Setup, database connection, execution, transaction verification and cancellation outcomes remain distinct. Successful counters cannot establish readiness when execution, capture or cleanup is incomplete. Run-scoped evidence is preserved beneath the report directory, while temporary configuration secrets are removed.

Known automatic schema preparation is not an initial blocker. Matching Hibernate startup evidence from the completed run establishes that the intended quoted schema was loaded. Imported evidence without that proof retains the applicable schema blocker; mismatches and schema validation failures also block. A generated properties file alone is not execution proof. The synthetic missing-API case has one blocker initially, two after a failed guided run with proven schema loading, and three when imported failed TVU evidence lacks that proof.

## Reports and terminal behavior

Export full technical report writes HTML, JSON and plain text and shows their paths. R3 support packaging automatically collects generated sanitized evidence, including guided-run provenance, schema loading, TVU counts, API correlation and runtime/classpath proof. It excludes proprietary binaries, keys and keystores, scans the completed ZIP again and creates a SHA-256 file. It refuses to publish the package when its safety checks fail.

Menus use ASCII > with arrow keys, j/k, Enter and q. Plain terminals use numbered labels. CI, JSON and redirected output remain deterministic and noninteractive. The terminal cursor and input mode are restored on normal exit, cancellation and handled failure. Actual packaged terminal screenshots and transcripts are generated by Docker validation; they are not recreated report content.

All public fixtures are synthetic. A successful synthetic guided run does not substitute for acceptance against an operator-confirmed isolated copy of a real Corda environment.
