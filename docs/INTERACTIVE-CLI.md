# Interactive CLI

The normal flow is Environment, Result, then relevant evidence or export actions. Discovery happens before deep compatibility analysis. The environment screen shows the chosen node, active current runtime, target runtime, current Java evidence, database, schema and CorDapp counts. Its only actions are Continue and Exit. Ambiguous node/configuration/current-runtime/target-runtime/TVU choices are resolved explicitly first.

A strongly identified root corda.jar is the active current runtime even when historical runtime copies are present. With no valid canonical runtime, one strong root candidate is selected regardless of name; multiple equally strong candidates require selection. Historical runtimes stay in exported diagnostics and are excluded from normal deep analysis. Active version, platform, minimum Java and vendor feed the same normalized model used by discovery and assessment.

Result actions depend on the actual findings:

| Condition | Action |
| --- | --- |
| CorDapp/API compatibility issue | View compatibility evidence |
| Schema issue or warning | View schema evidence |
| Supplied TVU results | View TVU evidence |
| READY FOR TVU | TVU instructions |
| All results | Export full technical report; Create R3 support package; Run again; Exit |

The three evidence views are short explanations of affected code, effective schemas and supplied TVU totals/root causes. Compatibility evidence names only proven source CorDapps and shows the referenced API alongside independent current/target class and member outcomes. Repeated callers share one API root cause. An unrelated broad runtime indexing limit remains in exports; incomplete required lookup is shown as unresolved compatibility. They do not show raw JSON, internal finding IDs, budgets, hashes or stack-trace dumps. There is no general technical-evidence dashboard or interactive raw-report browser. Repeated internal diagnostics map to user-facing issue groups; the result does not display a raw warning total.

Confirmed blockers, unresolved coverage and required reviews all prevent an upgrade recommendation. JSON preserves BLOCKED, UNKNOWN and WARNING separately, with their existing exit codes. The normal screen explains grouped issues using What happened, Why it matters and What to do. TVU failures are correlated to exact member signatures only when the supplied records support that match; missing details remain unclassified.

Export full technical report writes complete HTML, JSON and plain text and shows their paths. Raw runtime manifests, active/inactive candidates, inventories, exact API references, classpath order, schema/search-path declarations, TVU totals, coverage limits and skipped paths remain in exported diagnostics. Sanitized support packages contain generated textual evidence only, exclude binaries/keys/keystores, undergo a final ZIP secret scan and receive an external SHA-256 checksum.

TVU instructions preserve isolated-copy preparation, importing an existing complete run and explicitly approved execution on an isolated node/database copy. The command and environment are shown before approval. Static assessment never executes TVU, changes the node, runs SQL or performs migrations.

Selection uses ASCII >. Interactive menus hide the native cursor and restore it in a finally block and shutdown hook. Arrow keys, j/k, Enter and q are supported. Plain-terminal mode uses numbered labels; CI, JSON and redirected output remain deterministic and noninteractive. Abrupt power loss or SIGKILL cannot execute cleanup; standard exit, q, Ctrl+C, SIGTERM and exceptions are covered by terminal validation.
