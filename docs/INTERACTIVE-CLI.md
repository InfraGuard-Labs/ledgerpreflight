# Interactive CLI

The v0.1.0 flow is Environment → Result → relevant evidence, import, export and support actions. It performs static inspection and analyzes existing TVU evidence. It never starts TVU, a verifier, Corda or a database operation.

Discovery precedes deep compatibility analysis. The environment screen shows the node, active current runtime, target runtime, platform versions, Java evidence, database/schema and CorDapp counts. Continue and Exit are its only actions. Ambiguous node, configuration, runtime and validator artifacts require selection first; selecting a validator only identifies evidence for analysis.

A strongly identified root corda.jar is the active current runtime even when historical copies exist. Without that canonical runtime, a sole strong root candidate can be selected regardless of name. Multiple equally strong candidates require a choice. Historical copies remain in exported diagnostics and are excluded from normal deep analysis.

The result counts all grouped confirmed blockers and shows the priority issues: up to three issues and one warning, with remaining findings available in the full report. Its compact environment summary includes platform versions, Java, CorDapp counts, database/schema and whether TVU evidence was imported, including available processed/passed/failed counts. Unresolved questions and required reviews remain separate. Each issue explains What happened, Why it matters and What to do. Broad inventory limits do not become upgrade blockers when independent required-symbol analysis resolves the relevant questions. Missing required evidence still prevents a ready result.

## Result actions

Only actions relevant to the assessment appear: Import existing TVU results, compatibility/schema/TVU evidence, Export full technical report, Create R3 support package and Exit. There is no TVU execution, database confirmation or generated launch-command action in v0.1.0.

Import existing TVU results accepts a log, error ZIP or directory of evidence from one completed validation run. Import analyzes the supplied files and updates the current result without starting a validator. Keep summary logs and detailed records from the same run together.

Compatibility evidence identifies the source CorDapp, human API name and independent current/target class and member outcomes. Repeated callers share one API root cause. TVU correlation uses exact member signatures only when supplied records establish a match; missing details remain unclassified. Schema and TVU explanations remain concise. Descriptors, inventories, hashes and raw analysis diagnostics belong in exported reports.

READY FOR TVU means static checks are clear and successful TVU evidence is still needed. Perform TVU separately using the official procedure, then import its results. READY TO UPGRADE requires complete successful supplied evidence and clear required static checks. NOT READY TO UPGRADE covers blockers, required reviews and insufficient evidence; JSON distinguishes those causes.

## Reports and terminal behavior

Export full technical report writes HTML, JSON and plain text and prints their paths. Support packaging collects generated sanitized configuration, API, classpath, schema and imported TVU evidence. It excludes binaries, raw source configuration, raw logs, keys and keystores, scans the completed ZIP and creates a SHA-256 file. Safety rejection prevents package creation. Nothing is sent to a support service automatically.

Menus use an ASCII > marker with arrow keys, j/k, Enter and q. Plain terminals use numbered choices. CI, JSON and redirected output are deterministic and noninteractive. The terminal cursor and input mode are restored on normal exit, cancellation and handled failure. Package validation captures actual Ubuntu terminal output; screenshots use synthetic data.
