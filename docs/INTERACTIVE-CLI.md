# Interactive CLI

The normal flow has three layers: Environment, Result, Technical evidence. Discovery happens before deep compatibility analysis. The environment screen shows the chosen node, runtime versions/platforms, current Java evidence, database, primary schema and physical CorDapp counts. Its only actions are Continue and Exit. Ambiguous node/configuration/runtime/TVU choices are resolved explicitly first.

Result actions depend on the current evidence:

| Result | Actions |
| --- | --- |
| NOT READY TO UPGRADE | View technical evidence; Create R3 support package; Run again; Exit |
| READY FOR TVU | TVU instructions; View technical evidence; Exit |
| READY TO UPGRADE | View upgrade checklist; View technical evidence; Exit |

Confirmed blockers, unresolved coverage, and required warning reviews all prevent an upgrade recommendation. JSON preserves BLOCKED, UNKNOWN and WARNING separately, with their existing exit codes. The normal screen explains grouped issues using What happened, Why it matters, and What to do. Repeated TVU errors are correlated to exact missing member signatures only when the supplied evidence supports that match.

Technical evidence contains runtime manifests, inventories, exact API references, classpath order, schemas/search paths, TVU totals, coverage limits and skipped paths. It also generates complete HTML/JSON/text assessments and lists the generated files. Sanitized support packages contain generated textual evidence only, exclude binaries/keys/keystores, undergo a final ZIP secret scan, and receive an external SHA-256 checksum.

TVU instructions describe isolated-copy preparation and allow importing an existing complete run or explicitly approving execution on an isolated node/database copy. The exact command and environment are shown before approval. Static assessment never executes TVU, changes the node, runs SQL, or performs migrations.

Selection uses ASCII >. Interactive menus hide the native cursor and restore it in a finally block and shutdown hook. Arrow keys, j/k, Enter and q are supported. Plain-terminal mode uses full numbered labels; CI, JSON and redirected output contain no interactive cursor controls. Abrupt power loss or SIGKILL cannot execute cleanup; standard exit, q, Ctrl+C, SIGTERM and exceptions are covered by terminal validation.
