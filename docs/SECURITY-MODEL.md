# Security model

LedgerPreflight reads operator-supplied artifacts offline. v0.1.0 does not connect to a database, launch a node, execute TVU, deserialize Corda objects, load CorDapp classes or make upgrade changes. Interactive and command-line TVU import only parse supplied files. Docker development and validation use synthetic inputs only. Use read-only input mounts and a dedicated writable report directory.

## Untrusted inputs

The bytecode inventory uses ASM, bounded archive streams and explicit entry, expanded-byte, class and reference budgets. Archive paths containing traversal are rejected; entries are never extracted. Unsupported or malformed evidence produces incomplete-analysis findings, never a successful readiness gate. Recursive archives and filesystem walks have independent depth limits. An explicitly supplied symlinked root authorizes its canonical destination. Nested links are followed only within that root; external links are skipped and reported. Supply stable copies: path checks are not a substitute for operating-system isolation against a privileged process racing filesystem changes.

TVU evidence is limited to 8 MiB per text entry, 64 MiB aggregate text, 64 MiB compressed archive size and 2,000 entries per ZIP. Entries larger than 1 MiB with compression ratio above 200 are rejected. TVU directories permit at most 4,096 visited entries and bounded depth. Only text/log/JSON/ZIP files are discovered. Unrecognized records in error archives prevent success, and supplied failure-record counts are never extrapolated to unsupplied transactions.

HOCON is parsed by Typesafe Config with a 1 MiB source limit and conservative structural complexity limits. Bounded relative file includes, local substitutions and referenced non-sensitive environment variables are supported. Absolute, escaping, network and classpath includes and include cycles are rejected. System properties and sensitive environment values are not read. Unresolved credential placeholders may remain unused; unresolved required analysis signals fail clearly. No raw node.conf is retained in reports. Allowed evidence includes schema declarations, database type, a connection-details-omitted JDBC representation, schema search-path interpretation and selected presence/boolean settings. SQL is never executed. JVM argument values are limited to recognized memory and garbage-collector options.

## Output controls

CLI assessment output must be separate from every supplied assessment input. Report writes reject traversal and symbolic-link destinations. HTML escapes every untrusted value and includes a restrictive Content Security Policy; it uses no network resources or executable JavaScript. JSON serialization redacts credential-key values recursively and redacts credential assignments in text.

Support bundles use a fixed filename allowlist of generated textual evidence. They never recursively collect node/report directories and never include JARs, raw logs, original configuration, keystores, private keys or certificates. JSON is parsed and sanitized structurally. Every final entry passes a scanner for credential assignments and recognizable private-key, token and access-key patterns before a ZIP is created. Safety rejection names the affected permitted entry without echoing the secret. Bundle writes use a temporary file and refuse to overwrite an existing destination.

## Limits of assurance

Redaction and secret scanning cannot identify every arbitrary unlabelled secret. Review generated evidence before sharing and keep assessment inputs limited to the required files. Schema names, artifact names, class names and failure messages are diagnostically useful and may identify an environment. No telemetry, analytics or upload function is implemented. Unknown formats, incomplete runtime evidence, dynamic loading, reflection and unproven historical coverage require operator verification. Successful static checks do not replace TVU or the official R3 procedure.

Report vulnerabilities privately using your repository maintainer's security reporting process; do not include real credentials or customer artifacts in public issues. See SECURITY.md for the project policy.
