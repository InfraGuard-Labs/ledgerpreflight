# Troubleshooting

The Linux x86_64 release validation matrix targets Ubuntu 18.04, 20.04 and 22.04 LTS; release validation results record the measured outcomes. Use the standalone CLI over SSH or its non-root container. A browser is unnecessary for assessment; optional HTML output can be reviewed later on a workstation.

| Symptom | Interpretation and next step |
| --- | --- |
| Target version unknown | Use an artifact with release metadata and the correct contained runtime classes; use `--target-corda` for unusual layouts. Renaming a JAR does not prove identity. |
| TVU artifact missing | Add the authorized intended target TVU JAR; use `--tvu-jar` if it lives outside the kit. |
| Required exact member absent | Compare the displayed descriptor and invocation kind against the supplied runtime. Similar names or another overload do not satisfy linkage. |
| Missing ancestor or class | Supply the complete relevant runtime/dependency inventory; the tool cannot infer members in absent bytecode. |
| Internal API warning | The symbol may still exist. Review instability risk and historical verification; a warning is not a claim of removal. |
| Legacy duplicate | Check actual verifier classpath and class-load origin. Classes do not merge; avoid unsupported class replacement tricks. |
| Mixed-case schema | Compare database.schema, JDBC currentSchema, quoted search_path and Hibernate evidence on the intended TVU environment. |
| TVU says missing table | Establish effective schema independently; the message alone does not prove physical absence. Normal node success does not establish TVU success. |
| TVU totals incomplete | Supply a complete single-run console/log output; missing or contradictory totals prevent final readiness. |
| Fewer detailed failures than reported failures | Supply the remaining error evidence if available. Do not extrapolate a cause count from a sample. |
| HOCON include/substitution rejected | Supply a bounded self-contained diagnostic configuration. External includes and environment substitution must not access secrets or networks. |
| Malformed or oversized JAR/ZIP | Obtain a valid bounded artifact and rerun. Coverage errors prevent a ready result. |
| Symlink or path escape | Copy authorized artifacts into a normal isolated input directory without links outside its boundary. |
| Report output overlaps input | Select a separate output directory. Assessment inputs are protected from report writes. |
| Support bundle safety gate fails | Inspect the named generated file, remove or properly sanitize secret material, then regenerate. Do not bypass the final scanner. |
| Docker report permission denied | Make the output directory writable for the non-root image user using your runner's ownership policy. Keep input mounts read-only. |
| Standalone launcher permission denied | Check executable permission on the extracted launcher and traversal permission on its parent directories; use an account authorized to read the input copy. |
| Java command unavailable over SSH | Use the primary Linux archive's launcher and bundled runtime. Only the separate JAR-only distribution needs a selected Java 17 installation. Do not change system Java merely to run preflight. |
| Host Java 8 but analyzer Java 17 | These describe different runtimes. The bundled analyzer runtime does not establish the planned target node or external verifier runtime. |
| Relative paths resolve unexpectedly | Use absolute `/srv/...` paths in SSH and CI commands; container mounts have their own Linux paths. |
| No graphical display or browser | Read the terminal status and JSON report. HTML is optional output and requires no server-side desktop. |

Always reproduce against synthetic or authorized copied inputs first. `analyze-jar`, `compare-runtime` and `analyze-tvu` isolate individual analyses. Include sanitized evidence and artifact hashes when seeking support. LedgerPreflight does not provide an R3 support entitlement or prove that a target patch contains a vendor fix.
