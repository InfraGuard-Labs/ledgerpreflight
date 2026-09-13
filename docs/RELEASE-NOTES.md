# LedgerPreflight 0.1.0 (unreleased)

Standalone Linux Corda upgrade assurance. No tag, GitHub Release or public image publication is part of this candidate. The next gate is a final real-environment regression without TVU evidence and with the supplied correlated TVU evidence.

The product flow is Environment → Result → relevant evidence, export and support actions. Physical artifact identity is established before deep analysis. Runtime manifests, TVU entries, modern CorDapp headers and targeted legacy class headers survive incomplete compatibility scanning. Per-artifact deep budgets prevent a large capsule from starving later files; nested libraries do not inflate physical artifact counts.

Required compatibility questions come from active current CorDapp bytecode. Independent bounded lookup proves exact current and target classes, methods and fields inside runtime capsules, even when unrelated broad indexing is partial. Findings distinguish a missing member, missing class, changed descriptor and unresolved proof. Grouped source provenance identifies the historical calling CorDapp; rebuilt target artifacts and assessment labels are not attributed as callers. Human evidence shows current/target outcomes, while exact descriptors and separate coverage limits remain in exported reports.

Current node, target node and target external verifier now resolve in separate execution contexts. Supporting driver duplicates do not compete with selected runtime definitions. Proven verifier/legacy order selects one class without merging members; unproven ordering remains local to that context. Target replacement matching no longer obscures a confirmed runtime incompatibility. Human compatibility evidence shows each relevant runtime outcome, and sanitized support packages include execution-context and exact-symbol proof. Environment, schema evidence and result actions retain their existing flow.

Generic inherited-member resolution now handles facade/helper hierarchies without exhausting the archive-work budget through repeated full enumerations. Compatible exact inherited methods remain quiet, while missing or changed ancestor members remain incompatibilities. Interface defaults, constructors, access restrictions and invocation semantics are checked conservatively. Synthetic JVM oracles and packaged regressions cover a compatible inherited helper alongside one confirmed removed method, with and without all 201 correlated TVU failure records. The packaged heap limit remains 256 MiB.

The normal result groups compatibility and TVU problems and explains what happened, why it matters, and what to do. Static success enables READY FOR TVU only. READY TO UPGRADE requires complete successful TVU evidence and no outstanding required findings. JSON retains distinct BLOCKED, UNKNOWN and WARNING states and documented exit codes.

Schema analysis retains ordered PostgreSQL paths, agreed primary/default schemas and additional schemas. Conflicting defaults and unresolved values remain unproven. Mixed-case schema guidance is generic. Discovery performs no database connection, query, migration or node modification.

Exact JVM member comparison and classpath/shadowing analysis remain generic. Two synthetic 650/449/201 fixtures distinguish three supplied failure records from all 201 supplied records. Correlation requires matching owner, member and descriptor and makes no claims about unsupplied records or real vendor patch behavior.

The Linux x86_64 package bundles private Java 17; system Java remains unchanged. Validation uses clean Ubuntu 18.04, 20.04, 22.04 and 24.04, a separate Java 8 coexistence fixture, network-disabled operation, read-only inputs and non-root execution. Interactive tests exercise ASCII selection, arrows, cursor hiding/restoration, Ctrl+C, SIGTERM, exceptions, narrow terminals, CI and redirected output.

Build and validation evidence accompanies the candidate: clean Docker build logs, JUnit XML and test index, process and terminal summaries, acceptance reports, actual terminal screenshots, Ubuntu/Java 8 results, SBOM, security/public-source audits, support-package hashes and SHA256SUMS. Consult those results for exact counts and scan timestamps.

Reports are secondary output artifacts: HTML, JSON and plain text. Sanitized R3 Support packages contain generated evidence, configuration signals, API/classpath/TVU analysis and hashes. Binaries, private keys and keystores are excluded. The completed ZIP is scanned again before it is accepted.

Known limits: synthetic fixtures do not validate licensed Corda artifacts. Reflection, dynamic loading, complete JVM access/module behavior and historical attachments are outside static certainty. Signing metadata is not cryptographic signer validation. Supplied TVU logs are not authenticated or cryptographically bound to a database snapshot. Operators must establish provenance, use the supported upgrade procedure, validate in a lower environment, and complete change controls. Very narrow terminals wrap longer explanations into scrollback. Cleanup hooks cannot run after SIGKILL or power loss.

Development, building, fixture generation, testing, packaging and scanning run in Docker. The host stores project source and generated artifacts; no host Java, Gradle, Python, Node or database installation is required.
