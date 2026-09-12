# Architecture

LedgerPreflight is a Java 17 application organized into small packages with value records. Gradle, ASM, picocli, Typesafe Config, Jackson and JUnit supply build, bytecode, CLI, configuration, serialization and tests.

`bytecode` performs bounded read-only archive inventories and exact symbolic member analysis without class loading. `core.Discovery` assigns artifact roles using class/manifest evidence and directory context. `core.AssessmentService` coordinates current/target comparisons, schema evidence, TVU and versioned rules. `rules` evaluates additive declarative rules. `evidence` parses configuration and TVU text and protects support packaging. `reporting` writes deterministic escaped offline HTML and stable JSON. `cli` validates output separation, exposes commands and returns readiness exit codes.

Inputs are streamed in deterministic order with one scan worker. Bytecode class models remain bounded in memory. Nested archive content is bounded before recursion. Runtime class and member evidence is stronger than assumptions about a patch version. A missing descriptor is distinct from a same-name overload. Duplicate class definitions are never merged.

Readiness evaluates blockers first, then unknown evidence, then warnings. With none of these present, complete successful TVU evidence enables READY TO UPGRADE; absent evidence enables only READY FOR TVU. Static assessment never executes TVU. The separate interactive action requires explicit approval and an isolated validation copy; process failures cannot establish readiness. See INTERACTIVE-CLI.md. User evidence is not cryptographically bound to an inventory; provenance and historical coverage remain operator responsibilities.

Development compilation, test execution, fixture generation, report generation, packaging, dependency resolution, SBOM and release checks run in Docker. The host stores source and generated artifacts only. The Linux distribution includes a private Java 17 runtime; the JAR-only distribution requires Java 17. The optional runtime image is non-root.
