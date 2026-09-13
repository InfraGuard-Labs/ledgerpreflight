# Docker build and validation

Run these commands from the repository root in a Linux shell with Docker:

```sh
mkdir -p dist
docker build --platform linux/amd64 --target build -t ledgerpreflight-build:0.1.0 .
docker run --rm --network none -v "$PWD/dist:/dist" \
  ledgerpreflight-build:0.1.0 sh scripts/validate.sh
```

The build runs clean compilation, tests, synthetic replay, benchmarks and SBOM generation. The second command packages the distribution and checks offline assessment, readiness, repeated runs and support packaging. Outputs are in `dist/`, including `ledger-preflight-0.1.0-linux-x86_64.tar.gz`, the executable JAR and `SHA256SUMS`. Extract the Linux package and run its `ledger-preflight` launcher; its private Java 17 runtime does not change the server's existing Java installation.

All compilation, dependency resolution, fixture generation and validation tools run in Docker. The build toolchain is pinned by image digest. Gradle dependency locking fixes transitive versions, and `gradle/verification-metadata.xml` verifies artifact and metadata SHA-256 values. JAR entries use stable ordering and timestamps; distribution archives use fixed timestamps and numeric ownership. Report creation timestamps and measured benchmark timings vary.

Additional validation scripts cover CLI processes, interactive terminal navigation, report schemas and browser rendering. Their tool images are under `docker/`. `scripts/validate-ubuntu.sh` validates the packaged launcher in clean Ubuntu 18.04, 20.04, 22.04 and 24.04 x86_64 containers. Runtime validation disables networking and uses non-root execution with read-only inputs. A separate Ubuntu 18.04 Java 8 fixture checks private-runtime isolation.

Execution-context regressions generate a generic current-runtime/driver duplicate, separate node and verifier copies, verifier-only incompatibility, ambiguous replacement mapping, and proven/unproven verifier/legacy ordering. `validate-execution-context-package.sh` exercises the bundled 256 MiB launcher through Environment, Continue, evidence, export, sanitized support and exit on each Ubuntu version. `validate-execution-context-terminal.py` captures actual packaged terminal cell buffers and raw ANSI; `validate-execution-contexts.py` checks the A–T evidence matrix. Synthetic API owners are deliberately outside Corda packages to detect package-specific precedence shortcuts.

Scan the release SBOM, executable JAR and runtime image with containerized Trivy before deployment. Vulnerability results are point-in-time evidence. The CycloneDX SBOM records original runtime dependency hashes; its dependency edges conservatively enumerate included components rather than claiming exact transitive parentage.

All checked-in fixtures are synthetic source. No licensed Corda Enterprise validation is claimed yet. Private validation inputs and generated outputs are ignored by Git and excluded from Docker build contexts. Benchmarks use small synthetic JARs and are not production performance guarantees.
