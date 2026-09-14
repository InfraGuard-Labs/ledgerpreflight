# LedgerPreflight

LedgerPreflight is a Corda upgrade preflight and TVU analysis tool. It tells you what may break before an upgrade and helps explain why existing TVU validation failed.

**v0.1.0 is for external evaluation.** It performs static preflight analysis and imports existing TVU results. It does not run TVU for you.

The workflow is **preflight → existing TVU evidence → explanation → export**. Run the standalone Linux CLI on a server or over SSH; HTML and JSON are report files, not a dashboard.

## What it checks

- Current and target Corda versions, platform versions and runtime artifacts.
- Current Java evidence, target Java requirements and declared target readiness.
- Current and target CorDapps, replacement mapping and artifact boundaries.
- Runtime classes, methods and fields, including exact JVM descriptors and relevant verifier contexts.
- Internal API usage, duplicate legacy classes and evidenced classpath shadowing.
- PostgreSQL schema declarations, mixed-case risks and conflicting configuration.
- Existing TVU summaries, error ZIPs and failure correlation supported by matching evidence.

It does not start Corda or TVU, execute CorDapps, connect to a database, perform upgrades or change schemas. It does not clone databases, install node Java, certify an upgrade or replace the official Corda upgrade procedure.

## Install and verify

The primary package includes private Java 17. It can assess a node using Java 8 without replacing system Java or changing `JAVA_HOME`.

Download the Linux x86_64 archive and its checksum list from the [v0.1.0 release](https://github.com/InfraGuard-Labs/ledgerpreflight/releases/tag/v0.1.0):

```sh
release=https://github.com/InfraGuard-Labs/ledgerpreflight/releases/download/v0.1.0
curl -fL "$release/ledger-preflight-0.1.0-linux-x86_64.tar.gz" -o ledger-preflight-0.1.0-linux-x86_64.tar.gz
curl -fL "$release/SHA256SUMS" -o SHA256SUMS
awk '$2 == "ledger-preflight-0.1.0-linux-x86_64.tar.gz"' SHA256SUMS | sha256sum -c -
tar -xzf ledger-preflight-0.1.0-linux-x86_64.tar.gz
cd ledger-preflight-0.1.0
./ledger-preflight --help
```

Continue only if checksum verification succeeds. Obtain both files from the intended GitHub release; a checksum detects changed bytes, not the authenticity of an arbitrary download site.

Alternatively, review [install.sh](install.sh), then run `sh install.sh`. It downloads v0.1.0, verifies the archive before installation and installs under `$HOME/.local`. Use `--prefix /absolute/tool-directory` for a different location, or explicitly choose `--version latest`. Existing installations are preserved. The installer needs standard Linux utilities and `curl`; it does not modify system Java or a Corda node.

The [latest release download](https://github.com/InfraGuard-Labs/ledgerpreflight/releases/latest/download/ledger-preflight-0.1.0-linux-x86_64.tar.gz) is also available. For source builds, use [Docker build instructions](docs/REPRODUCIBILITY.md).

## Quick start

Use a consistent copy or snapshot of the current node and a separate target upgrade kit. Keep reports outside both input directories.

```text
ExampleIssuer/                 upgrade-kit/
├── corda.jar                  ├── corda-target.jar
├── node.conf                  ├── transaction-validator.jar
├── cordapps/                  ├── cordapps/
│   ├── example-contract.jar   │   ├── example-contract.jar
│   └── example-workflow.jar   │   └── example-workflow.jar
└── drivers/                   └── legacy-jars/     optional
    └── jdbc-driver.jar
```

These names are illustrative. Discovery uses artifact metadata and contents. Direct files in `cordapps/` form the default active CorDapp set; backup siblings and JDBC drivers do not. Prepare the kit using the [official Corda upgrade guide](https://docs.r3.com/en/platform/corda/4.12/enterprise/upgrade-guide.html). Supply your own licensed artifacts; none are distributed with LedgerPreflight. A TVU artifact can be inspected as target evidence, but is never launched.

```sh
./ledger-preflight assess \
  --node /path/to/ExampleIssuer \
  --upgrade-kit /path/to/upgrade-kit \
  --output ./reports/static
```

The discovery screen summarizes the node, current/target Corda and platform versions, Java, database/schema and current/target CorDapp counts. Confirm the discovered environment before continuing. Ambiguous artifacts require a selection; missing evidence is not guessed.

<img src="docs/images/ledgerpreflight-environment.png" alt="Synthetic ExampleIssuer discovery in an actual Ubuntu terminal" width="850">

Arrow keys select actions; `q` returns or exits. Plain terminals have numbered choices. CI, redirected output and `--json` do not prompt. Use `--verbose` for full findings and exported reports for raw technical evidence.

## Understand the decision

| Terminal result | Meaning | Next step |
| --- | --- | --- |
| NOT READY TO UPGRADE | A blocker, required review or missing evidence prevents a trustworthy decision. | Read what happened, why it matters and what to do; resolve the stated issues. |
| READY FOR TVU | Static checks are clear; complete successful TVU evidence is still required. | Perform TVU separately using R3's instructions, then import its results. |
| READY TO UPGRADE | Required static checks and the supplied TVU evidence passed. | Confirm evidence provenance and coverage, then follow your approved upgrade process. |

JSON keeps `BLOCKED`, `WARNING` and `UNKNOWN` distinct. [Exit codes](docs/USER-GUIDE.md#readiness-and-exit-codes) are 0 for final readiness, 1 for warnings or READY FOR TVU, 2 for blockers, 3 for tool/configuration errors and 4 for unknown evidence. Command syntax errors can also exit 2.

<details>
<summary>Actual terminal examples: blocked, ready for TVU and ready to upgrade</summary>

All screenshots use synthetic ExampleIssuer artifacts and evidence.

<img src="docs/images/ledgerpreflight-blocked.png" alt="Synthetic compatibility and imported TVU issues explained in an Ubuntu terminal" width="850">
<img src="docs/images/ledgerpreflight-ready-for-tvu.png" alt="Static checks passed; TVU evidence is still needed" width="850">
<img src="docs/images/ledgerpreflight-ready-to-upgrade.png" alt="Static checks and complete imported TVU evidence passed" width="850">

</details>

## Import existing TVU results

Run TVU separately according to the [official TVU instructions](https://docs.r3.com/en/platform/corda/4.12/enterprise/node/operating/tvu/running-tvu.html). Supply the complete console/validator log and error ZIPs from the **same run**:

```sh
./ledger-preflight assess \
  --node /path/to/ExampleIssuer \
  --upgrade-kit /path/to/upgrade-kit \
  --tvu-results /path/to/tvu.log \
  --tvu-results /path/to/tvu-errors.zip \
  --output ./reports/with-tvu
```

You can also supply a directory with `--tvu-results /path/to/tvu-evidence`, or choose **Import existing TVU results** in the result screen.

The log establishes available processed/passed/failed counts and completion evidence. Error ZIPs can provide detailed failure records. A summary reporting failures without matching detail cannot establish the cause of every failure. Malformed, incomplete or contradictory evidence cannot establish success. LedgerPreflight does not deserialize transaction objects. See [TVU analysis](docs/TVU-ANALYSIS.md) for format and coverage limits.

For example, a synthetic `com.example.contracts.ExampleContract` might call `InternalUtils.sum(Iterable)`, which is absent from the target runtime. When imported failure records identify that same owner, member and descriptor, LedgerPreflight links the records to the compatibility issue. Three matching detail records establish three matches; they do not explain additional failures whose details were not supplied.

## PostgreSQL schemas

Quoted mixed-case names such as `ExampleSchema` need consistent interpretation across node configuration, JDBC schema settings and the TVU environment. Conflicting defaults or unresolved declarations need operator review. A missing-table message alone does not prove a physical table is absent.

LedgerPreflight checks configuration and imported evidence. Actual matching Hibernate startup evidence can establish which quoted schema TVU loaded; configuration text alone does not prove that it was used. The tool does not prepare Hibernate files, query tables or change a schema. See [schema discovery boundaries](docs/UNIVERSAL-DISCOVERY.md).

## Reports and support evidence

Choose **Export full technical report** for HTML, JSON and plain text, or add `--support-bundle` to an assessment:

```sh
./ledger-preflight assess \
  --node /path/to/ExampleIssuer --upgrade-kit /path/to/upgrade-kit \
  --tvu-results /path/to/tvu-evidence \
  --output ./reports/with-tvu --support-bundle
```

The CLI prints the generated paths. Reports retain exact API evidence, descriptors, hashes, classpath analysis and findings. Support packaging collects generated diagnostic evidence, redacts recognized credentials, excludes binaries, raw configuration, raw logs, keys and keystores, then checks the completed package and writes its SHA-256. A failed safety check prevents package creation. Nothing is uploaded. See [support bundle contents](docs/SUPPORT-BUNDLE.md).

**Review before sharing.** Redaction cannot recognize every unlabelled secret. Artifact names, schema names, namespaces and error messages can still identify an environment. Use your approved support channel; do not attach customer logs, proprietary JARs or credentials to a public issue.

## Safety, environments and limitations

Use an unprivileged account, read-only input mounts where available, and a separate writable output directory. Inputs must remain stable during assessment. The CLI works offline and has no telemetry or upload service. Its default heap is 256 MiB; allow 512 MiB process memory and scratch space for nested archives. Large or unusual inputs can exceed explicit analysis limits and remain unresolved. See [security boundaries](docs/SECURITY-MODEL.md).

Release validation covers Linux x86_64 on Ubuntu 18.04, 20.04, 22.04 and 24.04, including a server environment with Java 8 and a separate bundled Java 17 runtime. Consult the release validation summary for exact tests and results. Newer Ubuntu LTS compatibility requires validation; Windows packaging is outside v0.1.0.

Static analysis cannot prove reflection, dynamic loading, full signer continuity or complete historical database coverage. Installed CorDapps are not a complete inventory of historical attachments. Supplied TVU logs are not authenticated or cryptographically bound to the assessed snapshot. No patch-specific vendor defect is inferred from a filename or version alone. Public tests and screenshots use synthetic data; they do not certify a production upgrade.

## Evaluate and report a problem

For Corda and R3 engineers:

1. Assess an authorized node copy and prepared target kit; check the discovered environment.
2. Compare findings with the actual artifacts and official upgrade guidance.
3. Import complete existing TVU evidence from the matching validation run.
4. Review correlations and unresolved evidence; export a sanitized technical assessment.
5. Test the intended upgrade in a lower environment and follow operational change controls.

Open a [GitHub issue](https://github.com/InfraGuard-Labs/ledgerpreflight/issues) with the tool version, Ubuntu version, expected/actual behavior and a small synthetic reproduction. Review any excerpt or support package first. Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting.

LedgerPreflight is licensed under [Apache 2.0](LICENSE); bundled components retain their [third-party notices](THIRD-PARTY-NOTICES). The release also supplies the [matching private-runtime source archive](https://github.com/InfraGuard-Labs/ledgerpreflight/releases/download/v0.1.0/OpenJDK17U-jdk-sources_17.0.20.1_1.tar.gz) and its checksum for license compliance. It is independent software, not affiliated with, endorsed by or supported by R3. Corda and R3 trademarks belong to their respective owners.
