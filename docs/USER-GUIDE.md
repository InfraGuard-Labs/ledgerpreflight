# User guide

LedgerPreflight 0.1.0 is a standalone Linux-first CLI for headless servers accessed over SSH. The release validation matrix targets Ubuntu 18.04, 20.04, 22.04 and 24.04 LTS x86_64; consult the release validation results for measured outcomes. It assesses supplied artifacts without starting or stopping Corda, executing CorDapps, accessing a database, or changing node configuration. Provide a current node directory and a prepared target upgrade kit. TVU evidence is optional for static assessment and required for final readiness.

## Run on Ubuntu

Running ledger-preflight without arguments in a terminal prompts for the current node and target kit, then opens the existing assessment flow. Blank input cancels. CI and redirected sessions print usage guidance without prompting.

Extract the Linux release archive into a directory your account can read and execute, then run the included `ledger-preflight` launcher. The primary Linux archive includes its own Java 17 runtime, so a machine with Java 8 or no system Java does not require a system Java change. The separate JAR-only distribution requires an explicitly selected Java 17 runtime. No browser, graphical desktop, Jenkins installation or plugin is required. Use absolute Linux paths when invoking the CLI over SSH or from shell jobs. The CLI writes a concise status and findings to the terminal and returns a documented exit code.

```sh
ledger-preflight assess \
  --node /srv/preflight/current-node \
  --upgrade-kit /srv/preflight/upgrade-kit \
  --output /srv/preflight/reports --offline
```

Use an unprivileged account with read access to the supplied artifacts and write access only to the separate report directory. Parent directories need traversal permission. Read-only bind mounts provide additional enforcement in Docker; ordinary file permissions and a controlled copy provide the corresponding boundary for the standalone CLI. Do not run as root merely to bypass input or output permissions. Development, compilation and release validation for this repository run inside Docker; end users may run the packaged Linux CLI directly with its bundled runtime.

Keep four different facts separate: the Java running LedgerPreflight, the current host/node Java evidence, the target Corda requirement for Java 17, and whether the planned target deployment actually meets that requirement. Running the analyzer with its bundled Java 17 does not prove the target node or external verifier will use Java 17. Host Java 8 remains useful inventory evidence and is not a reason to replace the host Java during preflight.

## How to use LedgerPreflight during a Corda 4.11 → 4.12 upgrade

Follow the [official Enterprise upgrade guide](https://docs.r3.com/en/platform/corda/4.12/enterprise/upgrade-guide.html) to prepare the intended target artifacts. Keep the current node intact during preflight. Use a consistent copy or snapshot if files might change during inspection. Place the intended runtime, TVU and rebuilt custom CorDapps in a kit:

```text
upgrade-kit/
  corda-target.jar
  transaction-validator.jar
  cordapps/
    contracts.jar
    workflows.jar
  legacy-jars/             # required historical dependencies, where applicable
  legacy-contracts/        # old contracts for a mixed-network node deployment
```

Artifact metadata and contained classes drive discovery; filenames alone cannot establish a trustworthy version. Do not bundle or redistribute licensed Enterprise artifacts with this tool.

Run a static assessment with read-only input mounts and a writable output directory outside the inputs:

```sh
docker build --platform linux/amd64 -t ledgerpreflight:0.1.0 .
mkdir -p reports
docker run --rm --network none \
  -v /safe/current-node:/node:ro \
  -v /safe/upgrade-kit:/upgrade-kit:ro \
  -v "$PWD/reports:/reports" \
  ledgerpreflight:0.1.0 assess \
  --node /node --upgrade-kit /upgrade-kit --output /reports --offline
```

For an end user with Java 17, the equivalent is:

```sh
java -jar ledger-preflight-0.1.0.jar assess \
  --node /safe/current-node --upgrade-kit /safe/upgrade-kit --output ./reports --offline
```

Resolve findings, prepare and run required TVU validation according to R3's operational instructions, then reassess with its complete results:

```sh
ledger-preflight assess --node /safe/current-node --upgrade-kit /safe/upgrade-kit \
  --tvu-results /safe/tvu-evidence --output ./reports-with-tvu --offline
```

In Docker, mount that evidence read-only and use its container path. Multiple `--tvu-results` arguments are accepted. Logs and error ZIPs from one validation run belong together. Avoid mixing runs, especially successful summaries and older failures.

The workflow is: official guide → prepare kit → assess → resolve findings → required TVU → reassess with evidence → continue official upgrade procedure → lower-environment testing → production change process. LedgerPreflight v0.1.0 never executes TVU. Run TVU separately using the official procedure and import the resulting evidence; no migration, shutdown or production change is performed by this tool.

The normal result screen uses NOT READY TO UPGRADE for blockers, incomplete evidence and required warning reviews. JSON keeps these causes distinct.

## Readiness and exit codes

| Status | Meaning | Exit |
| --- | --- | --- |
| BLOCKED | A supplied artifact or validation result establishes a blocker | 2 |
| UNKNOWN | Evidence or coverage is insufficient | 4 |
| WARNING | Review is required; uncertainty or risk remains | 1 |
| READY FOR TVU | Static checks have no outstanding findings; required TVU is still missing | 1 |
| READY TO UPGRADE | Static checks are clear and supplied TVU establishes complete success | 0 |

Errors exit 3. Exit 0 represents final readiness for the supplied inputs and evidence. A log file is not authenticated, signatures are not comprehensively validated, and historical database coverage cannot be reconstructed from installed CorDapps. Keep artifact hashes, TVU run provenance and your operational approvals together. A report is not R3 certification.

## Reports and investigation

The terminal is the primary interface. `report.html` is an optional self-contained executive report summarizing blockers, evidence and next actions; copy it through your approved file-transfer process to a workstation if the server is headless. No web server or dashboard runs. `report.json` and `assessment.json` provide machine-readable findings. Each finding identifies evidence, impact, next action, confidence and source. A warning about an internal API is distinct from an exact missing-member blocker. A TVU missing-table message does not establish physical table absence.

```sh
ledger-preflight inventory --node /safe/current-node
ledger-preflight analyze-jar /safe/upgrade-kit/cordapps/contracts.jar
ledger-preflight compare-runtime --source /safe/old-runtime --target /safe/new-runtime
ledger-preflight analyze-tvu /safe/tvu-evidence
ledger-preflight explain LP-API-001
ledger-preflight rules list
ledger-preflight support-bundle --assessment ./reports-with-tvu --output ./support.zip
```

Use `--target-corda`, `--tvu-jar`, `--target-cordapps`, `--legacy-jars` and `--node-conf` only for unusual layouts. `--verifier-classpath` accepts a supplied verifier command/class-loading evidence file. `--rule-pack` adds constrained local rules; see [Rule engine](RULE-ENGINE.md). `--support-bundle` on `assess` creates a sanitized bundle alongside reports. Never put reports inside the input directories. Quote Linux paths containing spaces and use container paths for mounted files.

See [Troubleshooting](TROUBLESHOOTING.md), [TVU analysis](TVU-ANALYSIS.md), [bytecode analysis](BYTECODE-ANALYSIS.md), and the [documentation crosswalk](R3-DOCUMENTATION-CROSSWALK.md).
