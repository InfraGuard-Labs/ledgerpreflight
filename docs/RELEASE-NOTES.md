# LedgerPreflight v0.1.0

LedgerPreflight is a Corda upgrade preflight and TVU analysis tool for external evaluation.

It compares a current node with a target upgrade kit, identifies upgrade risks and analyzes existing TVU logs/error bundles to help explain validation failures.

## Highlights

- Current/target Corda and platform discovery, with separate Java requirement evidence.
- Current/target CorDapp discovery and replacement mapping.
- Exact runtime class, method and field checks, including inheritance and relevant verifier contexts.
- PostgreSQL schema risk detection and imported schema-loading evidence.
- Existing TVU summary/error parsing and failure correlation when detailed records match.
- Concise terminal results, technical HTML/JSON/text reports and sanitized support packages.
- Standalone Linux x86_64 distribution with private Java 17; existing node Java remains unchanged.

v0.1.0 does not run TVU, start Corda, execute CorDapps, perform upgrades or change a database. Use it as an additional validation layer alongside the official Corda upgrade procedures.

## Download and verify

Download `ledger-preflight-0.1.0-linux-x86_64.tar.gz` and `SHA256SUMS` from the [v0.1.0 release](https://github.com/InfraGuard-Labs/ledgerpreflight/releases/tag/v0.1.0):

```sh
awk '$2 == "ledger-preflight-0.1.0-linux-x86_64.tar.gz"' SHA256SUMS | sha256sum -c -
tar -xzf ledger-preflight-0.1.0-linux-x86_64.tar.gz
cd ledger-preflight-0.1.0
./ledger-preflight --help
```

Extract only after checksum verification succeeds. The repository's `install.sh` downloads and verifies this version before installation. See [README](../README.md) for static assessment and existing-TVU import commands.

## Evaluation limits

Public tests and examples are synthetic. Static analysis cannot prove reflection, dynamic loading, full signer continuity or complete historical database coverage. Supplied TVU logs are not authenticated or cryptographically bound to the assessed snapshot. Review provenance, coverage and sanitized output before relying on or sharing a result.

The release validation summary records exact tests, Ubuntu/Java environments, artifact hashes and security scan results. Vulnerability results are dated evidence; they are not a guarantee that every bundled component is free of vulnerabilities. The supported evaluation platforms are Ubuntu 18.04, 20.04, 22.04 and 24.04 on x86_64, subject to those measured validation results.
