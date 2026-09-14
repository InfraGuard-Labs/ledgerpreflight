# Changelog

## 0.1.0

Initial external-evaluation release of the standalone Linux Corda upgrade preflight and existing-TVU analysis CLI.

- Discover current/target runtimes, platform versions, Java requirements and CorDapps.
- Check exact runtime classes/members, relevant verifier contexts, internal API use and legacy duplicates.
- Inspect HOCON database/schema declarations and imported schema-loading evidence.
- Parse existing TVU logs/error ZIPs and correlate supplied detailed failures with compatibility findings.
- Export technical reports and sanitized support evidence with checksums.
- Bundle private Java 17 for Linux x86_64 without changing the node's Java installation.

TVU execution is outside the v0.1.0 release interface and distribution. The tool performs no upgrade or database operation. Release checks use synthetic inputs and Docker-only development tools.
