# Rule engine

The bundled pack is `2026.09.12`. Evaluation takes an immutable view of extracted facts and produces findings in rule ID order. Conditions within a rule are ANDed. Vendor requirements apply only to exact Corda version family `4.12`; `4.120` does not match. Evidence-derived compatibility checks run independently of version assumptions. Unknown versions produce coverage findings and must never become a ready result.

Facts are strings, and missing, blank or `UNKNOWN` facts are unknown. Unknown does not satisfy `NOT_EQUALS`. The absence of a warning is therefore not proof that a prerequisite was checked. Overall readiness separately requires sufficient static coverage and complete successful TVU evidence. Informational Java/Kotlin/platform requirements report what the target requires, not what an uninspected deployment has installed.

| Fact | Value and meaning |
| --- | --- |
| source.version, target.version | Identified version such as `4.11.6`, `4.12.11`; filenames alone are weak evidence |
| target.java | Planned target Java major, e.g. `17`; never analyzer Java |
| target.kotlin | Evidenced compiler/toolchain version, e.g. `1.9.20` |
| target.platform | Target manifest platform value, expected `140` for 4.12 |
| tvu.present | `true` / `false`, artifact discovery |
| tvu.schemaVersion | Supplied database schema version; not established by database connection |
| network.mode | `mixed` / `all-4.12` / `UNKNOWN` |
| legacyContracts.present, legacyJars.present | `true` / `false`, prepared kit presence |
| legacyDependencies.required | `true` only with dependency evidence |
| constraints.hashDetected | `true` when hash constraint references occur; not persisted-state proof |
| constraints.explicitUpgradeDetected | `true` for relevant explicit contract-upgrade references |
| verification.legacyPattern | `true` for conversion/verify call pattern requiring review |
| cordapps.recompiled | `false` for evidenced unchanged or incompatible target CorDapps |
| contract.versionIncreased | `false` for paired contract metadata that has not increased |
| cordapps.minimumPlatform | Prepared CorDapp minimum platform value |
| signing.continuity | `different` / `unproven` / `same`; metadata assessment, not cryptographic assurance |

Use `ledger-preflight explain LP-JAVA-001` to explain a finding. The documentation crosswalk records the vendor rule sources. Bytecode, configuration and TVU analyzers emit additional evidence-derived findings.

## Local rule packs

Use `--rule-pack /input/local-rules.json`. A pack is additive and cannot remove or downgrade bundled rules. No scripts, regex, templates, class loading, external fetches or custom operators run. Files are limited to 1 MiB, 100 rules and 20 conditions per rule. JSON rejects duplicate keys, unknown fields, excess nesting and trailing documents. Rule IDs start `USR-`; duplicate IDs fail closed. Source may be `USER_RULE` or `VENDOR_CONFIRMED_LOCAL`, which records provenance asserted by the local author and does not authenticate it.

```json
{
  "schemaVersion": "1",
  "version": "local-2026-09-12",
  "rules": [{
    "id": "USR-TARGET-REVIEW",
    "title": "Local target review required",
    "severity": "WARNING",
    "category": "UPGRADE_PATH",
    "confidence": "MEDIUM",
    "source": "USER_RULE",
    "impact": "Local qualification remains outstanding.",
    "explanation": "The local change process requires target qualification.",
    "nextAction": "Record the qualification evidence in the change process.",
    "documentationReference": null,
    "conditions": [{"fact": "target.version", "operator": "VERSION_FAMILY", "value": "4.12"}]
  }]
}
```

Allowed severities: `INFO`, `WARNING`, `BLOCKED`, `UNKNOWN`. Confidence: `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `POTENTIAL`. Allowed operators: `EQUALS`, `NOT_EQUALS`, `PRESENT`, `ABSENT`, `VERSION_FAMILY`. `PRESENT` and `ABSENT` use an empty string value. Conditions can reference only the fact keys above. Private rules and licensed validation fixtures belong in the ignored `fixtures/private/` directory; keep private correspondence out of distributable reports.
