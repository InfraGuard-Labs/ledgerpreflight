# Report format

JSON report schemaVersion is `1`, productVersion `0.1.0`. Top-level fields are status, sourceVersion, targetVersion, findings and evidence. Findings contain id, title, severity, category, status, confidence, source, affectedArtifact, technicalEvidence, impact, explanation, recommendedNextAction and documentationReference.

Findings sort by severity, ID, artifact and evidence. Arrays and maps are deterministically ordered. Assessment IDs are deterministic; timestamps record assessment creation. Identical input bytes and paths produce identical findings and report content apart from timestamps. Artifact SHA-256 values identify assessed bytes. Relative input paths avoid automatic collection of host directory names.

JSON and HTML contain sanitized generated evidence, not raw configuration/logs. HTML escapes all dynamic text, embeds styles and a restrictive Content Security Policy, and has no scripts or external resources. Renderers must not reinterpret report strings as HTML or command arguments.

Exit codes: 0 for READY TO UPGRADE, 1 WARNING or READY FOR TVU, 2 BLOCKED, 3 tool/configuration error, 4 UNKNOWN; picocli syntax errors also use 2. To require final upgrade readiness, compare status exactly with READY TO UPGRADE.

The adjacent schema file documents required fields for downstream validation. This format is versioned independently of vendor rule-pack versions.
