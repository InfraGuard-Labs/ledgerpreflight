# Sanitized support bundles

Generate evidence while assessing, or package a saved assessment later:

```sh
ledger-preflight assess --node /node --upgrade-kit /upgrade-kit --output /reports --offline --support-bundle
ledger-preflight support-bundle --assessment /reports --output LedgerPreflight-support.zip
```

The bundle contains generated `README.txt`, `summary.txt`, `summary.html`, `assessment.json`, `environment.json`, `upgrade-kit.json`, `cordapps-current.json`, `cordapps-target.json`, `runtime-api-delta.json`, `internal-api-usage.json`, `legacy-jars-analysis.json`, `classpath-analysis.json`, `schema-analysis.json`, `tvu-summary.json`, `findings.json`, `reproduction.txt`, `sanitized-node.conf` and `checksums.sha256`, when available in the saved assessment. Checksums cover every entry except the checksum file itself. Archive entries have fixed timestamps for reproducibility.

`sanitized-node.conf` is an allowlisted diagnostic reconstruction of schema declarations. It is not a replacement configuration and must not be deployed. Original node.conf, JARs, keys, keystores, certificates and raw log files are never automatically collected. TVU summaries and normalized error signatures carry the supplied diagnostic evidence; optional raw logs are intentionally not packaged in v1.

Credential fields and assignments are redacted before serialization. JSON is sanitized structurally so redaction does not corrupt its syntax. A final safety scanner checks every prospective entry for recognizable secrets and private-key material. If it finds suspicious content, bundle creation fails before creating the destination ZIP and identifies the permitted filename that triggered rejection. Correct the underlying generated evidence and rerun; there is no bypass flag. An existing destination is never overwritten.

Review the resulting archive through your normal information-sharing process. Automated redaction is defense in depth and cannot recognize every unlabelled secret. LedgerPreflight does not send the archive anywhere. The operator chooses whether and how to submit it to an approved support channel.
