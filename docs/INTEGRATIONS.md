# CI integration

LedgerPreflight is a standalone Linux x86_64 CLI, including headless SSH operation. Its release validation matrix targets Ubuntu 18.04, 20.04 and 22.04. CI integration is optional shell invocation of that CLI or its container image. The primary Linux archive bundles Java 17 and does not require changing a runner's system Java. Keep proprietary artifacts in your authorized private artifact store, outside source control. LedgerPreflight has no CI plugins, web dashboard or upload service. Retain sanitized output using your existing CI policy; HTML is a secondary executive report.

Exit codes are 0 for `READY TO UPGRADE`, 1 for warnings or `READY FOR TVU`, 2 for blockers, 3 for errors and 4 for unknown. Fail on nonzero for a final upgrade gate. The following examples inspect static inputs and consequently cannot return final success until `--tvu-results` supplies complete successful validation. A preparation-only stage can inspect `status == "READY FOR TVU"` in `report.json` to distinguish it from other exit-1 outcomes.

## Generic shell

On an Ubuntu runner with the packaged Linux CLI and its bundled runtime, invoke the same command used over SSH:

```sh
ledger-preflight assess --node /srv/preflight/current-node \
  --upgrade-kit /srv/preflight/upgrade-kit --output /srv/preflight/reports --offline
```

Alternatively, use read-only input mounts with the runtime container:

```sh
mkdir -p reports
docker run --rm --network none \
  -v "$PWD/current-node:/node:ro" \
  -v "$PWD/upgrade-kit:/upgrade-kit:ro" \
  -v "$PWD/reports:/reports" \
  ledgerpreflight:0.1.0 assess --node /node --upgrade-kit /upgrade-kit --output /reports --offline
```

The non-root image needs write permission on the mounted report directory. Set ownership through your runner provisioning or use an approved compatible user mapping. Inputs stay read-only.

## Jenkins

This is an optional shell step in an existing Jenkins installation. No LedgerPreflight Jenkins plugin is required or provided.

```groovy
stage('Upgrade preflight') {
  steps {
    sh '''
      mkdir -p reports
      docker run --rm --network none \\
        -v "$WORKSPACE/current-node:/node:ro" \\
        -v "$WORKSPACE/upgrade-kit:/upgrade-kit:ro" \\
        -v "$WORKSPACE/reports:/reports" \\
        ledgerpreflight:0.1.0 assess --node /node --upgrade-kit /upgrade-kit --output /reports --offline
    '''
  }
  post { always { archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true } }
}
```

## GitHub Actions

Use a self-hosted runner with Docker, the locally built image and synthetic or privately staged authorized inputs. This example publishes nothing externally.

```yaml
name: Upgrade preflight
on: workflow_dispatch
jobs:
  preflight:
    runs-on: self-hosted
    steps:
      - name: Inspect prepared local artifacts
        shell: bash
        run: |
          mkdir -p reports
          docker run --rm --network none \
            -v "$PWD/current-node:/node:ro" \
            -v "$PWD/upgrade-kit:/upgrade-kit:ro" \
            -v "$PWD/reports:/reports" \
            ledgerpreflight:0.1.0 assess --node /node --upgrade-kit /upgrade-kit --output /reports --offline
```

## GitLab CI

Use a shell runner tagged `docker-local` with the image and inputs already staged. Docker-in-Docker and privileged mode are unnecessary.

```yaml
preflight:
  tags: [docker-local]
  script:
    - mkdir -p reports
    - >-
      docker run --rm --network none
      -v "$CI_PROJECT_DIR/current-node:/node:ro"
      -v "$CI_PROJECT_DIR/upgrade-kit:/upgrade-kit:ro"
      -v "$CI_PROJECT_DIR/reports:/reports"
      ledgerpreflight:0.1.0 assess --node /node --upgrade-kit /upgrade-kit --output /reports --offline
```

Do not grant CI access to live database credentials merely to run static preflight. Reports can contain sensitive architecture and artifact names even after secret redaction; distribute them according to your existing policy.
