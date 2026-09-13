#!/bin/sh
set -eu
# Executed only inside the build/packaging container.
mkdir -p /dist
cp /workspace/build/libs/ledger-preflight-0.1.0.jar /dist/
cp /workspace/build/reports/sbom.cdx.json /dist/sbom.cdx.json
cp /workspace/build/synthetic/example-report/report.html /dist/example-report.html
cp /workspace/build/synthetic/example-report/report.json /dist/example-report.json
cp /workspace/scripts/ledger-preflight /dist/ledger-preflight
chmod 755 /dist/ledger-preflight
mkdir -p /dist/test-report /dist/coverage
cp -a /workspace/build/reports/tests/test/. /dist/test-report/
cp -a /workspace/build/reports/jacoco/test/html/. /dist/coverage/
cp /workspace/build/benchmark/benchmark.csv /dist/benchmark.csv
cp /workspace/build/reports/jacoco/test/jacocoTestReport.xml /dist/coverage/coverage.xml
cp /workspace/docs/RELEASE-NOTES.md /dist/RELEASE_NOTES.md
mkdir -p /tmp/ledger-preflight-0.1.0
cp /dist/ledger-preflight /dist/ledger-preflight-0.1.0.jar /workspace/LICENSE /workspace/THIRD-PARTY-NOTICES /workspace/README.md /tmp/ledger-preflight-0.1.0/
cp -a /workspace/docs /tmp/ledger-preflight-0.1.0/
# Normalize product permissions even when Docker receives a Windows bind mount.
find /tmp/ledger-preflight-0.1.0 -type d -exec chmod 755 {} +
find /tmp/ledger-preflight-0.1.0 -type f -exec chmod 644 {} +
chmod 755 /tmp/ledger-preflight-0.1.0/ledger-preflight
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner -C /tmp -cf - ledger-preflight-0.1.0 | gzip -n > /dist/ledger-preflight-0.1.0.tar.gz
cp -a /opt/ledgerpreflight-jre /tmp/ledger-preflight-0.1.0/runtime
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner -C /tmp -cf - ledger-preflight-0.1.0 | gzip -n > /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz
cd /dist
sha256sum ledger-preflight-0.1.0.jar ledger-preflight-0.1.0.tar.gz ledger-preflight-0.1.0-linux-x86_64.tar.gz sbom.cdx.json example-report.html example-report.json > SHA256SUMS
sha256sum -c SHA256SUMS
