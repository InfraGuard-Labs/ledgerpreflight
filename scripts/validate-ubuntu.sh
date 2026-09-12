#!/bin/sh
# Run in a clean Ubuntu base container. No apt, Java, or dependency installation.
set -eu
. /etc/os-release
test "$(uname -m)" = x86_64
if command -v java >/dev/null 2>&1; then
  echo 'Expected clean Ubuntu without system Java' >&2
  exit 1
fi
mkdir -p /tmp/lp-distribution
# Extract into a directory containing spaces to exercise shell quoting.
mkdir -p '/tmp/lp-distribution/with spaces'
tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C '/tmp/lp-distribution/with spaces'
app='/tmp/lp-distribution/with spaces/ledger-preflight-0.1.0/ledger-preflight'
"$app" version
set +e
"$app" assess --node /dist/synthetic/replay/current-node --upgrade-kit /dist/synthetic/replay/upgrade-kit --tvu-results /dist/synthetic/replay/tvu.log --tvu-results /dist/synthetic/replay/errors.zip --verifier-classpath /dist/synthetic/replay/classpath.txt --output "/output/ubuntu-$VERSION_ID" --offline > "/output/ubuntu-$VERSION_ID.txt"
result=$?
set -e
test "$result" = 2
! command -v java >/dev/null 2>&1
printf 'Ubuntu %s x86_64: bundled launcher runs without system Java; replay exit2; system Java remains absent.\n' "$VERSION_ID" > "/output/ubuntu-$VERSION_ID.validation.txt"
cat "/output/ubuntu-$VERSION_ID.validation.txt"
