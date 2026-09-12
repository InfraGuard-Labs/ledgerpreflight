#!/bin/sh
# Run this INSIDE the Ubuntu22.04 build image, with networking disabled.
set -eu
cd /workspace
. /etc/os-release
test "$VERSION_ID" = 22.04
test "$(uname -m)" = x86_64
sh scripts/package-release.sh
mkdir -p /dist/test-results /dist/synthetic /dist/offline
cp -a build/test-results/test/. /dist/test-results/
cp -a build/synthetic/. /dist/synthetic/
expect() {
  expected=$1
  shift
  set +e
  "$@"
  actual=$?
  set -e
  if [ "$actual" -ne "$expected" ]; then
    printf 'Expected exit %s; received %s\n' "$expected" "$actual" >&2
    exit 1
  fi
}
for label in repeat-a repeat-b; do
  expect 2 java -Xmx512m -jar /dist/ledger-preflight-0.1.0.jar assess \
    --node /dist/synthetic/replay/current-node --upgrade-kit /dist/synthetic/replay/upgrade-kit \
    --tvu-results /dist/synthetic/replay/tvu.log --tvu-results /dist/synthetic/replay/errors.zip \
    --verifier-classpath /dist/synthetic/replay/classpath.txt --output "/dist/offline/$label" --offline > "/dist/offline/$label.txt"
done
expect 1 java -jar /dist/ledger-preflight-0.1.0.jar assess --node /dist/synthetic/clean/current-node --upgrade-kit /dist/synthetic/clean/upgrade-kit --output /dist/offline/static --offline > /dist/offline/static.txt
expect 0 java -jar /dist/ledger-preflight-0.1.0.jar assess --node /dist/synthetic/clean/current-node --upgrade-kit /dist/synthetic/clean/upgrade-kit --tvu-results /dist/synthetic/clean/tvu.log --output /dist/offline/ready --offline > /dist/offline/ready.txt
rm -f /dist/offline/repeat-a/support.zip
java -jar /dist/ledger-preflight-0.1.0.jar support-bundle --assessment /dist/offline/repeat-a --output /dist/offline/repeat-a/support.zip
printf 'Ubuntu %s %s: packaged launcher, tests, replay, readiness, repeat and support checks passed.\n' "$VERSION_ID" "$(uname -m)" > /dist/linux-validation.txt
cat /dist/linux-validation.txt
