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
mkdir -p /tmp/validation-inputs
cp -a build/synthetic/. /tmp/validation-inputs/
cp /dist/ledger-preflight-0.1.0.jar /tmp/validation.jar
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
  expect 2 java -Xmx512m -jar /tmp/validation.jar assess \
    --node /tmp/validation-inputs/replay/current-node --upgrade-kit /tmp/validation-inputs/replay/upgrade-kit \
    --tvu-results /tmp/validation-inputs/replay/tvu.log --tvu-results /tmp/validation-inputs/replay/errors.zip \
    --verifier-classpath /tmp/validation-inputs/replay/classpath.txt --output "/dist/offline/$label" --offline > "/dist/offline/$label.txt"
done
expect 1 java -jar /tmp/validation.jar assess --node /tmp/validation-inputs/clean/current-node --upgrade-kit /tmp/validation-inputs/clean/upgrade-kit --output /dist/offline/static --offline > /dist/offline/static.txt
expect 0 java -jar /tmp/validation.jar assess --node /tmp/validation-inputs/clean/current-node --upgrade-kit /tmp/validation-inputs/clean/upgrade-kit --tvu-results /tmp/validation-inputs/clean/tvu.log --output /dist/offline/ready --offline > /dist/offline/ready.txt
rm -f /dist/offline/repeat-a/support.zip
java -jar /tmp/validation.jar support-bundle --assessment /dist/offline/repeat-a --output /dist/offline/repeat-a/support.zip
printf 'Ubuntu %s %s: packaged launcher, tests, replay, readiness, repeat and support checks passed.\n' "$VERSION_ID" "$(uname -m)" > /dist/linux-validation.txt
cat /dist/linux-validation.txt
