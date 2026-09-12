#!/bin/sh
set -eu
. /etc/os-release
test "$VERSION_ID" = 18.04
before=$(java -version 2>&1)
printf '%s\n' "$before" | grep '1.8.' >/dev/null
mkdir -p /tmp/app
tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C /tmp/app
app=/tmp/app/ledger-preflight-0.1.0/ledger-preflight
printf '{"sourceHostOs":"Ubuntu 18.04 LTS","plannedTargetJava":"17.0.20"}\n' > /tmp/host-environment.json
set +e
"$app" assess --node /dist/synthetic/clean/current-node --upgrade-kit /dist/synthetic/clean/upgrade-kit --host-environment /tmp/host-environment.json --output /output/ubuntu-18.04-java8-static --offline > /output/ubuntu-18.04-java8-static.txt
result=$?
set -e
test "$result" = 1
"$app" assess --node /dist/synthetic/clean/current-node --upgrade-kit /dist/synthetic/clean/upgrade-kit --host-environment /tmp/host-environment.json --tvu-results /dist/synthetic/clean/tvu.log --output /output/ubuntu-18.04-java8-ready --offline > /output/ubuntu-18.04-java8-ready.txt
after=$(java -version 2>&1)
test "$before" = "$after"
printf 'Ubuntu18.04 existing Java8 unchanged; bundled Java17 assessment succeeds; declared targetJava17 remains separate.\n' > /output/ubuntu-18.04-java8.validation.txt
cat /output/ubuntu-18.04-java8.validation.txt
mkdir -p /tmp/lite
tar -xzf /dist/ledger-preflight-0.1.0.tar.gz -C /tmp/lite
set +e
/tmp/lite/ledger-preflight-0.1.0/ledger-preflight version 2> /output/java8-jar-only-message.txt
result=$?
set -e
test "$result" = 3
grep 'bundled runtime' /output/java8-jar-only-message.txt >/dev/null
