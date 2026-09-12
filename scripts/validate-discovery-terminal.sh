#!/bin/sh
# Packaged runtime and real PTYs in clean Ubuntu containers; no extra dependencies.
set -eu
mkdir -p /tmp/discovery-terminal/app
cp -a /dist/synthetic/discovery-regression /tmp/discovery-terminal/fixture
tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C /tmp/discovery-terminal/app
app=/tmp/discovery-terminal/app/ledger-preflight-0.1.0/ledger-preflight
node=/tmp/discovery-terminal/fixture/current-node
kit=/tmp/discovery-terminal/fixture/upgrade-kit
. /etc/os-release
for locale in C C.UTF-8; do
  file=/output/discovery-terminal-$VERSION_ID-$locale.txt
  (sleep 2; printf q; sleep 2) | env TERM=xterm-256color LANG="$locale" LC_ALL="$locale" script -q -e -c "$app assess --node $node --upgrade-kit $kit --output /tmp/discovery-terminal/reports" "$file"
  grep -q 'ExampleIssuer' "$file"
  grep -q '4.11.6' "$file"
  grep -q '4.12.11' "$file"
  grep -q 'ExampleMixedCaseIssuer' "$file"
  grep -q '2 current' "$file"
  grep -q '2 target' "$file"
  grep -q 'Discovery confidence: HIGH' "$file"
  grep -q '> Continue assessment' "$file"
  ! grep -q '❯\|□\|■\|▶' "$file"
done
(sleep 2; printf '3\n'; sleep 2) | env TERM=dumb script -q -e -c "$app assess --node $node --upgrade-kit $kit --plain-terminal --output /tmp/discovery-terminal/plain" /output/discovery-terminal-$VERSION_ID-plain.txt
printf 'Ubuntu %s: discovery identity and ASCII cursor in C/UTF-8/plain selection passed.\n' "$VERSION_ID"
