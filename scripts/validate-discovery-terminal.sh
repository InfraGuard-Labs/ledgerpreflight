#!/bin/sh
# Real PTYs and the bundled executable in a clean Ubuntu base. No installed tooling.
set -eu
mkdir -p /tmp/discovery-terminal/app
cp -a /dist/synthetic/product-acceptance/environment /tmp/discovery-terminal/fixture
tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C /tmp/discovery-terminal/app
app=/tmp/discovery-terminal/app/ledger-preflight-0.1.0/ledger-preflight
base=/tmp/discovery-terminal/fixture
# shellcheck source=/dev/null
. /etc/os-release
# Remove only this container version's prior harness transcripts before waiting for output.
rm -f /output/discovery-terminal-"$VERSION_ID"-*.txt /output/discovery-terminal-"$VERSION_ID".validation.txt
hide=$(printf '\033[?25l')
show=$(printf '\033[?25h')
command="$app assess --node $base/current-node --upgrade-kit $base/upgrade-kit --host-environment $base/host.json"
wait_text() {
  count=0
  until grep -qF "$2" "$1" 2>/dev/null; do
    count=$((count+1))
    if [ "$count" -ge 600 ]; then printf '\003'; return 1; fi
    sleep 0.1
  done
}
for locale in C C.UTF-8; do
  file=/output/discovery-terminal-$VERSION_ID-$locale.txt
  (wait_text "$file" "$hide"; printf q) | env TERM=xterm-256color LANG="$locale" LC_ALL="$locale" timeout --preserve-status --kill-after=3s 60s script -q -e -f -c "exec $command --output /tmp/discovery-terminal/reports" "$file" >/dev/null
  for expected in ExampleIssuer 4.11.6 4.12.11 ExampleMixedCaseIssuer '2 current' '2 target' '> Continue' '2 detected'; do grep -qF "$expected" "$file"; done
  grep -qF "$hide" "$file";grep -qF "$show" "$file"
  if grep -q 'Discovery confidence\|Other JARs\|❯\|□\|■\|▶' "$file"; then
    printf 'Unexpected discovery detail or unsupported menu cursor\n' >&2
    exit 1
  fi
done
# Arrow selection activates the environment Exit choice.
(wait_text "/output/discovery-terminal-$VERSION_ID-arrows.txt" "$hide"; printf '\033[B\r') | env TERM=xterm-256color timeout --preserve-status --kill-after=3s 60s script -q -e -f -c "exec $command --output /tmp/discovery-terminal/arrows" "/output/discovery-terminal-$VERSION_ID-arrows.txt" >/dev/null
grep -qF '> Exit' "/output/discovery-terminal-$VERSION_ID-arrows.txt"
grep -qF "$show" "/output/discovery-terminal-$VERSION_ID-arrows.txt"
for signal in interrupt terminate; do
  file=/output/discovery-terminal-$VERSION_ID-$signal.txt
  set +e
  if [ "$signal" = interrupt ]; then
    (wait_text "$file" "$hide"; printf '\003'; sleep 1) | env TERM=xterm-256color timeout --preserve-status --kill-after=3s 60s script -q -e -f -c "exec $command --output /tmp/discovery-terminal/interrupt" "$file" >/dev/null
    code=$?;expected=130
  else
    (wait_text "$file" "$hide"; kill -TERM "$(cat /tmp/discovery-terminal/java.pid)") | env TERM=xterm-256color timeout --preserve-status --kill-after=3s 60s script -q -e -f -c "echo \$\$ > /tmp/discovery-terminal/java.pid; exec $command --output /tmp/discovery-terminal/terminate" "$file" >/dev/null
    code=$?;expected=143
  fi
  set -e
  test "$code" = "$expected"
  grep -qF "$hide" "$file";grep -qF "$show" "$file"
done
# A post-discovery report-write exception must leave the cursor visible.
set +e
(wait_text "/output/discovery-terminal-$VERSION_ID-exception.txt" "$hide"; printf '\r') | env TERM=xterm-256color timeout --preserve-status --kill-after=3s 60s script -q -e -f -c "exec $command --output /proc/ledgerpreflight-unwritable" "/output/discovery-terminal-$VERSION_ID-exception.txt" >/dev/null
code=$?
set -e
test "$code" = 3
grep -qF "$show" "/output/discovery-terminal-$VERSION_ID-exception.txt"
(wait_text "/output/discovery-terminal-$VERSION_ID-plain.txt" 'Choose an action'; printf '2\n') | env TERM=dumb timeout --preserve-status --kill-after=3s 60s script -q -e -f -c "exec $command --plain-terminal --output /tmp/discovery-terminal/plain" "/output/discovery-terminal-$VERSION_ID-plain.txt" >/dev/null
if grep -qF "$hide" "/output/discovery-terminal-$VERSION_ID-plain.txt"; then
  printf 'Plain terminal output must not hide the cursor\n' >&2
  exit 1
fi
set +e
$command --non-interactive --output /tmp/discovery-terminal/noninteractive >"/output/discovery-terminal-$VERSION_ID-noninteractive.txt" 2>/tmp/discovery-terminal/stderr
code=$?
set -e
# This discovery fixture has an unproven mixed-case PostgreSQL schema.
# Static assessment must block it until relevant schema evidence is supplied.
test "$code" = 2
grep -qF 'NOT READY TO UPGRADE' "/output/discovery-terminal-$VERSION_ID-noninteractive.txt"
grep -qF '1 blocker' "/output/discovery-terminal-$VERSION_ID-noninteractive.txt"
grep -qF 'Schema configuration' "/output/discovery-terminal-$VERSION_ID-noninteractive.txt"
grep -qF 'TVU schema configuration is not proven.' "/output/discovery-terminal-$VERSION_ID-noninteractive.txt"
if grep -qF "$(printf '\033')" "/output/discovery-terminal-$VERSION_ID-noninteractive.txt"; then
  printf 'Non-interactive output must not contain terminal control sequences\n' >&2
  exit 1
fi
printf 'Ubuntu %s: 8 environment/cursor cases passed (C, UTF-8, arrows, Ctrl+C, SIGTERM, exception, plain, noninteractive).\n' "$VERSION_ID" > "/output/discovery-terminal-$VERSION_ID.validation.txt"
cat "/output/discovery-terminal-$VERSION_ID.validation.txt"
