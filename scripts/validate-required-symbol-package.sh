#!/bin/sh
# Actual standalone launcher proof in an unmodified Ubuntu base. Run after run-a package checks.
set -eu
# shellcheck source=/dev/null
. /etc/os-release
test "$(uname -m)" = x86_64
test "$(id -u)" != 0
if command -v java >/dev/null 2>&1; then
  printf 'Expected clean Ubuntu without installed Java\n' >&2
  exit 1
fi
mkdir -p /tmp/run-a-package
if [ ! -x /tmp/run-a-package/ledger-preflight-0.1.0/ledger-preflight ]; then
  tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C /tmp/run-a-package
fi
app=/tmp/run-a-package/ledger-preflight-0.1.0/ledger-preflight
"$app" --version
source=/dist/synthetic/required-symbols/blocked
base=/tmp/required-symbol-fixture
mkdir -p "$base"
# Copy assessment inputs only. Supplied TVU result files and asserted reports stay outside this run.
cp -a "$source/current-node" "$source/upgrade-kit" "$source/host.json" "$source/classpath.txt" "$base/"
out=/output/required-symbols-$VERSION_ID
file=$out.ansi
command="$app assess --node $base/current-node --upgrade-kit $base/upgrade-kit --host-environment $base/host.json --verifier-classpath $base/classpath.txt --network-mode all-4.12 --output $out"
rm -f "$file"
hide=$(printf '\033[?25l');show=$(printf '\033[?25h')
wait_new(){
  count=0
  until tail -c +"$1" "$file" 2>/dev/null | grep -qF "$2"; do
    count=$((count+1));test "$count" -lt 900 || return 1;sleep 0.1
  done
}
position(){ wc -c < "$file" | awk '{print $1+1}'; }
drive(){
  set -e
  wait_new 1 '> Continue'
  tr '\000' '\n' < /proc/"$(cat /tmp/run-a-package/required-symbol.pid)"/cmdline > "$out.command.txt"
  at=$(position);printf '\r'
  wait_new "$at" '> Import existing TVU results'
  at=$(position);printf 'j\r'
  wait_new "$at" 'Method missing'
  wait_new "$at" '> Back'
  at=$(position);printf '\r'
  wait_new "$at" '> Import existing TVU results'
  # Import precedes compatibility, schema, export and support.
  at=$(position);printf 'jjj\r'
  wait_new "$at" 'Technical report exported'
  wait_new "$at" '> Back'
  at=$(position);printf '\r'
  wait_new "$at" '> Import existing TVU results'
  at=$(position);printf 'jjjj\r'
  wait_new "$at" 'READY TO SHARE'
  wait_new "$at" '> Back'
  at=$(position);printf '\r'
  wait_new "$at" '> Import existing TVU results'
  printf q
  sleep 1
}
set +e
drive | env TERM=xterm-256color LANG=C.UTF-8 LC_ALL=C.UTF-8 timeout --preserve-status --kill-after=3s 150s script -q -e -f -c "echo \$\$ > /tmp/run-a-package/required-symbol.pid; exec $command" "$file" > /dev/null
code=$?
set -e
printf '%s\n' "$code" > "$out.exit.txt"
test "$code" = 2
grep -qx -- '-Xmx256m' "$out.command.txt"
for expected in 'NODE DISCOVERED' '4.11.6' 'Platform 13' '4.12.11' 'Platform 140' '1.8.0_242' 'PostgreSQL' 'ExampleSchema' '2 current' '2 target' 'TVU          Found' 'NOT READY TO UPGRADE' 'CorDapp compatibility' 'WHAT HAPPENED' 'WHY IT MATTERS' 'WHAT TO DO' 'COMPATIBILITY EVIDENCE' 'example-old-contract.jar' 'org.example.runtime.Amounts.total(Iterable)' 'Referenced by 3 source classes' 'Current runtime' 'Class found' 'Method found' 'Target runtime' 'Method missing' 'Technical report exported' 'READY TO SHARE' 'Session complete'; do
  grep -qF "$expected" "$file"
done
grep -qF "$hide" "$file";grep -qF "$show" "$file"
if grep -Eq 'Run TVU safely|Run TVU again|Exact execution command|OutOfMemoryError|Exception in thread|Compatibility analysis incomplete|View technical evidence|View full technical report|View TVU evidence|currentInventory|LP-API|LP-INPUT|LP-ANALYSIS|Ljava/|[0-9]+ warnings|650 processed|201 failed|Transactions processed' "$file"; then
  printf 'Unexpected diagnostic noise or invented TVU result in packaged output\n' >&2
  exit 1
fi
test -s "$out/report.json"
test -s "$out/required-symbol-resolution.json"
test -s "$out/technical-assessment.txt"
test -s "$out/report.html"
sha256sum /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz > "$out.tarball.sha256"
printf 'Ubuntu %s: bundled launcher; no installed Java; non-root; Environment -> Continue -> confirmed missing method -> human evidence -> technical export -> sanitized support -> exit 2 PASS; actual -Xmx256m confirmed.\n' "$VERSION_ID" > "$out.validation.txt"
cat "$out.validation.txt"
