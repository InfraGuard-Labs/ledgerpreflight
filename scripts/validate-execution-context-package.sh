#!/bin/sh
# Exercise the shipped launcher in clean Ubuntu without installing a host Java.
set -eu
# shellcheck source=/dev/null
. /etc/os-release
test "$ID" = ubuntu
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
  tr '\000' '\n' < /proc/"$(cat /tmp/run-a-package/execution-context.pid)"/cmdline > "$out.command.txt"
  at=$(position);printf '\r'
  wait_new "$at" "$first"
  if [ "$variant" != compatible ]; then
    at=$(position);printf '\r'
    wait_new "$at" 'Target verifier'
    wait_new "$at" '> Back'
    tail -c +"$at" "$file" > "$out.compatibility.ansi"
    at=$(position);printf '\r'
    wait_new "$at" "$first"
    at=$(position);printf 'j\r'
    wait_new "$at" 'SCHEMA EVIDENCE'
    wait_new "$at" '> Back'
    tail -c +"$at" "$file" > "$out.schema.ansi"
    at=$(position);printf '\r'
    wait_new "$at" "$first"
  fi
  at=$(position);printf '%s\r' "$export_keys"
  wait_new "$at" 'Technical report exported'
  wait_new "$at" '> Back'
  at=$(position);printf '\r'
  wait_new "$at" "$first"
  at=$(position);printf '%s\r' "$support_keys"
  wait_new "$at" 'READY TO SHARE'
  wait_new "$at" '> Back'
  at=$(position);printf '\r'
  wait_new "$at" "$first"
  printf q
  sleep 1
}
for variant in blocked verifier-only compatible; do
  source=/dist/synthetic/execution-context/$variant
  base=/tmp/execution-context-$variant
  mkdir -p "$base"
  cp -a "$source/node" "$source/kit" "$source/host.json" "$source/classpath.txt" "$base/"
  chmod -R a-w "$base/node" "$base/kit"
  test ! -w "$base/node"
  test ! -w "$base/kit"
  out=/output/execution-context-$variant-$VERSION_ID
  file=$out.ansi
  command="$app assess --node $base/node --upgrade-kit $base/kit --host-environment $base/host.json --verifier-classpath $base/classpath.txt --network-mode all-4.12 --output $out"
  if [ "$variant" = compatible ]; then
    first='> TVU instructions';export_keys=j;support_keys=jj;expected_exit=1;expected_status='READY FOR TVU';schema=example_issuer
  else
    first='> View compatibility evidence';export_keys=jj;support_keys=jjj;expected_exit=2;expected_status=BLOCKED;schema=ExampleSchema
  fi
  rm -f "$file"
  set +e
  drive | env TERM=xterm-256color LANG=C.UTF-8 LC_ALL=C.UTF-8 timeout --preserve-status --kill-after=3s 180s script -q -e -f -c "stty cols 96 rows 56; echo \$\$ > /tmp/run-a-package/execution-context.pid; exec $command" "$file" > /dev/null
  code=$?
  set -e
  printf '%s\n' "$code" > "$out.exit.txt"
  test "$code" = "$expected_exit"
  grep -qx -- '-Xmx256m' "$out.command.txt"
  for expected in 'NODE DISCOVERED' '4.11.6' 'Platform 13' '4.12.11' 'Platform 140' '1.8.0_242' 'PostgreSQL' "$schema" '2 current' '2 target' 'TVU          Found' 'Technical report exported' 'READY TO SHARE' 'Final package rescanned' 'Session complete'; do
    grep -qF "$expected" "$file"
  done
  if [ "$variant" = compatible ]; then
    grep -qF 'READY FOR TVU' "$file"
    if grep -qF 'View compatibility evidence' "$file"; then exit 1; fi
  else
    for expected in 'NOT READY TO UPGRADE' 'CorDapp compatibility' 'WHAT HAPPENED' 'WHY IT MATTERS' 'WHAT TO DO' 'COMPATIBILITY EVIDENCE' 'example-old-contract.jar' 'org.example.runtime.Amounts.total(Iterable)' 'Current runtime' 'Target runtime' 'Target verifier' 'Class found' 'Method found' 'Method missing' 'SCHEMA EVIDENCE' 'Primary / effective schema' 'Why this matters'; do
      grep -qF "$expected" "$file"
    done
    if [ "$variant" = verifier-only ]; then grep -qF 'not available in the target verifier.' "$file"; fi
    if grep -Eq 'example-new-contract.jar|companion-tool.jar|external-verifier.jar|renamed-runtime.bin|Class missing' "$out.compatibility.ansi"; then exit 1; fi
  fi
  grep -qF "$hide" "$file";grep -qF "$show" "$file"
  if grep -Eq 'OutOfMemoryError|Exception in thread|Compatibility analysis incomplete|View technical evidence|View full technical report|View TVU evidence|currentInventory|LP-API|LP-INPUT|LP-ANALYSIS|Ljava/|CURRENT_NODE_RUNTIME|TARGET_NODE_RUNTIME|TARGET_VERIFIER|[0-9]+ warnings|650 processed|201 failed|Transactions processed' "$file"; then
    printf 'Unexpected diagnostics, unresolved context, or invented TVU result\n' >&2
    exit 1
  fi
  for report in report.json required-symbol-resolution.json execution-contexts.json technical-assessment.txt report.html summary.txt; do test -s "$out/$report"; done
  grep -Eq '"status"[[:space:]]*:[[:space:]]*"'"$expected_status"'"' "$out/report.json"
  for context in CURRENT_NODE_RUNTIME TARGET_NODE_RUNTIME TARGET_VERIFIER; do grep -qF "$context" "$out/required-symbol-resolution.json"; done
  sha256sum /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz > "$out.tarball.sha256"
  printf 'Ubuntu %s %s: no installed Java; non-root; read-only node/kit; packaged Environment -> Continue -> %s -> evidence/export/support -> exit %s PASS; actual -Xmx256m confirmed.\n' "$VERSION_ID" "$variant" "$expected_status" "$code" > "$out.validation.txt"
  cat "$out.validation.txt"
  # Only this script's disposable fixture copy is removed; exported evidence is retained.
  chmod -R u+w "$base/node" "$base/kit"
  rm -rf -- "$base"
done
