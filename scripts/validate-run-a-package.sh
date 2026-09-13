#!/bin/sh
# The shipped private runtime and launcher, in a clean Ubuntu base with no installed tools.
set -eu
. /etc/os-release
mkdir -p /tmp/run-a-package
tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C /tmp/run-a-package
app=/tmp/run-a-package/ledger-preflight-0.1.0/ledger-preflight
"$app" --version
test "$(id -u)" != 0
! command -v java >/dev/null 2>&1
cp -a /dist/synthetic/run-a/normal /tmp/run-a-package/fixture
base=/tmp/run-a-package/fixture
command="$app assess --node $base/current-node --upgrade-kit $base/upgrade-kit --host-environment $base/host.json --verifier-classpath $base/classpath.txt --network-mode all-4.12 --output /output/run-a-$VERSION_ID"
file=/output/run-a-$VERSION_ID.ansi
rm -f "$file"
hide=$(printf '\033[?25l');show=$(printf '\033[?25h')
wait_text(){ count=0; until grep -qF "$2" "$1" 2>/dev/null; do count=$((count+1));test "$count" -lt 900 || return 1;sleep 0.1;done; }
set +e
(wait_text "$file" "$hide";tr '\000' '\n' </proc/"$(cat /tmp/run-a-package/pid)"/cmdline > /output/run-a-$VERSION_ID.command.txt;printf '\r';wait_text "$file" '> View technical evidence';printf q;sleep 1) |
 env TERM=xterm-256color LANG=C.UTF-8 LC_ALL=C.UTF-8 timeout --preserve-status --kill-after=3s 120s script -q -e -f -c "echo \$\$ > /tmp/run-a-package/pid; exec $command" "$file" >/dev/null
code=$?
set -e
test "$code" = 2
grep -qx -- '-Xmx256m' /output/run-a-$VERSION_ID.command.txt
for expected in 'NODE DISCOVERED' '4.11.6' 'Platform 13' '4.12.11' 'Platform 140' 'ExampleSchema' '2 current' '2 target' 'TVU          Found' 'NOT READY TO UPGRADE' 'CorDapp compatibility' 'WHAT HAPPENED' 'WHY IT MATTERS' 'WHAT TO DO' 'Session complete';do grep -qF "$expected" "$file";done
grep -qF "$hide" "$file";grep -qF "$show" "$file"
! grep -q 'OutOfMemoryError\|Exception in thread' "$file"
# Independent symbol-pressure fixture through the same default 256 MiB packaged launcher.
base=/dist/synthetic/run-a/large
set +e
"$app" assess --node "$base/current-node" --upgrade-kit "$base/upgrade-kit" --host-environment "$base/host.json" --verifier-classpath "$base/classpath.txt" --network-mode all-4.12 --output "/output/run-a-$VERSION_ID-limited" --non-interactive >"/output/run-a-$VERSION_ID-limited.txt" 2>"/output/run-a-$VERSION_ID-limited.stderr"
code=$?
set -e
test "$code" = 2 || test "$code" = 4
grep -q 'Compatibility analysis incomplete' "/output/run-a-$VERSION_ID-limited.txt"
! grep -q 'OutOfMemoryError\|Exception in thread' "/output/run-a-$VERSION_ID-limited.stderr"
printf 'Ubuntu %s: packaged Environment -> Continue -> BLOCKED result -> normal exit PASS; actual -Xmx256m confirmed; large-symbol assessment graceful non-ready PASS.\n' "$VERSION_ID" >"/output/run-a-$VERSION_ID.validation.txt"
cat "/output/run-a-$VERSION_ID.validation.txt"
