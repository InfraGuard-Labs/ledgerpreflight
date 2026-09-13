#!/bin/sh
# Exercise the released launcher and real synthetic validator in clean Ubuntu.
set -eu
. /etc/os-release
test "$ID" = ubuntu
test "$(uname -m)" = x86_64
test "$(id -u)" != 0
if command -v java >/dev/null 2>&1; then printf 'Expected no installed Java\n' >&2;exit 1;fi
mkdir -p /tmp/lp
if [ ! -x /tmp/lp/ledger-preflight-0.1.0/ledger-preflight ]; then tar -xzf /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz -C /tmp/lp;fi
app=/tmp/lp/ledger-preflight-0.1.0/ledger-preflight
"$app" --version
assess(){ "$app" assess --node "$base/node" --upgrade-kit "$base/kit" --host-environment "$base/host.json" --verifier-classpath "$base/classpath.txt" --network-mode all-4.12 --output "$output" --json "$@"; }
for mode in failed success; do
  base=/tmp/guided-tvu-$mode
  mkdir -p "$base"
  cp -a /dist/synthetic/guided-tvu/"$mode"/node /dist/synthetic/guided-tvu/"$mode"/kit /dist/synthetic/guided-tvu/"$mode"/host.json /dist/synthetic/guided-tvu/"$mode"/classpath.txt "$base/"
  chmod -R a-w "$base/node" "$base/kit"
  test ! -w "$base/node";test ! -w "$base/kit"
  out=/output/guided-tvu-$mode-$VERSION_ID
  export SYNTHETIC_TVU_CONTROL=$out.observations
  mkdir -p "$SYNTHETIC_TVU_CONTROL"
  find "$base/node" "$base/kit" -type f -exec sha256sum '{}' \; | sort > "$out.inputs-before.sha256"
  output=$out.static
  set +e
  assess > "$out.static.json" 2> "$out.static.stderr"
  static_code=$?
  set -e
  if [ "$mode" = failed ];then test "$static_code" = 2;else test "$static_code" = 1;fi
  test ! -e "$SYNTHETIC_TVU_CONTROL/started.pid"
  test ! -d "$output/tvu"
  grep -qF 'AUTO_CONFIGURABLE' "$out.static.json"
  output=$out.refused
  set +e
  assess --run-tvu > "$out.refused.stdout" 2> "$out.refused.stderr"
  refused_code=$?
  set -e
  test "$refused_code" = 3
  grep -qF -- '--confirm-isolated-db' "$out.refused.stderr"
  test ! -e "$SYNTHETIC_TVU_CONTROL/started.pid"
  test ! -d "$output/tvu"
  output=$out
  set +e
  assess --run-tvu --confirm-isolated-db --support-bundle > "$out.json" 2> "$out.stderr" &
  shell_pid=$!
  set -e
  count=0
  until test -s "$SYNTHETIC_TVU_CONTROL/observed.properties"; do
    count=$((count+1));test "$count" -lt 900
    kill -0 "$shell_pid" 2>/dev/null || break
    sleep 0.1
  done
  test -s "$SYNTHETIC_TVU_CONTROL/observed.properties"
  # The validator records the actual inherited JVM flags, not a wrapper default.
  grep -qF -- '-Xmx256m' "$SYNTHETIC_TVU_CONTROL/observed.properties"
  set +e
  wait "$shell_pid"
  code=$?
  set -e
  if [ "$mode" = failed ];then test "$code" = 2;expected=BLOCKED;else test "$code" = 0;expected='READY TO UPGRADE';fi
  printf '%s\n' "$code" > "$out.exit.txt"
  grep -Eq '"status"[[:space:]]*:[[:space:]]*"'"$expected"'"' "$out.json"
  grep -qF 'HANDLED' "$out.json"
  grep -qF 'workspaceCleaned' "$out/tvu-run.json"
  test -s "$out/tvu-schema-execution.json"
  test -s "$out/support.zip"
  test -s "$out/support.zip.sha256"
  test -z "$(find "$out/tvu" -maxdepth 1 -name '.workspace-*' -print)"
  grep -qF 'workspaceMode=rwx------' "$SYNTHETIC_TVU_CONTROL/observed.properties"
  grep -qF 'configMode=rw-------' "$SYNTHETIC_TVU_CONTROL/observed.properties"
  grep -qF 'loadedSchema="ExampleSchema"' "$SYNTHETIC_TVU_CONTROL/observed.properties"
  validator_pid=$(cat "$SYNTHETIC_TVU_CONTROL/started.pid")
  if kill -0 "$validator_pid" 2>/dev/null;then printf 'Validator left running\n' >&2;exit 1;fi
  find "$base/node" "$base/kit" -type f -exec sha256sum '{}' \; | sort > "$out.inputs-after.sha256"
  cmp "$out.inputs-before.sha256" "$out.inputs-after.sha256"
  if grep -Eq 'SyntheticGuidedCredential42|External verifier process started|unable to verify with external verifier|Exception in thread|OutOfMemoryError' "$out.stderr" "$out.static.stderr";then exit 1;fi
  if grep -qF 'SyntheticGuidedCredential42' "$out.json";then exit 1;fi
  sha256sum /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz > "$out.tarball.sha256"
  printf 'Ubuntu %s guided %s: static and refused runs start no process; confirmed packaged private Java -Xmx256m; private permissions; source/kit unchanged; schema HANDLED; automatic log/ZIP analysis; safe support package; exit %s PASS.\n' "$VERSION_ID" "$mode" "$code" > "$out.validation.txt"
  cat "$out.validation.txt"
done
