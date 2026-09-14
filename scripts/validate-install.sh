#!/bin/sh
# Docker-only installer checks with the actual packaged distribution at /dist.
set -eu
sh -n /source/install.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$work/bin" "$work/fixtures"
export INSTALLER_WORK=$work
export SYSTEM_JAVA_SENTINEL=$work/system-java-used
export SYSTEM_JAVA_UNEXPECTED=$work/system-java-unexpected
export INSTALLER_EXEC_SENTINEL=$work/unverified-launcher-used
cat > "$work/bin/curl" <<'MOCK'
#!/bin/sh
set -eu
[ "${CASE:-}" != unavailable ] || exit 22
output=
head=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --head) head=true; shift ;;
    --write-out|--proto|--proto-redir|--connect-timeout|--max-time) shift 2 ;;
    --*) shift ;;
    *) url=$1; shift ;;
  esac
done
base=https://github.com/InfraGuard-Labs/ledgerpreflight/releases
if "$head"; then
  [ "$url" = "$base/latest" ] || exit 22
  if [ "${CASE:-}" = redirect ]; then printf '%s' 'https://example.invalid/releases/tag/v0.1.0'
  else printf '%s' "$base/tag/v0.1.0"; fi
  exit
fi
asset=ledger-preflight-0.1.0-linux-x86_64.tar.gz
source=${TEST_PACKAGE_OVERRIDE:-/dist/$asset}
case "$url" in
  "$base/download/v0.1.0/SHA256SUMS")
    [ "${CASE:-}" != checksum-download ] || exit 22
    case "${CASE:-}" in
      checksum) printf '%064d  %s\n' 0 "$asset" > "$output" ;;
      missing) : > "$output" ;;
      malformed) printf 'not-a-checksum  %s\n' "$asset" > "$output" ;;
      duplicate) sha256sum "$source" | awk -v name="$asset" '{print $1 "  " name;print $1 "  " name}' > "$output" ;;
      *) if [ -n "${TEST_PACKAGE_OVERRIDE:-}" ]; then sha256sum "$source" | awk -v name="$asset" '{print $1 "  " name}' > "$output"; else cp /dist/SHA256SUMS "$output"; fi ;;
    esac ;;
  "$base/download/v0.1.0/$asset") [ "${CASE:-}" != package-download ] || exit 22;cp "$source" "$output" ;;
  *) exit 22 ;;
esac
MOCK
cat > "$work/bin/java" <<'MOCK'
#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = -version ]; then
  printf '%s\n' '-version' >> "$SYSTEM_JAVA_SENTINEL"
  printf 'openjdk version "1.8.0_412"\n' >&2
  exit 0
fi
: > "$SYSTEM_JAVA_UNEXPECTED"
exit 97
MOCK
cat > "$work/bin/ln" <<'MOCK'
#!/bin/sh
if [ "${CASE:-}" = publish-failure ]; then exit 1; fi
exec /usr/bin/ln "$@"
MOCK
cat > "$work/bin/mv" <<'MOCK'
#!/bin/sh
if [ "${CASE:-}" = destination-race ]; then
  for argument do destination=$argument; done
  mkdir "$destination"
  printf 'Concurrent installation\n' > "$destination/preserve.txt"
fi
exec /usr/bin/mv "$@"
MOCK
chmod 755 "$work/bin/"*
export PATH="$work/bin:$PATH"
export JAVA_HOME="$work/system-java8"
expected_path=$PATH
expected_java_home=$JAVA_HOME
system_java_sha=$(sha256sum "$work/bin/java")
verify_system_java_unchanged() {
  test "$PATH" = "$expected_path"
  test "$JAVA_HOME" = "$expected_java_home"
  test "$(sha256sum "$work/bin/java")" = "$system_java_sha"
  test ! -e "$SYSTEM_JAVA_UNEXPECTED"
  test -s "$SYSTEM_JAVA_SENTINEL"
  test -z "$(grep -vx -- '-version' "$SYSTEM_JAVA_SENTINEL")"
}
checks=1
reject() {
  if "$@" > "$work/rejected.log" 2>&1; then cat "$work/rejected.log"; exit 1; fi
  checks=$((checks+1))
}
sh /source/install.sh --help > "$work/help.txt"
grep -q 'Default: v0.1.0' "$work/help.txt"
checks=$((checks+1))
sh /source/install.sh --version 0.1.0 --prefix "$work/with spaces" > "$work/explicit.txt"
test "$("$work/with spaces/bin/ledger-preflight" --version)" = 'LedgerPreflight 0.1.0'
(cd /tmp && "$work/with spaces/bin/ledger-preflight" --help > "$work/installed-help.txt")
grep -q 'assess' "$work/installed-help.txt"
verify_system_java_unchanged
checks=$((checks+1))
reject sh /source/install.sh --version 0.1.0 --prefix "$work/with spaces"
test "$("$work/with spaces/bin/ledger-preflight" --version)" = 'LedgerPreflight 0.1.0'
rm -rf -- "$work/with spaces"
sh /source/install.sh --prefix "$work/default" > "$work/default.txt"
test "$("$work/default/bin/ledger-preflight" --version)" = 'LedgerPreflight 0.1.0'
checks=$((checks+1))
rm -rf -- "$work/default"
sh /source/install.sh --version latest --prefix "$work/latest" > "$work/latest.txt"
test "$("$work/latest/bin/ledger-preflight" --version)" = 'LedgerPreflight 0.1.0'
checks=$((checks+1))
rm -rf -- "$work/latest"
reject sh /source/install.sh --version ../../invalid --prefix "$work/invalid"
reject sh /source/install.sh --prefix relative
reject sh /source/install.sh --version
reject sh /source/install.sh --prefix "$work/quote'prefix"
for scenario in checksum missing malformed duplicate unavailable package-download checksum-download; do
  reject env CASE="$scenario" sh /source/install.sh --prefix "$work/$scenario"
  test ! -e "$work/$scenario"
done
reject env CASE=redirect sh /source/install.sh --version latest --prefix "$work/redirect"
test ! -e "$work/redirect"
mkdir -p "$work/existing/bin"
printf 'Existing operator launcher\n' > "$work/existing/bin/ledger-preflight"
reject sh /source/install.sh --prefix "$work/existing"
grep -qx 'Existing operator launcher' "$work/existing/bin/ledger-preflight"
test ! -e "$work/existing/lib"
mkdir -p "$work/broken/lib/ledgerpreflight"
/usr/bin/ln -s /does-not-exist "$work/broken/lib/ledgerpreflight/0.1.0"
reject sh /source/install.sh --prefix "$work/broken"
test -L "$work/broken/lib/ledgerpreflight/0.1.0"
# Even a checksum-valid malformed archive must fail before any installation.
printf 'not an archive\n' > "$work/fixtures/invalid.tar.gz"
mkdir "$work/fixtures/other"
printf 'payload\n' > "$work/fixtures/other/file"
tar -czf "$work/fixtures/wrong-root.tar.gz" -C "$work/fixtures" other
printf 'payload\n' > "$work/fixtures/payload"
tar -czf "$work/fixtures/traversal.tar.gz" --transform='s@^payload$@ledger-preflight-0.1.0/../escaped@' -C "$work/fixtures" payload
package=$work/fixtures/ledger-preflight-0.1.0
mkdir "$package"
printf '#!/bin/sh\n: > "$INSTALLER_EXEC_SENTINEL"\nprintf "LedgerPreflight 0.1.0\\n"\n' > "$package/ledger-preflight"
chmod 755 "$package/ledger-preflight"
tar -czf "$work/fixtures/missing-runtime.tar.gz" -C "$work/fixtures" ledger-preflight-0.1.0
mkdir -p "$package/runtime/bin"
printf '#!/bin/sh\nexit 0\n' > "$package/runtime/bin/java"
chmod 755 "$package/runtime/bin/java"
/usr/bin/ln -s "$work/fixtures/other" "$package/escape"
tar -czf "$work/fixtures/escaping-link.tar.gz" -C "$work/fixtures" ledger-preflight-0.1.0
for scenario in invalid wrong-root traversal missing-runtime escaping-link; do
  reject env TEST_PACKAGE_OVERRIDE="$work/fixtures/$scenario.tar.gz" sh /source/install.sh --prefix "$work/$scenario"
  test ! -e "$work/$scenario"
  test ! -e "$INSTALLER_EXEC_SENTINEL"
done
rm "$package/escape"
printf '#!/bin/sh\nprintf "LedgerPreflight 9.9.9\\n"\n' > "$package/ledger-preflight"
chmod 755 "$package/ledger-preflight"
tar -czf "$work/fixtures/wrong-version.tar.gz" -C "$work/fixtures" ledger-preflight-0.1.0
reject env TEST_PACKAGE_OVERRIDE="$work/fixtures/wrong-version.tar.gz" sh /source/install.sh --prefix "$work/wrong-version"
test ! -e "$work/wrong-version"
reject env CASE=publish-failure sh /source/install.sh --prefix "$work/publish-failure"
test ! -e "$work/publish-failure/lib/ledgerpreflight/0.1.0"
test ! -e "$work/publish-failure/bin/ledger-preflight"
test -z "$(find "$work/publish-failure" -name '.install.*' -o -name '.ledger-preflight.*')"
reject env CASE=destination-race sh /source/install.sh --prefix "$work/destination-race"
grep -qx 'Concurrent installation' "$work/destination-race/lib/ledgerpreflight/0.1.0/preserve.txt"
test ! -e "$work/destination-race/bin/ledger-preflight"
verify_system_java_unchanged
printf 'PASS: %s installer cases; pinned/default/latest URLs, actual private runtime, checksum and transport failures, archive boundaries, no pre-verification execution, existing installation protection, race preservation and rollback.\n' "$checks"
