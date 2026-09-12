#!/bin/sh
# Run in Docker with the packaged distribution mounted at /dist.
set -eu
sh -n /source/install.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir "$work/bin"
cat > "$work/bin/curl" <<'MOCK'
#!/bin/sh
set -eu
if [ "${CASE:-}" = unavailable ]; then exit 22; fi
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
if "$head"; then printf '%s' 'https://github.com/InfraGuard-Labs/ledgerpreflight/releases/tag/v0.1.0'; exit; fi
case "$url" in
  */SHA256SUMS)
    if [ "${CASE:-}" = checksum ]; then printf '%064d  ledger-preflight-0.1.0-linux-x86_64.tar.gz\n' 0 > "$output"
    elif [ "${CASE:-}" = missing ]; then printf '' > "$output"
    else cp /dist/SHA256SUMS "$output"; fi ;;
  */ledger-preflight-0.1.0-linux-x86_64.tar.gz) cp /dist/ledger-preflight-0.1.0-linux-x86_64.tar.gz "$output" ;;
  *) exit 22 ;;
esac
MOCK
chmod 755 "$work/bin/curl"
export PATH="$work/bin:$PATH"
sh /source/install.sh --help
sh /source/install.sh --version 0.1.0 --prefix "$work/with spaces"
test "$("$work/with spaces/bin/ledger-preflight" --version)" = 'LedgerPreflight 0.1.0'
# The installed wrapper must find its bundled Java from an unrelated directory.
(cd /tmp && "$work/with spaces/bin/ledger-preflight" > "$work/start.txt")
grep -q 'Supply your current node' "$work/start.txt"
reject() { if "$@" > "$work/rejected.log" 2>&1; then cat "$work/rejected.log"; exit 1; fi; }
reject sh /source/install.sh --version 0.1.0 --prefix "$work/with spaces"
reject sh /source/install.sh --version ../../invalid --prefix "$work/invalid"
reject sh /source/install.sh --prefix relative
reject sh /source/install.sh --version
reject env CASE=checksum sh /source/install.sh --version 0.1.0 --prefix "$work/checksum"
test ! -e "$work/checksum"
reject env CASE=missing sh /source/install.sh --version 0.1.0 --prefix "$work/missing"
test ! -e "$work/missing"
reject env CASE=unavailable sh /source/install.sh --prefix "$work/unavailable"
test ! -e "$work/unavailable"
sh /source/install.sh --prefix "$work/latest"
test "$("$work/latest/bin/ledger-preflight" --version)" = 'LedgerPreflight 0.1.0'
printf '%s\n' 'PASS: installer syntax, explicit/latest release, checksum verification and rejection, missing checksum, missing release, existing installation protection, argument validation, spaces, private runtime and non-TTY startup.'
