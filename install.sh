#!/bin/sh
# Install a published Linux package without changing system Java.
set -eu
fail() { printf 'Installation stopped: %s\n' "$*" >&2; exit 1; }
version=latest
prefix=${HOME:?HOME must be set}/.local
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--prefix)
      [ "$#" -ge 2 ] || fail "$1 needs a value"
      case "$1" in --version) version=$2 ;; --prefix) prefix=$2 ;; esac
      shift 2 ;;
    --help) printf '%s\n' 'Usage: sh install.sh [--version 0.1.0] [--prefix /absolute/path]' 'Default: latest published release, installed under $HOME/.local'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || fail 'Linux x86_64 is required.'
case "$prefix" in /*) ;; *) fail '--prefix must be an absolute path.' ;; esac
case "$prefix" in *"'"*|*'
'*) fail 'Unsupported character in installation path.' ;; esac
for tool in curl sha256sum tar mktemp awk; do command -v "$tool" >/dev/null 2>&1 || fail "Required command: $tool"; done
base=https://github.com/InfraGuard-Labs/ledgerpreflight/releases
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 600 "$@"; }
if [ "$version" = latest ]; then
  url=$(fetch --head --output /dev/null --write-out '%{url_effective}' "$base/latest") || fail 'No published release is available, or GitHub could not be reached. Use the documented Docker source build until a release is published.'
  version=${url##*/}
fi
version=${version#v}
printf '%s\n' "$version" | awk '/^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$/ {ok=1} END {exit !ok}' || fail 'Invalid release version.'
asset=ledger-preflight-$version-linux-x86_64.tar.gz
package=ledger-preflight-$version
destination=$prefix/lib/ledgerpreflight/$version
[ ! -e "$destination" ] && [ ! -L "$destination" ] || fail "Version already installed at $destination; no files were changed."
[ ! -e "$prefix/bin/ledger-preflight" ] && [ ! -L "$prefix/bin/ledger-preflight" ] || fail 'An existing launcher was found; choose a different --prefix.'
umask 022
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
fetch --output "$stage/$asset" "$base/download/v$version/$asset" || fail 'Release package download failed.'
fetch --output "$stage/SHA256SUMS" "$base/download/v$version/SHA256SUMS" || fail 'Checksum download failed.'
awk -v name="$asset" '$2==name && length($1)==64 && $1 !~ /[^0-9a-fA-F]/ {print; n++} END {if(n!=1)exit 1}' "$stage/SHA256SUMS" > "$stage/selected.sha256" || fail 'Missing or ambiguous package checksum.'
(cd "$stage" && sha256sum -c selected.sha256) || fail 'Checksum mismatch; nothing installed.'
tar -tzf "$stage/$asset" > "$stage/members" || fail 'Invalid release archive.'
awk -v root="$package" '$0 !~ ("^" root "(/|$)") || $0 ~ /(^|\/)\.\.(\/|$)/ {bad=1} END {exit bad}' "$stage/members" || fail 'Unsafe archive path.'
mkdir "$stage/unpacked"
tar -xzf "$stage/$asset" --no-same-owner --no-same-permissions -C "$stage/unpacked"
app=$stage/unpacked/$package
[ -x "$app/ledger-preflight" ] && [ -x "$app/runtime/bin/java" ] || fail 'Release package is missing the launcher or private runtime.'
actual=$("$app/ledger-preflight" --version) || fail 'The downloaded runtime cannot run on this host.'
[ "$actual" = "LedgerPreflight $version" ] || fail 'Package version does not match the selected release.'
mkdir -p "$prefix/lib/ledgerpreflight" "$prefix/bin"
mv "$app" "$destination"
# A wrapper preserves the private runtime location when invoked through PATH.
(set -C; printf '#!/bin/sh\nexec '\''%s/ledger-preflight'\'' "$@"\n' "$destination" > "$prefix/bin/ledger-preflight") || fail 'Could not create launcher; existing files were preserved.'
chmod 755 "$prefix/bin/ledger-preflight"
"$prefix/bin/ledger-preflight" --version
printf '\nInstalled in %s\nNext: %s/bin/ledger-preflight\n' "$destination" "$prefix"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) printf 'Add %s/bin to PATH to run ledger-preflight by name.\n' "$prefix" ;; esac
