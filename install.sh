#!/bin/sh
# Install a checksum-verified published Linux package; leave node/system Java alone.
set -eu
fail() { printf 'Installation stopped: %s\n' "$*" >&2; exit 1; }
version=0.1.0
prefix=${HOME:?HOME must be set}/.local
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--prefix)
      [ "$#" -ge 2 ] || fail "$1 needs a value"
      case "$1" in --version) version=$2 ;; --prefix) prefix=$2 ;; esac
      shift 2 ;;
    --help) printf '%s\n' 'Usage: sh install.sh [--version 0.1.0|latest] [--prefix /absolute/path]' 'Default: v0.1.0, installed under $HOME/.local'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || fail 'Linux x86_64 is required.'
case "$prefix" in /*) ;; *) fail '--prefix must be an absolute path.' ;; esac
case "$prefix" in *"'"*|*'
'*) fail 'Unsupported character in installation path.' ;; esac
for tool in curl sha256sum tar mktemp awk find readlink cp mv ln chmod mkdir rm; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required command: $tool"
done
base=https://github.com/InfraGuard-Labs/ledgerpreflight/releases
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 600 "$@"; }
if [ "$version" = latest ]; then
  url=$(fetch --head --output /dev/null --write-out '%{url_effective}' "$base/latest") || fail 'GitHub latest release could not be resolved.'
  case "$url" in "$base/tag/"*) version=${url##*/} ;; *) fail 'Unexpected latest-release redirect.' ;; esac
fi
version=${version#v}
printf '%s\n' "$version" | awk '/^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$/ {ok=1} END {exit !ok}' || fail 'Invalid release version.'
asset=ledger-preflight-$version-linux-x86_64.tar.gz
package=ledger-preflight-$version
destination=$prefix/lib/ledgerpreflight/$version
launcher=$prefix/bin/ledger-preflight
[ ! -e "$destination" ] && [ ! -L "$destination" ] || fail "Version already installed at $destination; no files were changed."
[ ! -e "$launcher" ] && [ ! -L "$launcher" ] || fail 'An existing launcher was found; choose a different --prefix.'
umask 022
stage=$(mktemp -d)
install_stage=
launcher_stage=
destination_created=false
launcher_created=false
complete=false
cleanup() {
  if [ "$complete" = false ]; then
    [ "$launcher_created" = false ] || rm -f -- "$launcher"
    [ "$destination_created" = false ] || rm -rf -- "$destination"
  fi
  [ -z "$launcher_stage" ] || rm -f -- "$launcher_stage"
  [ -z "$install_stage" ] || rm -rf -- "$install_stage"
  rm -rf -- "$stage"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
fetch --output "$stage/$asset" "$base/download/v$version/$asset" || fail 'Release package download failed; nothing installed.'
fetch --output "$stage/SHA256SUMS" "$base/download/v$version/SHA256SUMS" || fail 'Checksum download failed; nothing installed.'
awk -v name="$asset" 'NF==2 && $2==name && length($1)==64 && $1 !~ /[^0-9a-fA-F]/ {print $1 "  " $2; n++} END {if(n!=1)exit 1}' "$stage/SHA256SUMS" > "$stage/selected.sha256" || fail 'Missing or ambiguous package checksum.'
(cd "$stage" && sha256sum -c selected.sha256) || fail 'Checksum mismatch; nothing installed.'
tar -tzf "$stage/$asset" > "$stage/members" || fail 'Invalid release archive.'
awk -v root="$package" '($0!=root && index($0,root "/")!=1) || $0 ~ /(^|\/)\.\.(\/|$)/ {bad=1} END {exit bad}' "$stage/members" || fail 'Unsafe archive path.'
mkdir "$stage/unpacked"
tar -xzf "$stage/$asset" --no-same-owner --no-same-permissions -C "$stage/unpacked" || fail 'Release extraction failed.'
app=$stage/unpacked/$package
[ -d "$app" ] && [ ! -L "$app" ] && [ -f "$app/ledger-preflight" ] && [ ! -L "$app/ledger-preflight" ] && [ -x "$app/ledger-preflight" ] && [ -f "$app/runtime/bin/java" ] && [ -x "$app/runtime/bin/java" ] || fail 'Release package is missing the launcher or private runtime.'
app=$(cd "$app" && pwd -P)
find "$app" -type l -exec sh -c '
  root=$1; shift
  for link do
    target=$(readlink -f -- "$link") || exit 1
    case "$target" in "$root"/*) ;; *) exit 1 ;; esac
  done
' sh "$app" {} + || fail 'Release contains an escaping or unresolved symbolic link.'
actual=$("$app/ledger-preflight" --version) || fail 'The downloaded runtime cannot run on this host.'
[ "$actual" = "LedgerPreflight $version" ] || fail 'Package version does not match the selected release.'
# Copy only verified content to staging on the destination filesystem, then rename.
mkdir -p "$prefix/lib/ledgerpreflight" "$prefix/bin"
install_stage=$(mktemp -d "$prefix/lib/ledgerpreflight/.install.XXXXXXXX")
cp -a -- "$app" "$install_stage/$package"
launcher_stage=$(mktemp "$prefix/bin/.ledger-preflight.XXXXXXXX")
printf '#!/bin/sh\nexec '\''%s/ledger-preflight'\'' "$@"\n' "$destination" > "$launcher_stage"
chmod 755 "$launcher_stage"
mv -T -n -- "$install_stage/$package" "$destination" || fail 'Could not install the verified package.'
[ ! -e "$install_stage/$package" ] || fail 'The version destination appeared during installation; existing files were preserved.'
destination_created=true
# A hard link publishes the prepared wrapper atomically and refuses an existing name.
ln -T -- "$launcher_stage" "$launcher" || fail 'Could not create launcher; existing files were preserved.'
launcher_created=true
"$launcher" --version || fail 'Installed launcher verification failed.'
complete=true
printf '\nInstalled in %s\nNext: %s/bin/ledger-preflight\n' "$destination" "$prefix"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) printf 'Add %s/bin to PATH to run ledger-preflight by name.\n' "$prefix" ;; esac
