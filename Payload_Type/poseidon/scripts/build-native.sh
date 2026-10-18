#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
agent_root="$project_root/poseidon/agent_code"
build_root="$project_root/.build"
release_manifest="$project_root/scripts/beaconcrypt-releases.txt"
native_target=${POSEIDON_BEACONCRYPT_NATIVE_TARGET:-"$build_root/beaconcrypt-native-target"}
if [[ $# != 0 && $# != 2 ]]; then
    printf '%s\n' 'Usage: build-native.sh [GOOS GOARCH]' >&2
    exit 1
fi
if [[ "$native_target" != /* ]]; then
    printf '%s\n' 'POSEIDON_BEACONCRYPT_NATIVE_TARGET must be an absolute path.' >&2
    exit 1
fi
cd "$agent_root"
host_os=$(go env GOHOSTOS)
host_arch=$(go env GOHOSTARCH)
if [[ "$host_os" != linux || ( "$host_arch" != amd64 && "$host_arch" != arm64 ) ]]; then
    printf '%s\n' 'Beaconcrypt native payload builds require a Linux amd64 or arm64 builder.' >&2
    exit 1
fi
if [[ $# == 0 ]]; then
    target_os=$host_os
    target_arch=$host_arch
else
    target_os=$1
    target_arch=$2
fi
case "$target_os/$target_arch" in
    linux/amd64) rust_target=x86_64-unknown-linux-gnu ;;
    linux/arm64) rust_target=aarch64-unknown-linux-gnu ;;
    darwin/amd64) rust_target=x86_64-apple-darwin ;;
    darwin/arm64) rust_target=aarch64-apple-darwin ;;
    *) printf 'Unsupported Beaconcrypt native target: %s/%s\n' "$target_os" "$target_arch" >&2; exit 1 ;;
esac
module_version=$(go list -m -f '{{.Version}}' github.com/0xd6cb6d73/beaconcrypt)
asset_name=
expected_sha256=
while read -r version triple asset checksum extra; do
    [[ -z "$version" || "$version" == \#* ]] && continue
    if [[ "$version" == "$module_version" && "$triple" == "$rust_target" ]]; then
        if [[ -n "$extra" || ! "$checksum" =~ ^[0-9a-f]{64}$ || -n "$asset_name" ]]; then
            printf 'Invalid or duplicate Beaconcrypt release entry: %s %s\n' "$module_version" "$rust_target" >&2
            exit 1
        fi
        asset_name=$asset
        expected_sha256=$checksum
    fi
done < "$release_manifest"
if [[ -z "$asset_name" ]]; then
    printf 'No pinned Beaconcrypt release archive for %s %s; update %s for the selected module version.\n' "$module_version" "$rust_target" "$release_manifest" >&2
    exit 1
fi
target_cache="$native_target/$rust_target"
archive="$target_cache/release/libbeaconcrypt.a"
mkdir -p "$build_root"
# Concurrent payload builds must see one verified archive and version marker.
exec 9>"$build_root/beaconcrypt-native.lock"
flock 9
archive_matches() {
    local actual
    [[ -f "$1" ]] || return 1
    actual=$(sha256sum < "$1") || return 1
    [[ "${actual%% *}" == "$expected_sha256" ]]
}
if [[ -f "$target_cache/module-version" && $(cat "$target_cache/module-version") == "$module_version" ]] && archive_matches "$archive"; then
    exit 0
fi
command -v curl >/dev/null || { printf '%s\n' 'curl is required to download the pinned Beaconcrypt release archive.' >&2; exit 1; }
mkdir -p "$target_cache/release"
download=
version_file=
cleanup() {
    [[ -z "$download" ]] || rm -f -- "$download"
    [[ -z "$version_file" ]] || rm -f -- "$version_file"
}
trap cleanup EXIT
download=$(mktemp "$target_cache/release/.libbeaconcrypt.XXXXXX")
version_file=$(mktemp "$target_cache/.module-version.XXXXXX")
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    --retry 3 --connect-timeout 15 --max-time 120 --output "$download" \
    "https://github.com/0xd6cb6d73/beaconcrypt/releases/download/$module_version/$asset_name"
if ! archive_matches "$download"; then
    printf 'SHA256 mismatch for Beaconcrypt release archive %s\n' "$asset_name" >&2
    exit 1
fi
printf '%s\n' "$module_version" > "$version_file"
chmod 0644 "$download" "$version_file"
mv -f -- "$download" "$archive"
mv -f -- "$version_file" "$target_cache/module-version"
