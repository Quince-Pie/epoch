#!/usr/bin/env bash
set -euo pipefail

package=$1
prefix=$2
component="$package/rust-src"
manifest="$component/manifest.in"
source_tree="$component/lib/rustlib/src"

# An unrecognized archive retains its own installer's per-file behavior.
[[ -f "$manifest" && -f "$package/components" && -f "$package/rust-installer-version" ]] || exit 0
[[ "$(<"$package/components")" == rust-src && "$(<"$package/rust-installer-version")" == 3 ]] || exit 0
[[ -d "$source_tree" && ! -e "$prefix/lib/rustlib/src" && ! -L "$prefix/lib/rustlib/src" ]] || exit 0

# Bind the equivalence proof to the audited stable and nightly installers.
# Other scripts retain their original behavior until their semantics are reviewed.
installer_hash=$(sha256sum "$package/install.sh") || exit 0
case "${installer_hash%% *}" in
  fdc8bc66c71068d72489b585557f77ecd946b17476cb100c86e06a41f6d23fe3|fe45fdbdda150c193e1a78b3127b6c408b07a63844c2575f7dafb027a3177a99) ;;
  *) exit 0 ;;
esac

scratch=$(mktemp -d) || exit 0
trap 'rm -rf "$scratch" || :' EXIT
tail -c 1 "$manifest" > "$scratch/last-byte" || exit 0
printf '\n' > "$scratch/newline" || exit 0
cmp -s "$scratch/newline" "$scratch/last-byte" || exit 0
# Bulk copying must preserve the per-file installer result, including modes,
# omitted empty directories, symlink dereferencing and manifest path parsing.
find "$source_tree" \( ! -type f ! -type d -o -type d -empty \
  -o -name '*[[:space:]]*' -o -name '*\\*' -o -perm /7000 \
  -o -type f -perm /111 ! -perm -111 \) -print -quit > "$scratch/unsupported" || exit 0
[[ ! -s "$scratch/unsupported" ]] || exit 0
(
  cd "$component" || exit 1
  find lib/rustlib/src -type f -printf 'file:%p\n'
) > "$scratch/files" || exit 0
LC_ALL=C sort "$scratch/files" > "$scratch/expected" || exit 0
LC_ALL=C sort "$manifest" > "$scratch/actual" || exit 0
cmp -s "$scratch/expected" "$scratch/actual" || exit 0
printf 'dir:lib/rustlib/src\n' > "$manifest"
