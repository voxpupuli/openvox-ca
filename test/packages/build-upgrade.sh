#!/bin/bash
# Builds the "upgrade" packages test/packages/install-verify.sh installs over
# the ones `mage build:packages` wrote, into the directory named by $1.
#
# An upgrade can only exercise conffile handling against a package that is
# newer AND ships a different config.yaml: given the same file, dpkg and rpm
# both upgrade silently and neither .dpkg-dist nor .rpmnew is written, so the
# assertion that an operator's edit survives would pass without anything being
# tested. So the packages built here differ from the real ones in exactly three
# ways: the version's patch number is one higher, packaging/config/config.yaml
# gains a comment line, and the header the deb's postinstall renders into
# /etc/default/openvox-ca gains one too. The last is the same argument for ucf:
# an upgrade that renders the same file never reaches ucf's conflict handling,
# which is where an operator's edit is kept or lost.
#
# The binaries are NOT rebuilt. Packaging reads them from the variant tarballs
# and nothing else, so the real tarballs are copied in under the new version's
# name. What an upgrade tests -- the maintainer scripts, conffiles, the restart
# -- is in the packaging, not the binary, and the binary reporting the old
# version is harmless: install-verify.sh checks --version against the package
# it installed first.
#
# Built from HEAD in a temporary worktree, so the checkout is never edited.
# Locally that means uncommitted packaging changes are absent from the upgrade
# packages (but present in the first ones); commit them first if that matters.
# Run from the project root, after `mage build:distVariant` for every packaged
# variant (the tarballs are read from dist/).

set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s <output-dir>\n' "$0" >&2
    exit 2
fi
out=$1

# git exports GIT_DIR and its relatives to hooks, and they outrank the worktree
# path below; see AGENTS.md on specs that shell out to git. Nothing runs this
# from a hook, but it costs nothing to be sure it operates on the worktree it
# creates. Every GIT_ variable, as AGENTS.md prescribes, rather than a list of
# the ones known today.
while IFS= read -r var; do
    unset "$var"
done < <(compgen -e | grep '^GIT_')

ver=$(sed -n 's/^const Version = "\([^"]*\)"$/\1/p' internal/version/version.go)
if [[ ! $ver =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
    printf 'cannot parse the Version constant %q in internal/version/version.go\n' "$ver" >&2
    exit 1
fi
# The patch number, not a suffix: a pre-release suffix sorts BELOW the version
# it is attached to in both dpkg and rpm (nfpm writes 1.0.0-dev as 1.0.0~dev),
# so appending one could produce a "newer" package that is older.
next="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))${BASH_REMATCH[4]}"

tmp=$(mktemp -d)
src="$tmp/src"
cleanup() {
    git worktree remove --force "$src" 2>/dev/null || :
    rm -rf "$tmp"
}
trap cleanup EXIT

git worktree add --quiet --detach "$src" HEAD

sed -i.orig "s/^const Version = \"$ver\"\$/const Version = \"$next\"/" "$src/internal/version/version.go"
rm -f "$src/internal/version/version.go.orig"
grep -q "^const Version = \"$next\"\$" "$src/internal/version/version.go"
printf '\n# Changed by test/packages/build-upgrade.sh so the upgrade has a new default.\n' \
    >>"$src/packaging/config/config.yaml"
postinstall=$src/packaging/scripts/postinstall
sed -i.orig 's|"# See /usr/share/doc/openvox-ca/docs/systemd.md." &&|"# See /usr/share/doc/openvox-ca/docs/systemd.md." "# Changed by test/packages/build-upgrade.sh." \&\&|' \
    "$postinstall"
rm -f "$postinstall.orig"
if ! grep -q '"# Changed by test/packages/build-upgrade.sh."' "$postinstall"; then
    printf 'could not change the header postinstall renders into /etc/default/openvox-ca\n' >&2
    exit 1
fi

mkdir -p "$src/dist"
found=0
for tarball in dist/openvox-ca_"${ver}"_*.tar.gz; do
    [[ -e $tarball ]] || continue
    variant=${tarball#dist/openvox-ca_"${ver}"_}
    cp "$tarball" "$src/dist/openvox-ca_${next}_${variant}"
    found=$((found + 1))
done
if [[ $found -eq 0 ]]; then
    printf 'no dist/openvox-ca_%s_*.tar.gz; run mage build:distVariant first\n' "$ver" >&2
    exit 1
fi

(cd "$src" && mage build:packages)

mkdir -p "$out"
cp "$src"/dist/*.deb "$src"/dist/*.rpm "$out"/
printf 'upgrade packages (%s) in %s:\n' "$next" "$out"
ls -1 "$out"
