#!/usr/bin/env bash
# Publishes a ProxBackup release on GitHub. A release is a package build, so it
# bumps BUILD/TOTAL in VERSION, commits that and tags it v<VERSION>. Consoles with
# automatic updates enabled install it in their next update window, and their
# agents follow.
#
#   scripts/release.sh            bump, commit, push, tag and push the tag; the
#                                 Release workflow builds and publishes it (normal way)
#   scripts/release.sh --local    bump, commit, push, then build with `make dist BUMP=0`
#                                 and publish from this machine (needs gh with write access)
#   scripts/release.sh --publish  publish an existing bin/dist (what the workflow runs)
#   scripts/release.sh --sign [VERSION]
#                                 sign a release's SHA256SUMS and publish its draft
#
# Signed releases: once internal/update/release.pub holds a minisign public key,
# consoles built with it only install releases whose SHA256SUMS.minisig checks
# out. The secret key stays on the maintainer's machine (default
# ~/.minisign/proxbackup.key, or $PROXBACKUP_SIGNING_KEY): the workflow then
# publishes drafts, which --sign signs and publishes; --local signs before upload.
#
# Releases of commits on the alpha branch are always pre-releases (only consoles that
# opt in to pre-releases install them).
#
# Options: --prerelease  mark the release as a pre-release from any branch
#          --draft       create a draft (not visible to the updater until published)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$("$root/scripts/version.sh")
tag="v$version"
dist="$root/bin/dist"

# bump_version makes this release's package build number and commits it.
bump_version() {
  version=$("$root/scripts/version.sh" build)
  tag="v$version"
  git rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists"
  git ls-remote --exit-code --tags origin "$tag" >/dev/null 2>&1 && die "tag $tag already exists on origin"
  git add VERSION .build-source
  git commit -q -m "chore: release $tag"
  git push -q origin HEAD
  echo "version bumped to $version"
}

mode=tag
flags=()
for a in "$@"; do
  case "$a" in
    --local) mode=local ;;
    --publish) mode=publish ;;
    --prerelease) flags+=(--prerelease) ;;
    --draft) flags+=(--draft) ;;
    --sign) mode=sign ;;
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) [ "$mode" = sign ] || { echo "release.sh: a version only goes with --sign" >&2; exit 2; }
      version=$a tag="v$a" ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "release.sh: unknown argument $a" >&2; exit 2 ;;
  esac
done

die() { echo "release.sh: $*" >&2; exit 1; }

check_tree() {
  [ -z "$(git status --porcelain --untracked-files=no)" ] || die "uncommitted changes; commit first"
  git fetch -q origin
  branch=$(git rev-parse --abbrev-ref HEAD)
  [ "$(git rev-parse HEAD)" = "$(git rev-parse "origin/$branch" 2>/dev/null)" ] || die "HEAD is not pushed to origin/$branch; push first"
}

# release_notes lists the commits since the previous release tag, without the
# version bump commits. Consoles show these notes under Settings -> Updates.
release_notes() {
  local prev range notes
  prev=$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^ 2>/dev/null || true)
  range=${prev:+$prev..}HEAD
  notes=$(git log --no-merges --format='- %s (%h)' "$range" | grep -v '^- chore: release v' || true)
  printf '%s\n' "${notes:-- No changes besides the version bump.}"
  [ -z "$prev" ] || printf '\nChanges since %s.\n' "$prev"
}

signing_key=${PROXBACKUP_SIGNING_KEY:-$HOME/.minisign/proxbackup.key}
signed_releases() { [ -n "$(tr -d '[:space:]' < "$root/internal/update/release.pub")" ]; }

# sign_sums signs $1/SHA256SUMS for this version (see update.SumsComment).
sign_sums() {
  command -v minisign >/dev/null || die "minisign is required to sign releases"
  [ -f "$signing_key" ] || die "release signing key $signing_key not found (set PROXBACKUP_SIGNING_KEY)"
  minisign -S -s "$signing_key" -m "$1/SHA256SUMS" -t "ProxBackup $version SHA256SUMS"
  minisign -V -p "$root/internal/update/release.pub" -m "$1/SHA256SUMS" >/dev/null || die "signature doesn't match internal/update/release.pub"
}

publish() {
  git fetch -q origin alpha 2>/dev/null || true
  if signed_releases && [ ! -f "$dist/SHA256SUMS.minisig" ]; then
    echo "releases are signed and the signing key isn't here: creating a draft"
    echo "  sign and publish it with: scripts/release.sh --sign $version"
    flags+=(--draft)
  fi
  if [ "$("$root/scripts/prerelease.sh")" = 1 ]; then
    echo "HEAD is on alpha; publishing $tag as a pre-release"
    flags+=(--prerelease)
  fi
  for f in SHA256SUMS "proxbackup-server_${version}_amd64.deb" "proxbackup-agent-windows-amd64.exe"; do
    [ -f "$dist/$f" ] || die "$dist/$f missing; run make dist"
  done
  if gh release view "$tag" >/dev/null 2>&1; then
    echo "release $tag exists; replacing its assets"
    gh release upload "$tag" "$dist"/* --clobber
    if [[ " ${flags[*]-} " == *" --prerelease "* ]]; then gh release edit "$tag" --prerelease; fi
  else
    gh release create "$tag" "$dist"/* --target "$(git rev-parse HEAD)" \
      --title "ProxBackup $version" --notes "$(release_notes)" ${flags[@]+"${flags[@]}"}
  fi
  echo "published $tag"
}

case "$mode" in
  tag)
    check_tree
    [ ${#flags[@]} -eq 0 ] || die "--prerelease/--draft need --local (or edit the release on GitHub; alpha releases are pre-releases anyway)"
    bump_version
    git tag -a "$tag" -m "ProxBackup $version"
    git push origin "$tag"
    echo "pushed $tag; the Release workflow builds and publishes it:"
    echo "  gh run watch \$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
    ;;
  local)
    check_tree
    command -v gh >/dev/null || die "gh (GitHub CLI) is required"
    bump_version
    make -C "$root" dist BUMP=0
    if signed_releases; then sign_sums "$dist"; fi
    publish
    ;;
  sign)
    command -v gh >/dev/null || die "gh (GitHub CLI) is required"
    signed_releases || die "internal/update/release.pub is empty: releases aren't signed"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    gh release download "$tag" -p SHA256SUMS -D "$tmp"
    echo "signing SHA256SUMS of $tag:"
    cat "$tmp/SHA256SUMS"
    sign_sums "$tmp"
    gh release upload "$tag" "$tmp/SHA256SUMS.minisig" --clobber
    gh release edit "$tag" --draft=false
    echo "signed and published $tag"
    ;;
  publish)
    command -v gh >/dev/null || die "gh (GitHub CLI) is required"
    publish
    ;;
esac
