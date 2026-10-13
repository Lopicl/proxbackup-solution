#!/usr/bin/env bash
# Publishes ProxBackup release v$(cat VERSION) on GitHub. Consoles with automatic
# updates enabled install it in their next update window, and their agents follow.
#
#   scripts/release.sh            tag HEAD as v<VERSION> and push the tag; the
#                                 Release workflow builds and publishes it (normal way)
#   scripts/release.sh --local    build with `make dist` and publish from this machine
#                                 (needs gh, logged in with write access)
#   scripts/release.sh --publish  publish an existing bin/dist (what the workflow runs)
#
# Options: --prerelease  mark the release as a pre-release (only consoles that opt in
#                        to pre-releases install it)
#          --draft       create a draft (not visible to the updater until published)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$("$root/scripts/version.sh")
tag="v$version"
dist="$root/bin/dist"

mode=tag
flags=()
for a in "$@"; do
  case "$a" in
    --local) mode=local ;;
    --publish) mode=publish ;;
    --prerelease) flags+=(--prerelease) ;;
    --draft) flags+=(--draft) ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "release.sh: unknown argument $a" >&2; exit 2 ;;
  esac
done

die() { echo "release.sh: $*" >&2; exit 1; }

check_tree() {
  [ -z "$(git status --porcelain --untracked-files=no)" ] || die "uncommitted changes; commit first (VERSION is bumped on commit)"
  git fetch -q origin
  branch=$(git rev-parse --abbrev-ref HEAD)
  [ "$(git rev-parse HEAD)" = "$(git rev-parse "origin/$branch" 2>/dev/null)" ] || die "HEAD is not pushed to origin/$branch; push first"
}

publish() {
  for f in SHA256SUMS "proxbackup-server_${version}_amd64.deb" "proxbackup-agent-windows-amd64.exe"; do
    [ -f "$dist/$f" ] || die "$dist/$f missing; run make dist"
  done
  if gh release view "$tag" >/dev/null 2>&1; then
    echo "release $tag exists; replacing its assets"
    gh release upload "$tag" "$dist"/* --clobber
  else
    gh release create "$tag" "$dist"/* --target "$(git rev-parse HEAD)" \
      --title "ProxBackup $version" --generate-notes ${flags[@]+"${flags[@]}"}
  fi
  echo "published $tag"
}

case "$mode" in
  tag)
    check_tree
    git rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists (commit something to get a new version)"
    git ls-remote --exit-code --tags origin "$tag" >/dev/null 2>&1 && die "tag $tag already exists on origin"
    [ ${#flags[@]} -eq 0 ] || die "--prerelease/--draft need --local (or edit the release on GitHub)"
    git tag -a "$tag" -m "ProxBackup $version"
    git push origin "$tag"
    echo "pushed $tag; the Release workflow builds and publishes it:"
    echo "  gh run watch \$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
    ;;
  local)
    check_tree
    command -v gh >/dev/null || die "gh (GitHub CLI) is required"
    make -C "$root" dist
    publish
    ;;
  publish)
    command -v gh >/dev/null || die "gh (GitHub CLI) is required"
    publish
    ;;
esac
