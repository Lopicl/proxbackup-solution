#!/usr/bin/env bash
# Version scheme: MAJOR.MINOR.BUILD.TOTAL  (stored in ./VERSION)
#   MAJOR  breaking / milestone releases
#   MINOR  feature releases
#   BUILD  build number within the current MAJOR.MINOR; resets to 0 on minor/major bumps
#   TOTAL  build counter over the whole project lifetime; never resets
#
# Only package builds count: `make deb` and `make dist` run `version.sh build`, and
# scripts/release.sh does it once per release. Commits don't change VERSION.
# .build-source holds the git tree of the source (working tree, without VERSION and
# itself) each bump was made from; a rebuild of the same source only bumps TOTAL.
#
#   scripts/version.sh            print the current version
#   scripts/version.sh build      a.b.c.x -> a.b.(c+1).(x+1), or a.b.c.(x+1) when the
#                                 source is unchanged since the last package build
#   scripts/version.sh minor      a.b.c.x -> a.(b+1).0.(x+1)
#   scripts/version.sh major      a.b.c.x -> (a+1).0.0.(x+1)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
file="$root/VERSION"
[ -f "$file" ] || echo "0.1.0.0" > "$file"
state="$root/.build-source"

# source_tree prints the git tree id of the working tree (tracked and untracked,
# not ignored files) without VERSION and .build-source.
source_tree() {
  local idx
  idx=$(mktemp)
  cp "$(git -C "$root" rev-parse --path-format=absolute --git-path index)" "$idx" 2>/dev/null || true
  GIT_INDEX_FILE=$idx git -C "$root" add -A
  GIT_INDEX_FILE=$idx git -C "$root" rm -q --cached --ignore-unmatch VERSION .build-source
  GIT_INDEX_FILE=$idx git -C "$root" write-tree
  rm -f "$idx"
}

IFS=. read -r major minor build total < "$file"
for n in "$major" "$minor" "$build" "$total"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { echo "version.sh: malformed VERSION file: $(cat "$file")" >&2; exit 1; }
done

case "${1:-show}" in
  show)  echo "$major.$minor.$build.$total"; exit 0 ;;
  build)
    tree=$(source_tree)
    [ "$tree" = "$(cat "$state" 2>/dev/null)" ] || build=$((build + 1)) ;;
  minor) minor=$((minor + 1)); build=0 ;;
  major) major=$((major + 1)); minor=0; build=0 ;;
  *) echo "usage: $0 [show|build|minor|major]" >&2; exit 2 ;;
esac
total=$((total + 1))
echo "${tree:-$(source_tree)}" > "$state"

echo "$major.$minor.$build.$total" > "$file"
echo "$major.$minor.$build.$total"
