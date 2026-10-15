#!/usr/bin/env bash
# Prints 1 when HEAD belongs to the alpha branch, 0 otherwise. Everything built or
# released from alpha is a pre-release: release.sh publishes it as a GitHub
# pre-release, and the Makefile stamps it into the console so it includes
# pre-releases in its updates by default.
#
# HEAD is on alpha when the alpha branch is checked out, or (detached, as in the
# Release workflow's tag checkout) when origin/alpha contains it.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" = alpha ]; then
  echo 1
elif git rev-parse -q --verify refs/remotes/origin/alpha >/dev/null &&
  git merge-base --is-ancestor HEAD refs/remotes/origin/alpha; then
  echo 1
else
  echo 0
fi
