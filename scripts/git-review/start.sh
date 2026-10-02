#!/usr/bin/env bash
# Open a local review: back up the branch tip, then soft reset onto the target.
# Usage: start.sh [target]   (default target: main)
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$(git rev-parse --show-toplevel)"

target="${1:-main}"
branch="$(mr_branch)"
backup="$(mr_backup "$branch")"

git rev-parse --verify --quiet "refs/heads/$target" >/dev/null || die "target branch '$target' does not exist locally"
[ "$branch" != "$target" ] || die "on $target itself; check out the branch to review"
if git rev-parse --verify --quiet "refs/heads/$backup" >/dev/null; then
    die "review already open ($backup -> $(mr_target "$branch")); use just mr-diff, just mr-approve, or just mr-abort"
fi
git diff --quiet HEAD || die "uncommitted changes"
[ -z "$(git ls-files --others --exclude-standard)" ] || die "untracked files"
[ "$(git merge-base "$target" HEAD)" = "$(git rev-parse "$target")" ] || die "$target has moved; rebase on $target first"
if git diff --quiet "$target" HEAD; then
    die "no changes vs $target"
fi

just check

git branch "$backup" HEAD
git config "branch.$branch.mrTarget" "$target"
git reset -q --soft "$target"
printf 'review open: %s -> %s, backup %s (%s commits)\n' \
    "$branch" "$target" "$backup" "$(git rev-list --count "$target..$backup")"
git diff --cached --stat
