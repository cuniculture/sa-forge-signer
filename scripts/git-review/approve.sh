#!/usr/bin/env bash
# Approve a local review: commit the staged diff as one commit,
# fast-forward the target, delete the branch and its backup. Never pushes.
# Usage: approve.sh "Commit message."
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

msg="${1:-}"
[ -n "$msg" ] || die "usage: just mr-approve \"Commit message.\""
case "$msg" in
    *.) ;;
    *) die "message must end with a full stop" ;;
esac

cd "$(git rev-parse --show-toplevel)"
branch="$(mr_branch)"
target="$(mr_require_open "$branch")"
backup="$(mr_backup "$branch")"

[ "$(git rev-parse HEAD)" = "$(git rev-parse "$target")" ] || die "$branch is not in review state (HEAD is not $target)"
git diff --quiet || die "unstaged changes; stage or discard them"
[ -z "$(git ls-files --others --exclude-standard)" ] || die "untracked files"
if git diff --cached --quiet; then
    die "nothing staged"
fi

just check

git commit -q -m "$msg"
# Fast-forward the target without checking it out, so this script is never rewritten mid-run.
git fetch -q . "$branch:$target"
git switch -q "$target"
git config --unset "branch.$branch.mrTarget"
git branch -q -D "$branch"
git branch -q -D "$backup"
git log --oneline -3
printf '%s updated locally; push with: git push origin %s\n' "$target" "$target"
