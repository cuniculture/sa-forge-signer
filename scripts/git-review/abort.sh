#!/usr/bin/env bash
# Cancel a local review: restore the incremental commits.
# Edits made during the review stay as uncommitted changes.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$(git rev-parse --show-toplevel)"

branch="$(mr_branch)"
mr_require_open "$branch" >/dev/null
backup="$(mr_backup "$branch")"

git reset -q --soft "$backup"
git branch -q -D "$backup"
git config --unset "branch.$branch.mrTarget"
printf 'review aborted; %s restored to %s\n' "$branch" "$(git rev-parse --short HEAD)"
git status --short
