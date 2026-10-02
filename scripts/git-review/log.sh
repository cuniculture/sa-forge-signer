#!/usr/bin/env bash
# Show the incremental commits behind an open review, without checking out the backup.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$(git rev-parse --show-toplevel)"

branch="$(mr_branch)"
target="$(mr_require_open "$branch")"
git log -p "$target..$(mr_backup "$branch")"
