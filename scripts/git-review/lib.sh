# shellcheck shell=bash
# Shared helpers for the git-review scripts. Portable: no repo-specific references.

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# mr_branch: the checked-out branch; dies on detached HEAD.
mr_branch() {
    local b
    b="$(git branch --show-current)"
    [ -n "$b" ] || die "detached HEAD; check out the branch under review"
    printf '%s\n' "$b"
}

# mr_backup <branch>: backup ref holding the pre-review tip.
mr_backup() {
    printf 'mr-review/%s\n' "$1"
}

# mr_target <branch>: target recorded for an open review (empty if none).
mr_target() {
    git config --get "branch.$1.mrTarget" || true
}

# mr_require_open <branch>: dies unless a review is open; prints its target.
mr_require_open() {
    local target
    git rev-parse --verify --quiet "refs/heads/$(mr_backup "$1")" >/dev/null ||
        die "no review open on $1 (missing $(mr_backup "$1"))"
    target="$(mr_target "$1")"
    [ -n "$target" ] || die "review on $1 has no recorded target (branch.$1.mrTarget)"
    printf '%s\n' "$target"
}
