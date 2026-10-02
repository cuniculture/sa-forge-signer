# git-review

A local merge-request workflow for `just`: squash the current branch into one staged diff against a target branch, review it, then approve it as a single commit. No GitHub/GitLab PR or MR needed. Built for Claude Code sessions, where the agent works on a `claude/<topic>` branch and the human reviews and approves.

## Install

1. Copy this folder into the repo (for example `scripts/git-review/`).
2. Add to the root `justfile`: `import "scripts/git-review/justfile"`
3. Make sure the root `justfile` has a `check` recipe (lint/tests). It gates both `mr-open` and `mr-approve`.

Requires `bash`, `git` and `just` (tested with just 1.49). Nothing in the folder is repo-specific: scripts find the repo via `git rev-parse --show-toplevel` and the justfile finds the scripts via `source_directory()`.

## Commands

| recipe | what it does |
|---|---|
| `just mr-open [target]` | Review the current branch against `target` (default `main`): runs `just check`, backs the tip up to `mr-review/<branch>`, records the target, soft-resets onto it. The whole branch becomes one staged diff. |
| `just mr-diff` | Show the staged review diff (`git diff --cached`). |
| `just mr-diff-words` | Same, word by word (for prose). |
| `just mr-log` | Show the individual commits behind the open review. |
| `just mr-abort` | Cancel: restore the individual commits. Edits made during the review stay uncommitted. |
| `just mr-approve "Message."` | Runs `just check`, commits the staged diff as one commit (message must end with a full stop), fast-forwards the target, deletes the branch, backup and recorded target. Never pushes. |

`mr-open` refuses to start if the tree is dirty, there are untracked files, the target does not exist or has moved (rebase first), the branch is the target, or a review is already open.

State lives only in the local repo: the backup branch `mr-review/<branch>` and the git config key `branch.<branch>.mrTarget`. Both are removed by `mr-approve` or `mr-abort`.

## With a Claude Code session

1. Claude works on `claude/<topic>`, committing in small steps.
2. When done, Claude runs `just mr-open` and summarises the diff.
3. You review with `just mr-diff` / `just mr-log`. Ask Claude for fixes; they get staged into the same diff.
4. You say "approve"; Claude runs `just mr-approve "Message."`, or you run it yourself. Push separately when you choose.

### Suggested CLAUDE.md block

```markdown
## Git workflow (local review, no PR/MR)

- All Claude/agent work goes on a `claude/<topic>` branch created from the target (default `main`). Never commit on the target directly.
- Commit in small steps. When the work is done, run `just mr-open [target]` and summarise the staged diff for the owner.
- The owner reviews with `just mr-diff` / `just mr-diff-words` / `just mr-log`. Fixes requested during review are made in place and staged into the same diff.
- Run `just mr-approve "Message."` only when the owner explicitly approves. It commits one squashed commit and fast-forwards the target; it never pushes.
- Run `git push` only when the owner explicitly asks. `just mr-abort` restores the individual commits if the review is abandoned.
```

### Optional: permission prompts

To make Claude Code always ask before approving or pushing, add to `.claude/settings.json`. Ask rules are checked before allow rules, so this prompts even if a broader rule such as `Bash(just *)` is allowed:

```json
{
  "permissions": {
    "ask": ["Bash(just mr-approve *)", "Bash(git push *)"]
  }
}
```

This matches the command as Claude writes it; it is a guard rail, not a security boundary (`git -C . push` would not match). The CLAUDE.md rule above is what keeps approvals and pushes owner-driven.
