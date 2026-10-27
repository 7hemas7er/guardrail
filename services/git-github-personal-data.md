# Git, GitHub and personal data

## Git and GitHub

- **Commits**: Conventional Commits with scope, description in English; one
  commit per logical unit; never `git add -A` or `git add .`, always explicit
  files. The prefix ends up in the changelog users read.
- **Never rewrite shared history**: no `push --force` on `main` or on other
  people's branches. `--force-with-lease` only on a personal branch, with
  confirmation. `main` without branch protection is one more reason, not one
  less.
- **Do not discard other people's work**: `git reset --hard`,
  `git checkout -- .`, `git clean -f` delete uncommitted changes that may not
  be yours (shared worktrees, parallel sessions). First `git status`, then ask.
- **`git clean -x` never**: it also removes ignored files, that is `.env` and
  the local credentials.
- **Secrets in git**: no non-`.example` `.env`, no SQL dump, no token in
  tracked files. If you find one already committed, deleting it is not enough:
  report that it must be rotated.
- **GitHub**: the right repo is the organization's, not stale personal forks.
  Check that issues and PRs exist before commenting or closing. Closing an
  issue is an action towards people: only with verification done and described
  in the comment.
- **Attribution**: the agent's commits carry the attribution lines the session
  prescribes, without inventing them or hardcoding them in skills and scripts.

## Personal data (GDPR)

Many projects handle personal records, GPS positions, health data, data of
minors. These rules apply regardless of the repo.

- **Minimization**: use only the fields the task requires. A `SELECT *` on a
  table of people in chat is already a leak.
- **Never real data in tests, fixtures, examples, logs, issues, PR comments.**
  For examples, use made-up data, or an anonymization seeder and a
  production-to-dev clone script that anonymizes in transit.
- **GPS and tracking**: a person's position is read only with their valid
  consent and every read is audited. An administrator does not turn on a
  person's tracking. If a feature would allow it, it is a bug to report, not
  to use.
- **Audit**: on sensitive models every new field must be classified: excluded
  from the log (noise) or redacted (confidential). In 2026-07 an audit trait
  ended up writing confidential fields to the log, because nobody had done it.
- **Retention**: data has an expiry. Do not copy it out of the system that
  enforces it (exports, spreadsheets, chat).
- **In transcripts**: what you print in chat stays on disk. Names, tax codes,
  phone numbers, coordinates: do not print them unless the person reading you
  needs them, and if they do, the minimum.

## What the hook enforces

| Action | Outcome |
|---|---|
| `git push --force`, `-f`, refspec `+ref` | BLOCK |
| `git push --force-with-lease` | CONFIRM |
| `git clean -x` / `-X` | BLOCK |
| `git clean -f`, `git reset --hard`, `git checkout -- .`, `git restore .` | CONFIRM |
| `git push --delete`, refspec `:branch` (deletes a branch or a tag on the remote) | CONFIRM |
| `git branch -D`, `git stash drop`, `git stash clear` | CONFIRM |
| GitHub MCP tool that closes, deletes or archives (`state: closed`, `delete_*`) | CONFIRM |
| GitHub MCP tool that modifies a repo marked production in `prod_patterns` | BLOCK |

The rules on personal data are rules of conduct: no hook can recognize a tax
code in a query. The agent enforces them, and whoever supervises it.
