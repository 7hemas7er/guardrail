---
name: guardrail
description: "Company rules by service (database, deploy and infrastructure, filesystem/shell/secrets, git/GitHub/personal data). Load BEFORE running SQL, migrations, seeds, deploys, syncs with --delete, recursive rm, temp-file cleanups, pushes, closing issues, or touching people's data. Triggers on: prod, production, database, migrate, seed, deploy, promote, rollback, lftp, rsync, rm -rf, cleanup, .env, secrets, credentials, force push, GDPR, GPS, personal data."
---

# Guardrail — rules by service

The core rules are already in the context (injected at session start). Here you
load the ones for the service you are about to touch. The files live in the
`services/` folder two levels above this skill.

1. Identify the service: database, deploy and infrastructure, filesystem/shell/
   secrets, git/GitHub/personal data. If the task touches more than one, read
   them all.
2. Read the matching file:
   - `../../services/database.md`
   - `../../services/deploy-infrastructure.md`
   - `../../services/filesystem-shell-secrets.md`
   - `../../services/git-github-personal-data.md`
3. If the repo has a `.guardrail.json`, read it: it says which servers and hosts
   are production for this project.
4. Before the irreversible action, write to the user in one line: what you are
   about to do, on which environment, and how you verified it (dry-run, count,
   ls). Then act, or stop if the rule requires it.
5. If a hook blocks you: do not look for an equivalent command. Report the
   reason for the block to the user and leave the decision to them.
