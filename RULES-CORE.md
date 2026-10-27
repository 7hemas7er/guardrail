# Guardrail — core rules (valid for every agent, in every repo)

1. **Production is read, never written.** No INSERT/UPDATE/DELETE/DDL on a
   production database, storage or service. Changes go through a migration in
   the repo or a human operator.
2. **Never a variable in a destructive command.** `rm -rf "$X"`, `rm -rf ~/.*`,
   `rsync --delete $DIR`: forbidden. A deletion target is a literal path,
   relative to the project, and you show the user what it contains first.
3. **Deleting is never a side effect.** `--delete`, `prune`, `clean -x`,
   `migrate:fresh`, `TRUNCATE`, `DROP`: only with a dry-run shown and the user's
   explicit confirmation. If in doubt, list and stop.
4. **Secrets.** Do not read `.env*`, keys, tokens; never print them in chat; do
   not write them to git-tracked files. If you need a value, ask the user.
5. **Nothing outside the project without asking.** The home directory,
   `~/.config`, `~/.claude`, other repos: touched only on explicit request.
6. **Git:** never `push --force` on shared branches, never rewrite the history
   of `main`, atomic commits with messages in English.
7. **Personal data** (personal records, GPS positions, health data): handled
   only for the requested purpose, never copied into logs, tests, examples or
   chat.
8. **Did a hook block you?** Do not work around it with an equivalent command.
   Explain to the user what you wanted to do and why; they decide.
9. **Auto mode is not a licence.** Before an irreversible action, reason as if
   the user were watching: show the plan, then act.
