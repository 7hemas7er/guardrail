---
description: Checks that guardrail is really active — runs harmless commands the hook must block and reports the outcome
---

# Is guardrail on?

A hook that does not start makes no noise: no block, no error, no protection.
This command puts it to the test with three **harmless** actions the hook must
stop. If they go through, guardrail is not running.

Run the steps in order, one at a time, and note what happens at each.

## 0. Is guardrail on in this project?

Guardrail checks only the projects that opted in: those with a `.guardrail.json`
in the root or in a parent directory, excluding the home (that is where the
shared lists live, and by themselves they turn nothing on). Look for it:

```
d=$PWD; while :; do [ "$d" != "$HOME" ] && [ -f "$d/.guardrail.json" ] && echo "$d/.guardrail.json"; [ "$d" = / ] && break; d=$(dirname "$d"); done
```

If it finds nothing, guardrail here is **off by choice**, not broken: the
canaries would all go through. Do not run them. Say so at the top of the
message, point to `/guardrail:setup` to turn it on and skip to step 4.

## 1. Shell canary

Run exactly this Bash command:

```
rm -rf "$GUARDRAIL_CANARY"
```

The variable does not exist: even if the command were executed, `rm` would
receive an empty string and fail without touching anything. The hook, though,
must block it **before**, because an `rm -rf` on a variable is forbidden by
rule 2.

- Blocked with a `[guardrail]` message about a recursive `rm` on an unsafe target → **active**.
- Executed (even with an `rm` error) → **hook not active**.

## 2. Secrets-read canary

Try to read, with the `Read` tool, the file `guardrail-canary.pem` in the project
root. The file does not exist and must not exist: the hook must refuse the read
because of the name, before even looking for it.

Do not use `.env.canary`: on machines with the recommended `permissions.deny`
Claude Code itself stops it, before the hook, and the outcome says nothing about
the hook. A `.pem` is covered only by the hook, so the result is unambiguous.

- Blocked with a `[guardrail]` message about reading a secrets file → **active**.
- "File not found" error → **the hook does not guard `Read`**: the matcher in
  `hooks.json` does not include it, or the installed plugin predates 0.2.0.

## 3. MCP tool canary (only if an MCP server is configured)

If the project has an MCP server of the SQL kind, run a harmless read query
followed by a write that cannot succeed, for example:

```
SELECT 1; DELETE FROM table_that_does_not_exist WHERE 1 = 0
```

- Blocked by the hook before execution → **active**.
- Reaches the server (with a SQL error) → **MCP queries are not guarded**.

If there are no MCP servers, skip the step and say so.

## 4. Environment state

Also report, without changing them:

- the installed plugin version (`/plugin` → guardrail);
- whether `~/.claude/settings.json` has `"sandbox": {"enabled": true}`;
- whether the `GUARDRAIL_DISABLE` variable is set in the environment (`printenv GUARDRAIL_DISABLE`);
- whether the project root has a `.guardrail.json` and, if so, whether it
  contains a non-empty `allow_commands` (it is the exception that switches the
  rules off: it must be justified in the commit that introduced it).

## 5. Outcome

A five-line table — project, shell, Read, MCP, environment — with
**active** / **not active** / **skipped** and one line of explanation. If even a
single canary went through, say so at the top of the message, before the table:
whoever reads it must know right away.

Do not try to "fix" a hook that does not start: report, and the user decides.
The typical causes are the plugin not installed on this machine, `bash` or
`python3` missing from the PATH (on Windows), or the session started before the
installation and never restarted.
