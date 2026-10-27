---
description: Turns on and configures guardrail for this project — works out what is production, proposes .guardrail.json and checks the Claude Code settings
---

# Configuring guardrail for this project

Your job is to produce a correct `.guardrail.json` for the current repo and
flag the missing settings. **You write nothing without showing it first.**

That file is also what **turns on** guardrail here: without it, the hook checks
nothing in this project and the core rules do not enter the context. If the
user does not want guardrail in this project, stop: the choice is theirs.

## 1. Gather the evidence

Look at, if they exist:

- `.mcp.json` and `~/.claude.json` → names of the MCP servers and the hosts they point to
- `docker-compose*.yml`, `*.tf`, `.github/workflows/`, `azure-pipelines.yml`
- `scripts/deploy/`, `Makefile`, `package.json` (deploy, promote, rollback scripts)
- `config/database.php`, `config/*.yml`, `.env.example` → **names** of the connections
- `git remote -v`, `README.md` → what project this is

**Absolute rule while gathering:** never print the content of `.mcp.json`,
`.env*` or any file that may contain credentials. Extract only the keys:

```
jq -r '.mcpServers | keys[]' .mcp.json
jq -r '.mcpServers | to_entries[] | "\(.key): \(.value.command // .value.url)"' .mcp.json | sed -E 's#(password|pwd|token|key)=[^ &"]*#\1=***#gi'
```

If a command gets blocked by the hook, that is the expected behaviour: do not
look for an alternative route, report the block and move on with the other
evidence.

## 2. Classify

For each MCP server and each host found, decide: production, shared
(test/staging used by others), or throwaway. The criterion is not the name: a
server called `postgres` may well be production. Use the host, the database,
the context of the deploy scripts.

When in doubt, classify as production: a false positive costs one more
confirmation, a false negative costs an incident.

A server that only writes text (documents, notes, issues) and does not touch
infrastructure can go in `prose_mcp_servers`: that way a document that mentions
"production" is not taken for a change to production. Propose it only if the
user confirms: the text of that server stops counting for the check.

## 3. Propose

Show the user a table — entry, value, why you classified it that way — and then
the complete `.guardrail.json`:

```json
{
  "prod_mcp_servers": [],
  "ask_mcp_servers": [],
  "prose_mcp_servers": [],
  "prod_patterns": [],
  "deny_commands": [],
  "ask_commands": []
}
```

If you found nothing to classify (no MCP server, no host, no deploy script),
propose the minimal file: it turns guardrail on with the basic rules.

```json
{
  "_comment": "No production reachable from here: the basic rules are enough."
}
```

Ask for explicit confirmation before writing. The write will trigger a
confirmation request from the hook, even if guardrail here is still off: that
is intended, it is the guarantee that this file does not change without the
user seeing it.

**Never propose `allow_commands`.** It is the exception that switches the rules
off: a human adds it, justifying it in the commit message.

**Never write `allow_scripts` in this command**, not even if you already know
which script the project runs all the time: that entry declares "I have read
this content", and at this stage nobody has read it. See step 3-bis.

## 3-bis. Flag the scripts to approve, do not approve them

Every invoked script is read by the hook, and if it contains a blockable
command it produces a confirmation at every run. Identify the candidates — the
scripts the project runs often and that contain such commands:

- the `scripts` in `package.json`, the `Makefile` targets, the CI jobs;
- what the README says to run for build, test, local deploy;
- `scripts/*.sh` invoked by other scripts.

For each one, one line: path, what it does in one sentence, and which command
would produce the confirmation (with the line number). Then stop the list there
and point the way:

```
/guardrail:approve scripts/build.sh
```

That command is what reads the script, shows it to the user and records its
fingerprint. An exemption written without reading is worth less than nothing:
it removes the confirmation and adds no review.

## 4. Check the Claude Code settings

Read `~/.claude/settings.json` and check that it contains:

```json
"sandbox": { "enabled": true, "autoAllowBashIfSandboxed": true }
```

The sandbox is the only protection no hook can turn on in the user's place. If
it is missing, show the line to add and explain what changes: Bash commands run
isolated from the rest of the filesystem. Do not change the file unless the
user asks you to.

Reads of `.env` and of keys are already blocked by the hook, both via `Read`
and via the shell: no more `permissions.deny` entries are needed.

## 5. Close

Remind the user to commit `.guardrail.json`: it is part of the repo, it is
reviewed the way code is reviewed, and it holds for whoever works on it — people
and agents. Once committed it turns guardrail on for colleagues who have the
plugin too; if the user wants it for themselves only, it goes in
`.git/info/exclude` instead of the commit.

Also tell them what changes right away: the hook already checks the next
command, and the core rules enter the context from the next session.
