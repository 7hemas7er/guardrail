# Guardrail — rules for coding agents

This repo holds the rules every agent (Claude Code, Copilot, Cursor, Codex,
Gemini CLI) must follow when working on the organization's projects. It was born
from a real incident: on 2026-09-11 a subagent in auto mode, asked to *read* a
deploy script that used `--delete`, deleted every configuration file in the
developer's home directory. Rules in prose would not have stopped it: that is
why the repo also ships hooks that block.

## How to use it

- **Claude Code**: install the plugin (see README), then turn it on in the
  projects you want to protect: it is active only where there is a
  `.guardrail.json`. There, the core rules enter the context at every session
  and dangerous commands are blocked or put up for confirmation; in a folder
  without one, the first session warns that guardrail is off. The `guardrail`
  skill loads the rules for the service at hand; `/guardrail:check` verifies
  that the hook is active, `/guardrail:setup` turns on and configures guardrail
  in the current repo, `/guardrail:log` summarizes what was blocked,
  `/guardrail:approve` approves a script that is launched all the time and
  records its fingerprint.
- **Other tools**: clone the repo next to your projects and import `AGENTS.md`
  into your tool's instruction file. No automatic blocking: only the written
  rules apply.

## The core rules

They are in [`RULES-CORE.md`](RULES-CORE.md). They always apply, in every repo.
Read them first.

## Rules by type of service

Read the file for the service you are about to touch, **before** acting.

| Service | File | When to read it |
|---|---|---|
| Database | [`services/database.md`](services/database.md) | queries, migrations, seeds, dumps, MCP SQL |
| Deploy and infrastructure | [`services/deploy-infrastructure.md`](services/deploy-infrastructure.md) | builds, image pushes, promotions, FTP, Azure, containers |
| Filesystem, shell, secrets | [`services/filesystem-shell-secrets.md`](services/filesystem-shell-secrets.md) | rm, cleanups, scripts with variables, `.env`, keys, home directory |
| Git, GitHub, personal data | [`services/git-github-personal-data.md`](services/git-github-personal-data.md) | commits, pushes, PRs, issues, personal records, GPS, audit |

## What gets blocked automatically (Claude Code only)

Each service file separates the **rules of conduct** (prose) from what the
`hooks/guard.py` hook enforces: `BLOCK` (the tool does not start) or `CONFIRM`
(someone has to approve). ⚠️ In auto mode the `CONFIRM` is granted by the agent,
not the user: if a decision must be a human's, the rule has to be written as a
`BLOCK`, the only outcome that cannot be overridden. A block is not an obstacle
to work around: if it fires, stop the work and explain to the user.

## Per-project configuration

A `.guardrail.json` file in the repo root turns guardrail on in that project
(even empty, `{}`) and tells the hook which MCP servers are production, which
patterns identify production in commands, and which project commands are
forbidden. Removing it turns guardrail off: the user does that, never the agent.
Example in [`examples/example.guardrail.json`](examples/example.guardrail.json).

## Contributing

A rule gets in here if it prevented, or would have prevented, real damage. Every
rule cites the case that motivated it. Changes to the hooks go through
`tests/run.py`, which must stay green.
