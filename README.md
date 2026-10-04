# guardrail

Company rules for coding agents, in two forms: **prose** that every agent reads
(`AGENTS.md`, `services/`) and **hooks** that, in Claude Code, block dangerous
commands or ask for confirmation (`hooks/`). It was born from the 2026-09-11
incident, in which a subagent in auto mode deleted a developer's home directory
while "studying" a deploy script.

## Installing in Claude Code (recommended)

The repo is both a plugin and its own marketplace. Claude Code does not download
a package: it **git-clones** the repo from GitHub, branch `main`. The machine
therefore needs `git`, and, if the repo is not public, valid git credentials for
GitHub (`gh auth login` or an SSH key); otherwise the clone fails.

```
/plugin marketplace add 7hemas7er/guardrail
/plugin install guardrail@7hemas7er-guardrail
```

From a local clone, to try it out or develop it:

```
/plugin marketplace add /path/to/guardrail
/plugin install guardrail@7hemas7er-guardrail
```

### Updating

The installed plugin is a **copy**, in `~/.claude/plugins/cache/`, of the version
that existed at install time: a new commit on GitHub does not arrive by itself.
Two steps bring it in, pulling the marketplace and then updating the plugin:

```
/plugin marketplace update 7hemas7er-guardrail    # git pull of the repo from GitHub
/plugin update guardrail@7hemas7er-guardrail      # fresh copy in the cache
```

Then start a new session: the open session keeps the old hooks. From a local
clone you pull yourself (`git pull` in the clone), then run the same two commands.

Whoever publishes a change must **push to `main` and bump the version** in
`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`: without the
push nobody receives it, and without a new version the update has nothing to
install.

### What you get

The plugin is installed once per machine, but **switched on per project**: where
you don't turn it on, it checks nothing and adds nothing to the context. In every
active project:

- at every session, the core rules (`RULES-CORE.md`) enter the context;
- every Bash command, file read and write, and MCP query goes through the
  `guard.py` hook, with outcome `allow`, `ask` (confirmation — but in auto mode
  the agent grants it, not the user) or `deny` (a block explained to the agent,
  and the only outcome auto mode cannot override);
- the `guardrail` skill, which loads the rules for the service at hand;
- four commands: `/guardrail:check` (is the hook really running?),
  `/guardrail:setup` (turn on and configure the current repo), `/guardrail:log`
  (what was blocked, and why), `/guardrail:approve` (approve a script and record
  its fingerprint);
- optionally, masking of reserved terms: it is turned on by creating a map, and
  applies in every folder, active or not (see [Masking](#masking-reserved-terms)).

### First steps

In a new session opened in the project you want to protect:

```
/guardrail:setup
```

The agent looks at `.mcp.json`, the deploy scripts and the CI, works out which
servers and hosts are production, and proposes the `.guardrail.json` to commit.
It writes nothing without showing it to you. That file is what turns guardrail on
in the project. Then check:

```
/guardrail:check
```

It runs three harmless actions the hook must stop and tells you whether it did. A
hook that doesn't start makes no noise: without this check you don't know you
are unprotected.

One thing remains to do by hand, once per machine: turn on the sandbox in
`~/.claude/settings.json` (see `examples/settings.example.json`). It is the only
protection no hook can switch on for you. If it is off, guardrail tells you at
the start of the first session in an active project.

## Turning it on per project

Guardrail is on wherever there is a `.guardrail.json`: in the project root, or in
a parent directory, which turns it on for every project below it
(`~/repos/client/.guardrail.json` covers every repo of that client). The
exception is `~/.guardrail.json`: it holds the lists shared by all active
projects and turns nothing on by itself, otherwise it would cover every folder in
the home directory.

| You want to… | Do this |
|---|---|
| turn it on with the right configuration | `/guardrail:setup` |
| turn it on with the basic rules only | a `.guardrail.json` containing `{}` in the root |
| turn it on for yourself only, not your colleagues | as above, with the file in `.git/info/exclude` instead of the commit |
| turn it off | remove `.guardrail.json` yourself: the agent cannot |

When Claude starts in a folder without `.guardrail.json`, at the first request
the agent asks you whether to turn it on, before doing anything else, mentioning
`.mcp.json`, `docker-compose` or `scripts/deploy` if present: **yes, configure
it** (`/guardrail:setup`), **yes, basic rules** (a `.guardrail.json` with `{}`)
or **no**. The question is not repeated for that folder: it is a choice, not an
oversight to remind you of every time. The state lives in
`~/.claude/guardrail.state.json`; removing the `inattivo:<folder>` entry brings
the question back.

What counts is the project the session started from and the command's working
directory: either one being active is enough, so a `cd` out of the project turns
nothing off. Removing `.guardrail.json` is blocked, and where guardrail is off it
still keeps the rules that protect itself; details in
[docs/configuration.md](docs/configuration.md#self-protection).

⚠️ Up to 0.9.x guardrail was on everywhere. After updating, projects without a
`.guardrail.json` stay unprotected until you add one.

## Per-project configuration

Put `.guardrail.json` in the repo root. Full example in
`examples/esempio.guardrail.json`:

```json
{
  "prod_mcp_servers": ["postgres", "telemetria"],
  "ask_mcp_servers": ["postgres-test"],
  "prod_patterns": ["db-produzione\\.esempio\\.com", "\\bappdb\\b(?!_)"],
  "deny_commands": ["scripts/deploy/(promote-to-production|rollback-production)\\.sh"],
  "ask_commands": ["scripts/deploy/containerapp/(promote-to-production|rollback-production)\\.sh", "build-and-push(-fast)?\\.sh[^;|]*--skip-tests"]
}
```

| Key | Meaning |
|---|---|
| `prod_mcp_servers` | exact names of MCP servers that are production: writes blocked |
| `ask_mcp_servers` | shared servers: writes need confirmation |
| `prod_patterns` | regexes that mark as production a `psql`/`mysql`/`pg_restore` command, an MCP server name, or the parameters of an MCP call (e.g. the Azure resource group) |
| `deny_commands` | regexes on the Bash command: hard block |
| `ask_commands` | regexes on the Bash command: confirmation |
| `allow_commands` | regexes that exempt a command from all rules (use sparingly, justify in the commit) |
| `allow_scripts` | scripts already read and approved: `{"path": regex, "sha256": fingerprint}`. They exempt **only** the content scan, and only while the content stays the same |

Approved scripts, shared lists in `~/.guardrail.json` and the environment
variables (`GUARDRAIL_CONFIG`, `GUARDRAIL_DISABLE`) are described in
[docs/configuration.md](docs/configuration.md).

## Masking reserved terms

Keeps terms that must not leave the machine (host, people, place and client
names) away from the model, wherever they come from: command output, a document
read, a search result, an MCP server reply. `nas-warehouse.lan` becomes
`nas-site1.lan`. It is turned on by creating `~/.config/guardrail/mask.tsv`,
outside any repo, **never** in `.guardrail.json`, which is tracked in projects:

```
# real-term   placeholder
warehouse     site1
```

Without the file, nothing changes. Setup, what it covers per tool, and what no
hook can cover are in [docs/masking.md](docs/masking.md).

## Log

Every `deny` and `ask` goes to `~/.claude/guardrail.log.jsonl` with tool, cwd,
session and reason. It shows what agents try to do, and helps fix false positives
with a better rule instead of `GUARDRAIL_DISABLE`. `/guardrail:log` summarizes it
by rule and flags workaround attempts (same session, same action retried in a
different form).

## Other tools (Copilot, Cursor, Codex, Gemini)

Clone the repo next to your projects and import `AGENTS.md` into the tool's
instruction file. Prose only: no automatic blocking.

## Development

```
python3 tests/run.py                  # guard.py hook cases, must stay green
python3 tests/test_attivazione.py     # on only where .guardrail.json exists
python3 tests/test_session_start.py   # injected rules and one-time notices
python3 tests/test_mask.py            # masking: real commands, rewritten results
```

A new rule comes with its test case and with the reason (the incident or near
miss) in the matching service file. How the cases work, and why the hook that
blocks you while developing may not be the one you are writing, is in
[docs/development.md](docs/development.md).

## Layout

```
AGENTS.md                 index and rules for every agent
RULES-CORE.md             the 9 core rules, injected at every session in active projects
CLAUDE.md                 imports the two files above for Claude Code
services/                 rules per type of service
hooks/guard.py            PreToolUse hook: allow / ask / deny, and input rewritten for masking
hooks/session-start.py    SessionStart hook: injects RULES-CORE.md in active projects, asks in the others
hooks/mask.py             masking of reserved terms: runner, PostToolUse and UserPromptSubmit hooks
hooks/hooks.json          hook registration in the plugin
skills/guardrail/         skill that loads the right service file
commands/check.md         /guardrail:check — is the hook running?
commands/setup.md         /guardrail:setup — turn on and configure the current repo
commands/log.md           /guardrail:log — summarizes recent blocks
commands/approve.md       /guardrail:approve — approve a script, record its fingerprint
docs/                     configuration, masking and development in detail; incident notes
examples/                 example .guardrail.json, recommended settings,
                          reference clone-prod-to-local.sh
tests/                    cases, runner, script fixtures, session-start and activation tests
.claude-plugin/           plugin and marketplace manifests
```
