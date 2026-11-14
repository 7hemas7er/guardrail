---
description: Summarizes guardrail's recent blocks and confirmations, to fix false positives with a better rule
---

# What guardrail stopped

Every `deny` and `ask` goes to `~/.claude/guardrail.log.jsonl`, one JSON line
per event with `ts`, `verdict`, `tool`, `cwd`, `session`, `reason` and the first
400 characters of `input`. This command reads it and summarizes it.

## 1. Read the log

```
tail -n 200 ~/.claude/guardrail.log.jsonl
```

If the file does not exist, guardrail has never blocked anything on this
machine: say so and stop. If the user passed an argument (`$ARGUMENTS`), use it
as a filter: a number is how many lines to read, a word is a filter on `reason`
or on `cwd`.

## 2. Group

For each event, take the rule that decided (the first sentence of `reason`) and
group by it. For each group:

- how many times, in how many sessions, in which projects (`cwd`);
- one example of `input`, **with sensitive values redacted**: if an input
  contains connection strings, tokens or passwords, replace them with `***`
  before reporting them. The log has already truncated them, but has not
  redacted them.

## 2-bis. Count by target

The same events, counted by *what the command pointed at* instead of by rule:
one rule can hit very different targets, and one target can trip several rules.
Put each event in one class, from the first that applies:

| Class | How to recognize it |
|---|---|
| session temporary folder | `$TMPDIR/…`, `/tmp/claude-…`, or a variable the command sets to one |
| production | a `prod_mcp_servers` server, or a `prod_patterns` match (host, database, app name) |
| secret file | `.env*`, keys, tokens, credentials |
| guardrail and Claude Code config | `.guardrail.json`, `.claude/` (settings, commands, skills, hooks, plugins), `CLAUDE.md` |
| invoked script | the reason starts with "the script … contains" |
| outside the project | home, other repos, system paths |
| git remote and branches | push, `--delete`, `branch -D`, force |
| MCP server | any other MCP tool: name the server |
| project path | everything else inside the project |

Report it as a table with one row per class: total, `deny`, `ask`, and the
projects it came from, most frequent first. Under the table, one line on the
class that grew or shrank the most compared with the older half of the lines
read: that is where a recent change in the hook or in a project shows.

## 3. Classify

For each group, say whether in your view it is:

- **a correct block**: the action really had to be stopped;
- **a false positive**: the action was legitimate and the rule is too broad.
  Propose the precise fix — the regex to narrow in `hooks/guard.py`, or the
  `ask_commands`/`prod_patterns` entry to adjust in `.guardrail.json` — and the
  case to add to `tests/cases.jsonl` so that it does not happen again;
- **a workaround attempt**: the same agent retried the blocked action with an
  equivalent command (same `session`, different `reason`s a few seconds apart).
  This must be flagged first: it is exactly what rule 8 forbids.

## 4. Report

One list per group, from the most frequent to the rarest, with the
classification and the proposal. Do not change the log, `guard.py` or
`.guardrail.json`: the fixes are the user's decision, and an `allow_commands` is
never an acceptable proposal for a false positive — the rule is narrowed, not
switched off.
