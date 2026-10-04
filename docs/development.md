# Development

```
python3 tests/run.py                  # guard.py hook cases, must stay green
python3 tests/test_attivazione.py     # on only where .guardrail.json exists
python3 tests/test_session_start.py   # injected rules and one-time notices
python3 tests/test_mask.py            # masking: real commands, rewritten results
```

## Test cases

The cases are in `tests/cases.jsonl`: one per line, with the expected outcome. A
new rule comes with its case and with the reason (the incident or near miss) in
the matching service file.

- `"config": ".guardrail.json"` evaluates the case with this repo's configuration
  instead of the fixture: that is how this repo's own `deny_commands` are
  verified, which would otherwise block the very command that tries to verify
  them.
- `"mask_map"` runs the case with a masking map; without it, with no map, so the
  machine's own map doesn't change the outcomes.
- The scripts in `tests/fixtures/` serve the cases that check the scan of invoked
  scripts: they must not be executed.

Activation per project can't be tested through `cases.jsonl`, which always sets
`GUARDRAIL_CONFIG` (and so turns guardrail on): `tests/test_attivazione.py` runs
the hook with a fake home and fake projects instead.

## Writing files that quote dangerous commands

To write files that *quote* dangerous commands (documentation, test cases), use
the agent's file editing tools: a heredoc that feeds an interpreter (`bash <<EOF`)
is read as commands, one that writes to a file (`cat > x <<EOF`) as data.

## The hook that blocks you is the installed one

**The hook that blocks you while developing is the installed one, not the one you
are writing.** When the plugin is installed from GitHub, Claude Code runs the
copy in `~/.claude/plugins/cache/<marketplace>/guardrail/<version>/hooks/guard.py`:
a fix in the repo has no effect until you update the plugin, and the plugin code
is not edited by hand. So you work under the previous version — handy for
noticing false positives, awkward when the thing blocking you is exactly what you
are fixing. In that case use `Edit`/`Write` on the repo, and verify with
`python3 tests/run.py`, which runs the local `guard.py`.

With the marketplace added from a local clone, `/reload-plugins` re-reads the
plugin from that folder: the hooks are those of the branch currently checked out.
