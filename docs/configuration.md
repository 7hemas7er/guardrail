# Configuration

The keys of `.guardrail.json` are listed in the [README](../README.md#per-project-configuration).
This page covers what doesn't fit there.

## Approved scripts: `allow_scripts`

The hook reads every script that gets invoked, and if the script contains a
command that would be blocked, the outcome is a confirmation. On a build script
run twenty times a day that confirmation becomes noise, and noise teaches people
to approve without reading. `allow_scripts` removes it, but ties the exemption to
the **content**:

```json
"allow_scripts": [
  {"path": "scripts/build\\.sh", "sha256": "625f88e4…"}
]
```

```
/guardrail:approve scripts/build.sh    # reads, shows, records the fingerprint
sha256sum scripts/build.sh             # if you prefer to do it by hand
```

Without arguments, `/guardrail:approve` checks the existing approvals and reports
which fingerprints are stale, incomplete or orphaned.

If the script changes, the fingerprint no longer matches: the confirmation comes
back, with a notice saying the content is not the approved one. An entry without
`sha256` exempts nothing — "I trust this file forever" is not something this repo
can say. `deny_commands` still wins: a forbidden command stays forbidden even
inside an approved script, and the exemption covers only the content scan, not
the command that launches it (`rm -rf "$X" && bash build.sh` stays blocked).

## Shared lists and environment variables

The lists add up with those in `~/.guardrail.json`, if it exists, which however
does not turn guardrail on by itself (see the README).

- `GUARDRAIL_CONFIG=<file>` replaces both files and turns guardrail on
  everywhere (used by the tests).
- `GUARDRAIL_DISABLE=1` switches the hook off; the choice is recorded in the log.
  Masking does not follow it: it is switched off by removing the map.

## Self-protection

Removing `.guardrail.json` is how guardrail gets switched off, so that decision
stays with the user: `rm`, `unlink`, `mv`, `git rm`, `git mv` and `find … -delete`
on it are blocked, including through a glob (`.guardrail*`), with different
letter case (on NTFS `.GUARDRAIL.JSON` is the same file), together with the
folder that contains it (`rm -rf project`, `git rm -r .`), or inside a launched
script. Giving it a second name (`ln`, `cp -l`, `cp -s`) is blocked too, and a
write to a path that leads to it through a link counts as a write to it.

Where guardrail is off, it still keeps the rules that protect itself:

| Action | Outcome |
|---|---|
| removing a `.guardrail.json` (any project) | blocked |
| writing a `.guardrail.json` or `~/.guardrail.json` | confirmation |
| writing Claude Code settings, in the home or in a project's `.claude/` | confirmation |
| writing plugin code in `~/.claude/plugins` or `~/.claude/hooks` | blocked |

Otherwise a session opened in any folder could switch guardrail off, or loosen it
with an `allow_commands` in `~/.guardrail.json`, in the projects where it is on.
Any entry named `.guardrail.json` counts as "on", not only a regular file: a link
to `/dev/null` in its place doesn't switch it off. In active projects these rules
come before `allow_commands`, which doesn't exempt them.

**Stated limit**: these are regular expressions over a shell command, and a
variant they don't anticipate can always be found. An interpreter that is not a
shell (`python3 -c "os.remove(…)"`) is out of scope, as for every other rule; a
`.guardrail.json` more than two levels below a deleted folder is not searched
for; the hook checks a script before the command runs, so a script written and
launched in the same command is not seen in its final form. These rules protect
against an agent that makes a mistake, not one looking for the gap. The details
per rule are in [services/filesystem-shell-segreti.md](../services/filesystem-shell-segreti.md).
