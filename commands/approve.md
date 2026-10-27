---
description: Approves a script for allow_scripts — reads it, shows what it does that is dangerous, and records its fingerprint in .guardrail.json
---

# Approving a script

Every invoked script is read by the hook: if it contains a command guardrail
would stop, the outcome is a confirmation, **every time**. On a build script
launched twenty times a day that confirmation becomes noise, and noise teaches
you to approve without reading.

`allow_scripts` removes it, but ties the exemption to the sha256 fingerprint of
the content: if the script changes, the confirmation comes back. This command is
the correct way to set and renew that fingerprint.

**The approval is given by the user, not by you.** Your job is to read, show and
record. If you wrote the script yourself in this session, say so before anything
else: the user would be approving code that was just generated.

## 0. Without arguments: check the existing approvals

If `$ARGUMENTS` is empty, read `allow_scripts` from `.guardrail.json` and for
each entry compare `sha256sum` with the declared fingerprint. Report in a table:

| Status | Meaning |
|---|---|
| valid | the file is there and the fingerprint matches |
| expired | the content has changed: the exemption no longer holds |
| incomplete | the entry declares no `sha256`, so it exempts nothing |
| orphan | the path no longer exists |

Do not update anything in this mode: an expired fingerprint is renewed by
re-reading the script, that is, by running this command again on that path.

## 1. With a path: read the script in full

Use `Read`, not `head`. If it exceeds 200 lines, read it anyway, and summarize it
by blocks. Stop right away, explaining why, if:

- the path does not exist, or lies outside the current project;
- the file is not tracked by git. An unversioned file can change without
  leaving a trace in any revision: the fingerprint would catch it, but there is
  nothing to re-read to understand *what* changed. Say so, and let the user decide.

## 2. Show what it contains that matters

List, with the line number, every command the hook would stop: recursive `rm`,
`--delete`, `prune`, write SQL, reads of secrets, `sudo`, `curl | sh`. Then:

- **No such command**: the script needs no approval, because it produces no
  confirmation. Say so and stop without writing anything.
- **A command present in `deny_commands`**: it is not approved. `deny_commands`
  wins even inside an approved script, so the entry would be useless and
  misleading. Explain and stop.

## 3. If it was already approved with a different fingerprint

Show what changed since the last approval. The approved revision is found by
comparing the fingerprints of the versions in git:

```
for c in $(git log --format=%H -- SCRIPT_PATH); do
  echo "$c $(git show "$c:SCRIPT_PATH" | sha256sum | cut -d' ' -f1)"
done
```

The line with the fingerprint declared in `.guardrail.json` is the revision the
user had read: show `git diff <that commit> -- SCRIPT_PATH`. If no revision
matches, say so: the script was modified without going through git, and that is
information that matters more than the diff.

## 4. Ask for confirmation

Show the exact entry you are about to write:

```json
{"path": "scripts/build\\.sh", "sha256": "625f88e4…"}
```

The `path` is a regex: dots escaped, anchored to the project just enough not to
catch namesakes in other directories. Ask for explicit confirmation. If the user
does not confirm, write nothing.

## 5. Write

Update `allow_scripts` in `.guardrail.json` (create the file if it is missing,
with the other keys empty). Replace the existing entry for that path instead of
adding a second one. The fingerprint is that of `sha256sum SCRIPT_PATH`, taken
**after** the reading, not before.

The write will trigger a confirmation from the hook: that is intended, it is the
guarantee that this file does not change without the user seeing it.

## 6. Close

Remind the user of two things:

- `.guardrail.json` must be committed: the approval holds for whoever works in
  the repo, people and agents, and like code it is reviewed in a PR;
- at every deliberate change to the script the fingerprint must be renewed, by
  running this command again. If someone renews it without re-reading, the
  exemption goes back to being what it must not be: trust in a name.
