# Filesystem, shell and secrets

The most dangerous service, because it does not look like a service: it is the
shell every agent uses for everything else.

## The case that generated this file

2026-09-11, 14:38. A subagent of a workflow in auto mode had to check what a
deploy script would do. It built a simulation in the scratchpad, with a fake
`HOME`, and at the end it cleaned up. The cleanup, in all likelihood in the
form `rm -rf "$HOME"/.[!.]* "$S"`, was executed in a shell where `HOME` was the
real one again. Result: every dotfile in the home directory deleted,
credentials included. The security classifier had approved the command: it
does not resolve variables.

## Rules of conduct

- **Never a variable in a destructive command.** Not `rm -rf "$DIR"`, not
  `rm -rf "$HOME/..."`, not `rsync --delete "$SRC" "$DST"`. The target is a
  literal path, relative to the project. If you computed the path, print it,
  show it, and use the printed one.
- **Never hidden globs.** `.*`, `.[!.]*`, `..?*` take everything that starts
  with a dot, and in a home directory that is everything. If you must remove
  `.cache`, write `.cache`.
- **Before deleting, list.** `ls -la <target>` or `find <target> -maxdepth 1`
  shown to the user; then the delete command, with the very same path.
- **`set -e` is not a protection.** It stops the script after an error, not
  before an `rm` that succeeds. Do not rely on it for safety.
- **End-of-work cleanups**: delete only what you created, by name, one by one.
  Not "everything in the temporary folder".
- **The home directory is not a workspace.** `~/.config`, `~/.claude`,
  `~/.ssh`, `~/.bashrc` are touched only on explicit request, and never with
  recursive commands.
- **Secrets**: do not read `.env*`, `*.pem`, keys, tokens; do not print them in
  chat (they end up in the transcript on disk); do not copy them into tracked
  files. Need a value? Ask the user. Need only the variable name? Read
  `.env.example`.
- **Isolating a test does not mean changing `HOME`.** Use dedicated directories
  and the tool's explicit options (`--config`, `--credentials <file>`); if
  `HOME` is really needed, export it for the whole script in a subshell
  `( export HOME=…; … )`, so the cleanup sees it too.
- **`sudo`**: never to delete. If it is needed, the user runs it.
- **Backup before changing the environment**: before rewriting a dotfile, copy
  it alongside with the suffix `.bak-<date>`.

## What the hook enforces

| Action | Outcome |
|---|---|
| `rm -r` with a variable target (`$X`, `${X}`), and `rm` (recursive or not) on `~`, `/home/<user>`, system root, `.`, `..`, hidden globs, `*` | BLOCK |
| Non-recursive `rm` with a variable target (`rm -f "$FILE"`) | CONFIRM |
| `find … -delete`, `find … -exec rm` | CONFIRM; BLOCK if the find root is one of the targets above |
| `sudo rm` | BLOCK |
| `sudo <anything else>` | CONFIRM |
| Recursive `chmod`/`chown` on the home directory or on the root | BLOCK |
| `mkfs`, `dd of=/dev/`, `chmod 777`, `curl \| sh`, `base64 -d \| sh` | BLOCK |
| `git clean -x` | BLOCK |
| Reading (`Read`) `.env*`, `.secrets`, keys, `.netrc`, `.pgpass`, `.npmrc`, `.git-credentials`, `~/.claude.json`, or inside `~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.gnupg`, `~/.docker/config.json` | BLOCK |
| `cat`, `grep`, `head`, `sed`… on the same files from the shell | BLOCK |
| `source .env` | CONFIRM |
| Writing from the shell (`>`, `tee`, `cp`, `sed -i`…) to the same files | CONFIRM |
| Writing (Write/Edit) to `~/.ssh/*`, private keys, `/etc`, `/usr` | BLOCK |
| Writing to `.env*` (except `.example`/`.sample`/`.template`/`.dist`) and to the other secret files | CONFIRM |
| Writing to a top-level dotfile of the home directory (`~/.bashrc`, `~/.gitconfig`…) | CONFIRM |
| Writing, from a tool or from the shell, to `.guardrail.json`, `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.claude/commands|skills|agents|rules` | CONFIRM |
| Removing `.guardrail.json` from the shell (`rm`, `unlink`, `mv` as source, `git rm`, `git mv`, `find … -delete`), including through a glob (`.guardrail*`), with different letter case, together with the folder that contains it (`rm -rf project`, `git rm -r .`) or inside a launched script | BLOCK |
| A second name for `.guardrail.json` (`ln`, `cp -l`, `cp -s`) | BLOCK |
| Writing (Write/Edit) to `.claude/settings.json`, `.claude/settings.local.json`, `.claude/CLAUDE.md` and to a project's `.claude/hooks|commands|skills|agents|rules` | CONFIRM |
| Writing, from a tool or from the shell, in `~/.claude/plugins` or `~/.claude/hooks` (the code of guardrail itself) | BLOCK |
| Writing (Write/Edit) outside the current project, the scratchpad and Claude Code's memory | CONFIRM |
| Code passed to a shell as a string (`bash -c "…"`, `sh -c '…'`, `eval …`, `ssh host "…"`): analyzed with the same rules, same outcome | as the command it contains |

On that last row: the first token of a string passed to a shell is in command
position, so `bash -c "rm -rf $HOME"` counts exactly as `rm -rf "$HOME"`,
nesting included. The agent wrote that string at that moment, not a human in
a file of the repo: that is why the `BLOCK` stays a block and is not
downgraded to a confirmation, as happens instead for an invoked script.
Quoting is not executing: in `grep "bash -c 'rm -rf'"` the command is `grep`,
and nothing happens.

**Stated limit**: an interpreter that is *not* a shell stays largely out of
scope. Of code passed as a string (`python3 -c`, `node -e`) the hook looks at
one thing only: whether it calls APIs that write or launch processes. If not,
the strings it contains are data, and a `node -e` that reads a file under
`.claude/plugins` does not modify it. If so, a `python3 -c` that names
`.guardrail.json` or the settings asks for confirmation. In heredocs aimed at
Python or Node (`python3 - <<'PY'`, `node <<'JS'`, and
`node -e 'eval(…readFileSync(0…))'` where the body is the program) the hook
goes deeper: it reads the code, skips comments and strings nobody passes on,
and the **literal** strings given to `os.system`, `os.popen`,
`subprocess.*(…, shell=True)`, `subprocess.getoutput`,
`child_process.exec`/`execSync` (and `spawn`/`execFile` with `shell`) it
judges as Bash commands, with the same rules, project ones included and with
the same depth cap: `os.system('rm -rf ~')` counts as `rm -rf ~`. A built
string (`'rm -rf ' + d`, an f-string, `%s`, `${x}`) counts with a variable
placeholder in place of what cannot be read, and a variable in a destructive
command is forbidden. An argument list without a shell
(`subprocess.run(['git', 'status'])`) launches no shell and stays allowed.
`eval`/`exec` of a literal are read as code in turn. Out of scope remain: a
command the code builds without any literal (`os.system(cmd)`), the same
reading inside `python3 -c "…"` or `node -e '…'` (there only the checks on
protected paths apply), Ruby, Perl, PHP and R, and a program that confuses the
reader (a JavaScript regex with a quote inside: if the quotes do not balance
everything is re-read without skipping anything, but an artfully balanced
string hides the call). A project can tighten with a rule of its own in
`deny_commands` (e.g. `os\.system`), but should know that it applies to
`python3 -c "…"` and **not** inside a heredoc: there the body is excluded from
the project regexes on purpose, because a path quoted in a script is not a
path executed; the strings that code passes to the shell, on the other hand,
they do see.

Secret reads are guarded both on the `Read` tool and on the shell: the
`permissions.deny` in the settings apply only to `Read`, and a `cat .env`
would get through. Keeping them is still useful as defence in depth.

The confirmations and blocks on the configuration of guardrail and of Claude
Code — from the tool and from the shell, because `echo '{}' > .guardrail.json`
is as much a write as a `Write` — serve one purpose only: an agent that has
received a block cannot loosen on its own the rules that bind it (rule 8).

Removing `.guardrail.json` is a block and not a confirmation because, since
0.10, that file is what turns guardrail on in the project: without it, the
hook checks nothing any more. A confirmation in auto mode is granted by the
agent, and switching off the rules that bind it cannot be its decision.
Modifying it stays a confirmation: any content, even `{}`, leaves it on.

These rules on the configuration and on the code of guardrail hold even in the
folders where guardrail is off, the only ones to do so: from there one reaches
the `.guardrail.json` of the other projects, `~/.guardrail.json` (which adds
to every active project), the projects' settings (`enabledPlugins` switches
the plugin off) and the plugin code. For guardrail any entry named
`.guardrail.json` counts as on, not only a file: a link to `/dev/null` in its
place does not switch it off.

Where a path leads is checked too: writing to `note.json` that is a link to
`.guardrail.json` is writing to `.guardrail.json`. And where guardrail is on
these rules come before `allow_commands`, which does not exempt them.

**Stated limit**: these are regular expressions over a shell command, and a
variant they do not anticipate can always be found. An interpreter that is not
a shell stays out of scope, as for every other rule, except for the case
described above; a `.guardrail.json` more than two levels below the deleted
folder is not searched for. They protect against an agent that makes a
mistake, not one looking for the gap.

A copy of the project in a temporary folder (`/tmp`, `$TMPDIR`) outside the
home directory — a `git checkout-index`, a `git archive`, a `cp -r` into the
scratchpad — carries `.guardrail.json` and `.claude/` along, which there
switch on and configure nothing: removing it or rewriting its settings asks
nothing. The check returns if the session works inside it (working directory
or project of the session). The path must be literal: with `rm -rf "$T"`
nobody knows where it leads, and it stays blocked.

The last row is rule 5 made enforceable: the project is the git root of the
working directory; everything outside it (home directory, other repos, `/opt`)
requires a confirmation. The session's scratchpad and Claude Code's memory
(`~/.claude/projects`) are legitimate workspaces and do not require it.

On heredocs: one that writes to a file (`cat > README.md <<EOF`,
`git commit -F - <<EOF`) contains data, and the hook does not read it as
commands — quoting `rm -rf ~` in a guide is not executing it; unless what it
writes ends up in a shell (`tee x <<EOF | bash`, `tee x <<'EOF' >(bash)`: tee
writes into the process substitution too). With an **unquoted** tag, however,
the shell executes the `$(…)` and the backticks of the body *before* handing
it to anyone, `cat` and `git` included: of that body the hook strips the text
and keeps the substitutions, which it judges as commands (and which the
project rules see), whoever the recipient, interpreters included. With a
quoted tag they are text. Backticks outside a heredoc count as `$(…)`, except
between single quotes and in comments. The recipient of the heredoc is read
the way the shell reads it, quotes included: if the line cannot be understood,
the body stays analyzed. One that feeds a shell (`bash <<EOF`) remains
commands in every respect. One that feeds Python or Node (`python - <<PY`,
`node <<JS`) is a program: if it launches processes the body stays analyzed as
shell text too, and the strings given to the launchers are judged as above.
If the code is passed with `-c`/`-e` and reads stdin while launching processes
(`python3 -c 'import os; os.system(input())' <<EOF`), the body is a shell
command and stays analyzed in full. Ruby, Perl and PHP are always analyzed.
A script written to a file and then launched is scanned at launch time (see
deploy-infrastructure.md).
