# Log review — 2026-11-08

What `~/.claude/guardrail.log.jsonl` said after two months in use, and what
changed because of it. Hook 0.10.1 (commit bbdc4dd) installed; the log held
2749 decisions since 2026-09-12, of which 497 in real work outside this repo
between 2026-10-01 and 2026-11-07 (the rest are this repo's own tests). The 171
of those whose input survived the 400-character truncation were replayed
against HEAD before touching anything: what HEAD already allowed is not listed.

## Still wrong in HEAD, fixed here

### 1. `rm` on the session's temporary folder — 150 of 174 `rm` decisions

```
rm -rf $TMPDIR/head && mkdir -p $TMPDIR/head && git archive HEAD | tar -x -C $TMPDIR/head
S=/tmp/claude-1000/…/scratchpad; rm -rf $S/snap && mkdir -p $S/snap
SP=/tmp/claude-1000/…/t; rm -f $SP/session.txt $SP/seed.log
```

Blocked (recursive) or put up for confirmation (not recursive) by rule 2, as
written. Every time the agent re-ran the command with the literal path: same
effect, one turn lost, and an agent trained to expand `$TMPDIR` by hand. The
harness sets `TMPDIR` and tells the agent to work there.

**Change** (`check_rm`, `temp_target`, `temp_aliases`): a temporary root
(`$TMPDIR`, `${TMPDIR:-/tmp}`, `/tmp`, `/var/tmp`) followed by a literal first
component is a safe target; so is a variable the same command sets exactly
once to such a path. Still blocked: the root alone, `$TMPDIR/*`, hidden globs,
`$(mktemp -d)`, a variable set twice (also by `for … in` or `read`), and a
suffix that with `TMPDIR` empty would be a real top-level directory
(`$TMPDIR/snap` → `/snap`: the hook checks `os.path.lexists`). RULES-CORE rule 2
now states the exception. While testing, `for d in …; do rm -rf $d/x; done`
turned out to be invisible to `RM_ANY` (the `rm` follows `do`, not a
separator): `do`, `then`, `else` and `{` now count as command position.

### 2. `source ~/.nvm/nvm.sh` — 35 confirmations, 5 blocks

```
cd $S/head && ln -sfn …/node_modules node_modules && source ~/.nvm/nvm.sh >/dev/null && vite build …
```

The sourced file is scanned like a project script, and `nvm.sh` is full of
`command rm -rf "${NVM_DIR}/…"`. The 5 blocks ("removal of `"`, which contains a
.guardrail.json") were the `empty_operand` bug already fixed on 2026-10-04; the
confirmations remained. `/guardrail:approve ~/.nvm/nvm.sh` is no way out: the
command refuses paths outside the project.

**Change** (`env_manager_init`): the init scripts of the version managers,
*sourced* from their install location (`~/.nvm/nvm.sh`, `~/.cargo/env`,
`~/.sdkman/bin/sdkman-init.sh`, `~/.asdf/asdf.sh`, `~/.rvm/scripts/rvm`, and
the `/usr/share`, Homebrew paths), are not scanned. A copy of nvm.sh inside the
project (`tests/fixtures/like-nvm.sh`) still is.

### 3. A Python tool denied by its own usage text — 9 blocks, then surrender

```
python3 tools/deploy-ftp.py --dry-run home.html      → deny
python3 tools/deploy-ftp.py --help                   → deny
```

The project's `deny_commands` has `deploy-ftp\.py[^;|]*--remove(?!…--dry-run)`.
The hook reads the invoked script and applies the project regexes to its
content, where line 21 of the docstring reads
`python3 tools/deploy-ftp.py --remove tests/README.md tests   # unpublish`. The
agent concluded that deploys are off limits and wrote that down in its memory.

**Change** (`check_scripts`, `is_shell_script`): project regexes apply to the
content of shell scripts only (by shebang or suffix; a file with neither, such
as `~/.cargo/env`, counts as shell). They are written for a command line; in a
Python string they describe, they do not run. The built-in rules still scan
everything, as before. The shell twin showed up while verifying the fix:
`./deploy-ovh.sh` in iro was denied because a *comment* in it quoted
`python3 tools/deploy-ftp.py --remove <path>`. Full-line comments are now
removed from a scanned script before any rule sees it (`without_comment_lines`);
an inline `cmd  # note` is kept whole, since `#` may sit inside a string.

### 4. A commit message read as a command — 1 block

```
git commit -q -m "fix(risultati): … deploy-ftp.py --plain-ftp …"   → deny
```

**Change** (`strip_commit_messages`): the quoted argument of `-m`/`--message`
is emptied in the text the project regexes see. `-F -` with a heredoc was
already covered by the data-heredoc stripping.

### 5. `.env` inside a JMESPath query — 1 block in October, 1 during this review

```
az containerapp show … --query "properties.template.containers[0].env[?name=='CACHE_STORE']…" | head
```

`SECRET_FILE` only refused a word character or `$` before `.env`; `]` passed.
The hook blocked the very probe written to reproduce it.

**Change**: `.env` is a file name only at the start of a token: after
whitespace, a quote, `=`, `/`, `(`, `{`, `,`, `:`, a redirection or a shell
separator. `sub/.env`, `"$D/.env"`, `{.env,.env.local}` are still files.

## Hardening after the automated security review

The first version of the fixes above was reviewed by the security plugin the
same day. Three findings, all valid, all addressed with a test each:

- `rm -rf $TMPDIR/x/../../etc` passed as a temp path: a `..` component now
  refuses the exemption. `TMPDIR=/ rm -rf $TMPDIR/home`, `export TMPDIR=…` or
  `unset TMPDIR` in the same command disable it entirely; `${TMPDIR:-…}` is a
  temp root only with `/tmp` or `/var/tmp` as the default.
- `git commit -m "$(scripts/deploy/promote.sh)"` was stripped as prose while
  the substitution ran: only single-quoted messages, or double-quoted ones
  without `$` and backticks, are stripped, and only in a `git commit|tag|merge|
  stash|notes` segment.
- `bash evil.py` was treated as Python by its suffix: the interpreter on the
  command line decides (`bash x.py` is shell, `python3 x.sh` is not), then the
  shebang, then the suffix. `deny_commands` still applies to non-shell scripts,
  on their code without comments and triple-quoted strings; only `ask_commands`
  is skipped there.

A second pass, on the committed version, found seven more, again all valid:

- A quote opened in an earlier argument (`git commit --trailer "x -m 'y" ;
  evil.sh ; echo "z'"`) made the regex take `'y" ; evil.sh ; echo "z'` for one
  single-quoted message and hide what the shell runs. The regex is gone: a
  scanner (`quoted_words`) tracks the quote state like the shell, finds `git` in
  command position, and blanks only an inert message token. Unbalanced quotes
  strip nothing.
- `S=$TMPDIR/a/$X; rm -rf $S` with `X=..`: after the temp root only literal
  characters are accepted, no `$`, backticks, braces, globs.
- `TMPDIR` given a value by `read`, `printf -v`, `declare`, `export`, `+=`,
  `for … in`, `getopts`, or anything through `eval`/`source`: every such form
  counts as an assignment (`assigned_names`), and `eval`/`source` in the command
  disable the exemption outright. The same list makes an alias opaque.
- A triple-quoted string that is not a docstring (`subprocess.run("""…""")`)
  was stripped too: Python docstrings are now found with `ast`, nothing else is
  removed; a file that does not parse is scanned whole. `//` lines are removed
  only in JavaScript, TypeScript and PHP.
- `source ~/.nvm/nvm.sh` was exempt from every rule: it is now scanned like an
  approved script, so the project's `deny_commands` and the removal of
  `.guardrail.json` still apply to it, only the confirmations on its own `rm`
  are skipped.
- `cat \.env` and `cat ''.env` were suspected to slip past the tightened
  `.env` lookbehind: they do not, the operands are shell-tokenized before the
  match. Two tests pin that.

A third pass found three more, two of them real bypasses reproduced by hand:

- `git commit -m $'a\' -m ' ; evil.sh ; echo ' #' #'`: an ANSI-C string keeps
  going past its escaped quote, so from there on the scanner's quote state is
  the shell's shifted by one, and a span the scanner takes for an inert
  message is code the shell runs. The scanner now strips nothing when the text
  contains `$'`, `$"`, a backtick, `$(` or a word-initial `#`.
- `ast` column offsets count UTF-8 bytes: a docstring with non-ASCII text that
  ends on a line with code took the first bytes of that code along. Lines are
  now sliced as bytes.
- `read -r A TMPDIR`, `declare -x A=1 TMPDIR=/`, `: ${TMPDIR:=/}`, `select
  TMPDIR in …`: every word of a naming builtin, the `${X:=…}` expansion and
  `select` now count as assignments.

Two things the reviews did not change: an unquoted `$TMPDIR/x` is still subject
to word splitting if `TMPDIR` holds spaces (the harness never sets such a
value), and the hook lets the tool through on an internal error, printing
"internal error, tool let through". The second is a pre-existing choice, and it
is why a name collision in this very fix (`shell_words` already existed) made
every rule pass until the suite caught it.

## Right as it is (noted, not changed)

- `git push --delete`, `git branch -D`, `docker … volumes`: asked, as intended.
- Edits to `.claude/commands/*.md`, `.claude/settings*.json`, `~/.claude/dev-mods/…`:
  asked under rules 5 and 8. Noisy in a session that edits one command file
  five times, but each is a change to what binds the agent.
- `grep APP_TIMEZONE .env`, `grep -c <token> ~/.git-credentials`: blocked by rule 4.
  Correct, and the second command had the token in clear in the command line.
- jev-hooks' own `ask_commands: ["\\bgit\\s+push\\b"]`: a project choice.

## Project configurations

Two patterns in `.guardrail.json` files matched read-only commands because they
named a file, not an invocation. gestionale-laravel had already fixed
`clone-prod-to-dev.sh` on 2026-10-05 with an anchor on the command position;
the same was applied on 2026-11-08 to:

- iro: `deploy-ftp\.py(?![^;|]*--dry-run)` fired on `grep … tools/deploy-ftp.py`
  and `sed -n … tools/deploy-ftp.py` (15 confirmations). The `--plain-ftp` block
  now exempts `--dry-run`, since the script does not connect in a dry run.
- gestionale-laravel: `az containerapp (update|revision|delete)` caught
  `revision list`, a read; `scripts/sync-azure-db-to-local\.sh` fired on a grep
  of the file.

## Deployment

- The installed plugin was bbdc4dd (Italian messages); HEAD had been English
  since 2026-10-27 under the same version number, so the cache never refreshed.
  Version bumped to 0.11.0.
- `~/repos/xml` logged 71 decisions, then was re-cloned on 2026-11-06 and lost
  its untracked `.guardrail.json`: guardrail has been off there since. A tracked
  `.guardrail.json` would travel with the clone.
- The second machine (192.168.0.27) has Claude Code 2.1.319 and jev-hooks, no
  guardrail plugin, no `.guardrail.json` in any of its 60 repos.
