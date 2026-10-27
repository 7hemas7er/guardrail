#!/usr/bin/env python3
"""Guardrail — PreToolUse hook for Claude Code.

Reads from stdin the JSON that Claude Code passes to hooks:
    {"tool_name": "...", "tool_input": {...}, "cwd": "...", "session_id": "..."}
and answers on stdout with a decision:
    allow  -> no output (the tool proceeds)
    ask    -> asks for confirmation. ⚠️ Does NOT guarantee a human: in auto mode
              the agent grants it. Only `deny` cannot be overridden.
    deny   -> blocks the tool and explains the reason to Claude

Four families of rules, all in the `decide` function:
    Bash        destructive commands, deploys that delete, SQL from the CLI on prod,
                reads of secrets from the shell (cat .env), shell writes to the
                guardrail configuration, invoked scripts (read and scanned)
    mcp__*__*   SQL queries via MCP servers: writes on prod, DELETE/UPDATE without WHERE;
                every other MCP server: destructive or mutating operations
    Write/Edit  secret files, home dotfiles, ~/.claude, the guardrail configuration
                itself, and everything outside the project
    Read        secret files, ~/.ssh and the other credential directories

With ~/.config/guardrail/mask.tsv present, it also maps the placeholders in the
tool input back to the real terms, runs every Bash command through the masking
runner and denies the tools whose result cannot be masked (see hooks/mask.py).
Without the map, no difference.

Guardrail applies only in the projects that opted in: those with a `.guardrail.json`
in the root or in a parent directory (see `is_active`). Elsewhere only the rules
that protect guardrail itself apply (its configuration, its code, the Claude Code
settings), plus masking, which follows the map and not the project.
The lists in `.guardrail.json` add up to those in `~/.guardrail.json`, which however
turns nothing on by itself. See README.md.

Standard library only. No dependencies, no network.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import time
from pathlib import Path

import mask  # hooks/mask.py: masking of reserved terms, active only with the map

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    # Regexes (case-insensitive) that, when they appear in the command or in the
    # MCP server name, mark the target as PRODUCTION.
    "prod_patterns": [r"\bprod(uction|uzione)?\b", r"\blive\b"],
    # Exact names of MCP servers that are production (often just "postgres").
    "prod_mcp_servers": [],
    # Shared but non-prod MCP servers: writes ask for confirmation.
    "ask_mcp_servers": [],
    # MCP servers that write text (documents, notes): the text of their content
    # fields does not count for recognizing a production target. Exact name only,
    # declared by whoever configures the project.
    "prose_mcp_servers": [],
    # Extra regexes on the Bash command: hard block / confirmation / exception.
    "deny_commands": [],
    "ask_commands": [],
    "allow_commands": [],
    # Scripts already read and approved: {"path": regex, "sha256": fingerprint}. They
    # exempt only the content scan, and only as long as the content does not change.
    "allow_scripts": [],
}

# The entries of these keys are objects, not regexes: they must not be converted to strings.
OBJECT_KEYS = frozenset({"allow_scripts"})

WRITE_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|REPLACE|MERGE|RENAME|VACUUM\s+FULL)\b",
    re.I,
)
READ_ONLY_START = re.compile(r"^\s*(SELECT|WITH|EXPLAIN|SHOW|DESCRIBE|DESC|TABLE|VALUES|\\d)", re.I)

# Words that say "there is SQL here". They keep the `query` field of an MCP
# server that does not speak SQL at all from being treated as a query.
SQL_KEYWORD = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|MERGE|REPLACE"
    r"|CALL|DO|COPY|EXPLAIN|SHOW|DESCRIBE|VACUUM|ANALYZE|REFRESH|BEGIN|COMMIT|ROLLBACK)\b",
    re.I,
)
# Statements that neither read nor write: they delimit a transaction or touch
# the session state. They do not turn a read into a write.
SQL_NEUTRAL = re.compile(r"^\s*(BEGIN|START\s+TRANSACTION|COMMIT|ROLLBACK|END|SET|SHOW)\b", re.I)
# `SELECT ... INTO table` creates a table: it reads like a read, it writes.
SELECT_INTO = re.compile(r"^\s*SELECT\b(?![^;]*\bINSERT\b)[^;]*\bINTO\s+[\w\".]+", re.I | re.S)
# Functions that inside a SELECT are not reads: they run SQL elsewhere, touch
# the filesystem, terminate sessions, advance sequences. `SELECT` alone proves
# nothing, and the SQL these run sits inside a literal, which is exactly where
# the skeleton does not look.
SQL_UNSAFE_FUNC = re.compile(
    r"\b(dblink(_exec)?|query_to_xml|pg_terminate_backend|pg_cancel_backend|pg_read_(binary_)?file"
    r"|pg_ls_dir|lo_(import|export|unlink)|pg_stat_statements_reset|pg_logical_slot_get_changes"
    r"|setval|nextval|load_file|sys_exec|sys_eval)\s*\(",
    re.I,
)
# MySQL: `SELECT … INTO OUTFILE` writes a file on the server.
SELECT_OUTFILE = re.compile(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", re.I)
# Opening of a dollar-quote: $$ or $tag$.
DOLLAR_TAG = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")


def normalized_sql(sql: str) -> tuple[str, bool]:
    """The SQL with literals and comments emptied, and whether the result can be trusted.

    Walks the text once keeping state — text, quoted literal (with doubled
    `''`), dollar-quote with tag, line comment, nestable block comment —
    because literals and comments interleave and no order of substitutions
    holds up: a quote inside `/* … */` is not a quote for the database, but it
    is for a regex, and a `DELETE` can hide in there.

    Applies only to pure SQL (payload of an MCP tool), NEVER to a shell line:
    there the quotes delimit the payload of `psql -c '...'` and emptying them
    would hide the real write.

    The second value is false when at the end of the text a literal or a comment
    is still open: the text is not understood, and whoever does not understand
    does not authorize.
    """
    pieces: list[str] = []
    reliable = True
    i, n = 0, len(sql)
    while i < n:
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            pieces.append(" ")
            i = n if end == -1 else end
            continue
        if sql.startswith("/*", i):
            level, j = 1, i + 2
            while j < n and level:
                if sql.startswith("/*", j):
                    level, j = level + 1, j + 2
                elif sql.startswith("*/", j):
                    level, j = level - 1, j + 2
                else:
                    j += 1
            reliable = reliable and level == 0
            pieces.append(" ")
            i = j
            continue
        if sql[i] == "'":
            j, closed = i + 1, False
            while j < n:
                if sql[j] != "'":
                    j += 1
                elif j + 1 < n and sql[j + 1] == "'":
                    j += 2
                else:
                    closed, j = True, j + 1
                    break
            reliable = reliable and closed
            pieces.append(" '' ")
            i = j
            continue
        if (opening := DOLLAR_TAG.match(sql, i)):
            tag = opening.group(0)
            closing = sql.find(tag, opening.end())
            reliable = reliable and closing != -1
            pieces.append(" '' ")
            i = n if closing == -1 else closing + len(tag)
            continue
        pieces.append(sql[i])
        i += 1
    return "".join(pieces), reliable


def classify_sql(sql: str) -> str:
    """`read`, `write` or `uncertain`.

    `uncertain` is not a fallback: it is the honest answer for a `DO $$ … $$`, a
    `CALL`, a `COPY … FROM`, an unclosed literal. Whoever receives it must not
    guess — on production it stops and shows the query.
    """
    skeleton, reliable = normalized_sql(sql)
    if not reliable:
        return "uncertain"
    statements = [s for s in skeleton.split(";") if s.strip()]
    if not statements:
        return "uncertain"
    if any(WRITE_SQL.search(s) or SELECT_INTO.match(s) or SELECT_OUTFILE.search(s) for s in statements):
        return "write"
    if any(SQL_UNSAFE_FUNC.search(s) for s in statements):
        return "uncertain"
    if all(READ_ONLY_START.match(s) or SQL_NEUTRAL.match(s) for s in statements):
        return "read"
    return "uncertain"


def exposed_query(sql: str, limit: int = 300) -> str:
    """The query inside the message: whoever decides must see what would run.

    Credentials are redacted — a connection string in a payload would end up in
    the transcript and in the log — and the text is truncated, because it serves
    to decide, not to archive. Values stay visible: they are what makes the query
    judgeable. They may however be personal data, and the message says so.
    """
    clean = re.sub(r"(?i)\b(password|pwd|passwd|token|secret|api[_-]?key)\s*=\s*('[^']*'|[^\s')]+)", r"\1=***", sql)
    clean = re.sub(r"(?i)(://[^:\s/@]+):[^@\s/]+@", r"\1:***@", clean)
    clean = " ".join(clean.split())
    if len(clean) > limit:
        clean = f"{clean[:limit]}… (+{len(clean) - limit} characters)"
    return clean

# Maximum size of an invoked script that the hook agrees to read.
SCRIPT_MAX_BYTES = 256 * 1024


def _read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def project_config(start: str) -> Path | None:
    """The .guardrail.json that applies to `start`: the first one walking up to the root.

    The one in the home does not count: those are the user's shared lists, and if it
    counted as project configuration it would turn guardrail on in every folder under
    the home.
    """
    if not start:
        return None
    try:
        current = Path(start).resolve()
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return None
    # Any entry with that name counts, not only a file: a link to /dev/null or a
    # directory in its place must not turn guardrail off.
    for candidate in [current, *current.parents]:
        probe = candidate / ".guardrail.json"
        if candidate != home and os.path.lexists(probe):
            return probe
    return None


def is_active(cwd: str) -> bool:
    """Is guardrail on here? Only where a .guardrail.json says so.

    It is enough that the working directory or the project the session started
    from (CLAUDE_PROJECT_DIR) has one: a `cd` outside the project does not turn it off.
    """
    if os.environ.get("GUARDRAIL_CONFIG"):
        return True
    return any(project_config(start) for start in (cwd or os.getcwd(), os.environ.get("CLAUDE_PROJECT_DIR", "")))


def load_config(cwd: str) -> dict:
    """Merges defaults, ~/.guardrail.json and the project's .guardrail.json."""
    config = {key: list(value) for key, value in DEFAULT_CONFIG.items()}

    sources: list[Path] = []
    override = os.environ.get("GUARDRAIL_CONFIG")
    if override:
        sources.append(Path(override))
    else:
        sources.append(Path.home() / ".guardrail.json")
        project = project_config(cwd or os.getcwd()) or project_config(os.environ.get("CLAUDE_PROJECT_DIR", ""))
        if project:
            sources.append(project)

    for source in sources:
        for key, value in _read_json(source).items():
            if key in config and isinstance(value, list):
                config[key].extend(value if key in OBJECT_KEYS else (str(item) for item in value))
    return config


def project_root(cwd: str) -> Path | None:
    """The project's git root (or the cwd itself if it is not a repo)."""
    if not cwd:
        return None
    try:
        current = Path(cwd).resolve()
    except OSError:
        return None
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return current


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

class Decision(Exception):
    def __init__(self, verdict: str, reason: str):
        super().__init__(reason)
        self.verdict = verdict
        self.reason = reason


def deny(reason: str) -> None:
    raise Decision("deny", reason)


def ask(reason: str) -> None:
    raise Decision("ask", reason)


def matches_any(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.I):
                return pattern
        except re.error:
            continue
    return None


# ---------------------------------------------------------------------------
# Bash: deletions
# ---------------------------------------------------------------------------

# `timeout [options] 60 cmd`: launches cmd, which stays in command position.
TIMEOUT_PREFIX = r"\btimeout\s+(?:[^\s;&|]+\s+)*?\d[\d.]*[smhd]?\s+"
# In command position, also behind whatever launches the following command without
# changing it: `command rm -rf "$X"` (the nvm.sh form), `env rm`, `FOO=1 rm`.
RM_PREFIX = r"(?:(?:command|builtin|exec|nohup|time|env(?:\s+-[^\s;&|]+)*|\w+=[^\s;&|]*)\s+)*"
RM_ANY = re.compile(
    r"(?:(?:^|[;&|(\n])\s*" + RM_PREFIX + r"|\bsudo\s+|\bxargs\s+(?:-[a-zA-Z0-9]+\s+)*|" + TIMEOUT_PREFIX
    + r")rm\s+(?P<args>[^;&|)\n]*)",
    re.M,
)
RM_RECURSIVE_FLAG = re.compile(r"(?:^|\s)(?:-[a-zA-Z]*r[a-zA-Z]*|--recursive)(?:\s|$)")
DANGEROUS_RM_TARGET = re.compile(
    r"""^(?:["']?)(?:
        \$|\{\$|              # variable: $HOME, $S, ${X}
        ~|                    # home
        /home/[^/\s"']+/?["']?$ |  # /home/user
        /root/?["']?$ |
        /(?:[a-z]+/?)?["']?$ |     # /, /usr, /etc ...
        \.\.?["']?$ |         # . or ..
        \.\*|\.\[|\.\.\?\*|   # hidden globs: .* .[!.]* ..?*
        \*["']?$              # * alone
    )""",
    re.X,
)
FIND_DELETE = re.compile(
    r"(?:^|[;&|(]\s*)(?:sudo\s+|" + TIMEOUT_PREFIX + r")?find\s+(?P<root>[^-\s;&|][^\s;&|]*)?[^;&|]*?(?:-delete\b|-exec\s+(?:sudo\s+)?rm\b)"
)


def check_rm(cmd: str) -> None:
    for match in RM_ANY.finditer(cmd):
        args = match.group("args")
        recursive = RM_RECURSIVE_FLAG.search(" " + args) is not None
        variable_only: str | None = None
        for arg in args.split():
            if arg.startswith("-") or not DANGEROUS_RM_TARGET.match(arg):
                continue
            # A non-recursive rm on a variable has a limited reach: confirmation,
            # not block. Everything else (recursive, home, roots, globs) is a block.
            if not recursive and re.match(r"""^["']?[$\{]""", arg):
                variable_only = variable_only or arg
                continue
            deny(
                f"rm{' (recursive)' if recursive else ''} on an unsafe target: {arg!r}. "
                "Forbidden: variables ($HOME, $DIR...), ~, system roots, '.', '..', hidden globs (.*, .[!.]*) and '*'. "
                "Use a literal path relative to the project, or ask the user to delete by hand. "
                "(guardrail: filesystem-shell-secrets.md)"
            )
        if variable_only:
            ask(
                f"rm on a variable ({variable_only!r}): the target depends on the value at execution "
                "time, and an empty variable or one with spaces deletes something else. Print the path, "
                "show it, and use the literal one. Confirm?"
            )
    for match in FIND_DELETE.finditer(cmd):
        root = match.group("root") or "."
        if root != "." and DANGEROUS_RM_TARGET.match(root):
            deny(f"find … -delete / -exec rm starting from {root!r}: recursive deletion on an unsafe target.")
        ask(
            f"find … -delete / -exec rm starting from {root!r}: deletes everything the predicate selects. "
            "First the same find without -delete, shown to the user. Confirm?"
        )


# ---------------------------------------------------------------------------
# Bash: secrets and configuration
# ---------------------------------------------------------------------------

# `\.env(?:\.[\w-]+)*` takes the *whole* chain of suffixes: with a single
# segment `.env.azure.example` would stop at `.env.azure`, and the template
# exemption (anchored at the end) would never see `.example`.
# `.env` is a file name only if it starts there: in `process.env.HOME` and
# `os.environ` it is a piece of an identifier, and reading it as the file `.env.HOME`
# is the false positive of 2026-09-28 (9 times in a week). Before it there can be
# the start, `/`, a space, a quote, `=`; never a letter or `$`.
SECRET_FILE = re.compile(
    r"(?:[\w./~-]*/)?(?:(?<![\w$])\.env(?:rc)?(?:\.[\w-]+)*(?![A-Za-z0-9])|\.secrets|\.netrc|\.pgpass|\.my\.cnf|\.htpasswd"
    r"|\.claude\.json|\.credentials\.json|credentials\.json|\.git-credentials|\.npmrc|\.pypirc"
    r"|\.aws/credentials|\.docker/config\.json|\.kube/config|gh/hosts\.yml|\.gnupg/[^\s\"']+"
    r"|[\w.-]+\.(?:pem|key|p12|pfx)|id_(?:rsa|ed25519|ecdsa|dsa))"
)
# Commands that print or transform the content of a file: the secret ends up
# in the session transcript, which stays on disk.
SECRET_READERS = re.compile(
    r"\b(cat|bat|tac|less|more|head|tail|nl|od|xxd|strings|grep|egrep|fgrep|rg|ag|awk|sed|cut|base64|jq|tee)\b"
)
SECRET_SOURCERS = re.compile(r"(?:^|[;&|]\s*)(?:source|\.)\s+\S")
# Commands whose first operand is an expression, not a file: in
# `grep "\.env" cases.jsonl` that `.env` is a regex and no secret is read.
PATTERN_COMMANDS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "perl"}
# ...unless the pattern comes from a flag: then every operand is a file.
# Also in compound form (`sed -ne`, `grep -ve`, `awk -f`).
PATTERN_FLAGS = {"-e", "--regexp", "-f", "--file", "--expression"}
PATTERN_SHORT_FLAG = re.compile(r"-[a-zA-Z]*[ef]")

# Files that govern guardrail and Claude Code: modifying them from the shell is
# the way to work around a block without going through Write/Edit.
PROTECTED_PATH = re.compile(
    r"(?:^|[\s/\"'=])(?P<path>\.guardrail\.json|\.claude/settings(?:\.local)?\.json|\.claude/CLAUDE\.md"
    r"|\.claude/(?P<plugin>plugins|hooks)(?:/[^\s\"']*)?|\.claude/(?:commands|skills|agents|rules)(?:/[^\s\"']*)?)",
    re.I,  # on NTFS (WSL, /mnt/c) .GUARDRAIL.JSON is the same file
)
SHELL_WRITER_CMDS = re.compile(
    r"(?:^|[;&|(])\s*(?:sudo\s+)?(?:tee|cp|mv|rm|sed|perl|truncate|ln|install|chmod|chattr|dd|rsync|python3?|node)\b"
)

# Who writes, and *where*. Naming a path is not modifying it: `ls .claude/hooks/`
# reads, `cp .claude/hooks/x /tmp/` copies *from* there. The direction counts, that
# is which operands are the target of the write:
#   all      every operand (rm, tee, chmod: they are all targets)
#   last     only the last one (cp, mv, ln, rsync, install: the others are sources)
#   inplace  only if the in-place edit flag is there (sed -i, perl -pi)
#   of       only the of= operand (dd)
#   opaque   not inspectable from outside (python, node): all of them, to be safe
INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
WRITER_TARGETS = {
    "tee": "all", "rm": "all", "rmdir": "all", "shred": "all", "truncate": "all",
    "mkdir": "all", "touch": "all", "chmod": "all", "chown": "all", "chattr": "all",
    "cp": "last", "mv": "last", "ln": "last", "rsync": "last", "install": "last",
    "sed": "inplace", "perl": "inplace",
    "dd": "of",
    "python": "opaque", "python3": "opaque", "node": "opaque",
}
# What stands *before* the real command: `sudo -u deploy rm x`, `FOO=1 tee y`,
# `timeout 60 grep …`.
COMMAND_PREFIX = re.compile(r"^(?:sudo|command|env|nohup|time|xargs|\w+=.*)$")
PREFIX_VALUE_FLAGS = {"-u", "-g", "-U", "-C", "-p", "-r", "-t", "-n", "-I"}
# `timeout` has a mandatory duration between itself and the command: without
# skipping it, `timeout 60 grep -o "process\.env" bin` takes 60 as the command and
# the pattern as a file. False positive of 2026-09-28.
DURATION = re.compile(r"\d+(?:\.\d+)?[smhd]?")
TIMEOUT_VALUE_FLAGS = {"-s", "-k", "--signal", "--kill-after"}


def after_timeout(tokens: list[str], index: int) -> int:
    """The index of the command that `timeout` launches: after its options and the duration."""
    while index < len(tokens) and tokens[index].startswith("-"):
        index += 2 if tokens[index] in TIMEOUT_VALUE_FLAGS else 1
    if index < len(tokens) and DURATION.fullmatch(tokens[index]):
        index += 1
    return index


def without_prefixes(tokens: list[str]) -> list[str]:
    """The real command with its arguments, stripped of what stands before it."""
    seen_prefix = False
    while tokens:
        if os.path.basename(tokens[0]) == "timeout":
            tokens = tokens[after_timeout(tokens, 1):]
            seen_prefix = False
            continue
        if COMMAND_PREFIX.match(tokens[0]):
            tokens = tokens[1:]
            seen_prefix = True
            continue
        # The flags of sudo/env/xargs, not those of the real command.
        if seen_prefix and tokens[0].startswith("-"):
            tokens = tokens[2:] if tokens[0] in PREFIX_VALUE_FLAGS else tokens[1:]
            continue
        break
    return tokens
IN_PLACE_FLAG = re.compile(r"^--in-place|^-[a-zA-Z]*i")
# Code (Python, JavaScript) that writes, deletes or moves files. Deliberately
# broad: a false alarm here only falls back to the cautious behaviour of before.
# `dumps(` stays out: `json.dumps`, `pickle.dumps`, `yaml.dump` without a stream
# produce a string, they do not touch files. On 2026-10-17 a `print(json.dumps(d))`
# on a plugin file that was only read was denied as a write.
CODE_WRITES = re.compile(
    r"\b(?:write\w*|append\w*|dump(?!s\s*\()\w*|save\w*|unlink\w*|rename\w*|rm\w*|remove\w*|copy\w*|cp\w*|move\w*"
    r"|symlink\w*|link\w*|mkdir\w*|makedirs|truncate\w*|chmod\w*|chown\w*|utime\w*|touch|replace|extract\w*"
    r"|urlretrieve|createWriteStream)\s*\("
    r"|\bopen\w*\s*\([^\n]*?['\"][rbt]*[wax+][rwabxt+]*['\"]"
    r"|\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\b|\bshutil\b|\bfs\.promises\b"
)
# Code that launches processes: there a string can become a shell command
# (`os.system("rm -rf …")`, `execSync(…)`), and the shell rules must see it.
# No `\b` in front: `asyncio.create_subprocess_shell` and `os.execvp` count.
# Dynamic access (`getattr(os, 'sys' + 'tem')`, `__import__`, `eval`) counts
# as a launch: from outside nobody knows what it calls. It is still a blacklist,
# and protects from an agent that makes a mistake, not from one looking for the hole.
SPAWNS_PROCESS = re.compile(
    r"(?:subprocess|child_process|Open3|getattr|__import__|importlib|builtins|process\.binding)"
    r"|(?:system|popen|exec\w*|spawn\w*|shell_exec|passthru|proc_open|eval|Function|globals)\s*\("
)
# `node -e '…'`, `python3 -c "…"`: the code passed as a string, whole. The
# regex finds the candidates; whether node or python really are the command is
# decided by `final_command`, which reads the line with its quotes (see judge_inline_code).
INLINE_CODE = re.compile(
    r"\b(?:node\s+(?:-[\w=-]+\s+)*?(?:-[ep]+|--eval|--print)|python[\d.]*\s+(?:-[\w=-]+\s+)*?-[a-zA-Z]*c)"
    r"""\s+(?P<code>'[^']*'|"(?:[^"\\]|\\.)*")"""
)
CODE_FLAG = re.compile(r"-[ep]+|--eval|--print|-[a-zA-Z]*c")
SHELL_PUNCTUATION = frozenset("();<>|&")


def real_segments(text: str) -> list[str] | None:
    """The segments of `text` split by the *real* separators: `;`, `|`, `&`, `(`, `)` or
    newline outside quotes, escapes and comments. Inside a segment, quoted or escaped
    punctuation (`";"`, `\\>`) becomes `_`, so that nobody later mistakes it for an
    operator: shlex in posix mode strips the quotes, and `";"` would become `;` again.

    A `\\` outside quotes takes the following character with it, newline included:
    `bash -s \\` newline `python3` is a single command, bash. A `#` at the start of
    a word opens a comment up to the newline, and there nothing is an operator.
    None if `text` ends inside a string, an escape or a comment: whoever asks about
    the commands of a line that does not close knows nothing.
    """
    segments: list[str] = []
    current: list[str] = []
    state = ""  # "" outside, "'" or '"' inside a string, "#" in a comment
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if state == "#":
            if c == "\n":
                segments.append("".join(current))
                state, current = "", []
            i += 1
            continue
        if state == "'":
            state = "" if c == "'" else state
            current.append("_" if c in "();<>|&" else c)
            i += 1
            continue
        if c == "\\":
            if i + 1 >= n:
                return None
            if text[i + 1] != "\n":
                following = text[i + 1]
                current.append("\\" + ("_" if following in "();<>|&" else following))
            i += 2
            continue
        if state == '"':
            state = "" if c == '"' else state
            current.append("_" if c in "();<>|&" else c)
            i += 1
            continue
        if c in "'\"":
            state = c
            current.append(c)
        elif c == "#" and (not current or current[-1] in " \t"):
            state = "#"
        elif c in ";|&()\n":
            segments.append("".join(current))
            current = []
        else:
            current.append(c)
        i += 1
    if state:
        return None
    return segments + ["".join(current)]


def last_segment(text: str) -> str | None:
    """The text after the last real separator (see real_segments)."""
    segments = real_segments(text)
    return None if segments is None else segments[-1]


def final_command(text: str) -> tuple[str, list[str], bool] | None:
    """The command in progress at the end of `text`, read the way the shell reads it:
    quotes included, separators (`;`, `&&`, `|`, `(`, newline) and prefixes
    (`sudo`, `env`, `FOO=1`, `timeout 60`) excluded. Name, arguments, and whether
    it has an output redirection.

    None if unknown: the end of `text` is inside a string, after an escape or in
    a comment; there is a backtick; the segment has no command. Whoever receives
    None must not conclude anything favourable.
    """
    segment = last_segment(text)
    if segment is None or "`" in segment:
        return None
    lexer = shlex.shlex(segment, punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    command: list[str] = []
    output = skip = False
    for token in tokens:
        if skip:
            skip = False
            continue
        if token and set(token) <= {"<", ">"}:
            output = output or ">" in token
            skip = True
            continue
        command.append(token)
    command = without_prefixes(command)
    if not command:
        return None
    return os.path.basename(command[0]), command[1:], output
# The target of a redirection is the token that follows it, not the command that
# contains it: `ls .claude/hooks 2>/dev/null` writes to /dev/null, not to the hooks.
REDIRECT = re.compile(r"(?:^|\s)\d*>>?\s*(?P<target>[^\s;&|<>()]+)")


def shell_segments(text: str) -> list[str]:
    return [s for s in re.split(r"[;&|\n]+|\$\(|\)", text) if s.strip()]


def redirect_targets(segment: str) -> list[str]:
    return [m.group("target") for m in REDIRECT.finditer(segment)]


def shell_tokens(segment: str) -> list[str]:
    """Tokens of the command, redirections removed. Unbalanced quotes: best effort."""
    cleaned = REDIRECT.sub(" ", segment)
    try:
        return shlex.split(cleaned)
    except ValueError:
        return cleaned.split()


def plugin_data(arg: str) -> bool:
    """`arg` is a clean path that really leads inside `~/.claude/plugins/data/`: no
    `..`, quotes or shell characters, and with links resolved it stays under there. An
    argument that merely *contains* that piece of path is not enough."""
    if arg.startswith("-") or any(c in arg for c in "'\"();`$|&<>*?[]{}\\\n") or ".." in arg.split("/"):
        return False
    try:
        base = (Path.home() / ".claude" / "plugins" / "data").resolve()
        real = Path(os.path.expanduser(arg)).resolve()
    except (OSError, RuntimeError):
        return False
    return real != base and is_inside(real, base)


def write_targets(segment: str) -> list[str]:
    """The operands the command *writes* to. A read command has none."""
    targets = redirect_targets(segment)
    tokens = without_prefixes(shell_tokens(segment))
    if not tokens:
        return targets
    mode = WRITER_TARGETS.get(os.path.basename(tokens[0]))
    if mode is None:
        return targets
    args = tokens[1:]
    flags = [a for a in args if a.startswith("-")]
    operands = [a for a in args if not a.startswith("-")]
    if mode == "of":
        return targets + [a.split("=", 1)[1] for a in args if a.startswith("of=")]
    if mode == "inplace" and not any(IN_PLACE_FLAG.match(f) for f in flags):
        return targets
    if mode == "last" and not any(f in ("-t", "--target-directory") for f in flags):
        operands = operands[-1:]
    if mode == "opaque":
        # A script that receives the path of a plugin log reads it: `.claude/plugins/data/`
        # is the plugins' data (logs, state), not their code. False positive of
        # 2026-10-07: `node join.ts ~/.claude/plugins/data/…/log.jsonl` denied as a
        # modification of the plugins. Whoever really writes there (tee, cp, rm, sed -i, `>`) is still seen.
        if not any(f in INLINE_CODE_FLAGS or re.fullmatch(r"-[a-zA-Z]*[ce]", f) for f in flags):
            operands = [a for a in operands if not plugin_data(a)]
    return targets + operands


def secret_names(values: list[str]) -> list[str]:
    """The secret file names among `values`, templates excluded (.env.example)."""
    return [
        m.group(0)
        for value in values
        for m in SECRET_FILE.finditer(value)
        if not SECRET_TEMPLATE.search(m.group(0))
    ]


def file_operands(segment: str) -> list[str]:
    """The operands the command treats as files, without the grep/sed/awk pattern."""
    tokens = without_prefixes(shell_tokens(segment))
    if not tokens:
        return []
    args = tokens[1:]
    if os.path.basename(tokens[0]) not in PATTERN_COMMANDS:
        return [a for a in args if not a.startswith("-")]
    operands: list[str] = []
    pattern_from_flag = skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if not arg.startswith("-"):
            operands.append(arg)
        elif arg.split("=", 1)[0] in PATTERN_FLAGS or PATTERN_SHORT_FLAG.fullmatch(arg):
            pattern_from_flag = True
            # The value of -e is the pattern (`sed -e "s/x/os.environ['A']/"`): it is not
            # a file. The value of -f is, and it gets read.
            skip = "=" not in arg and (arg in ("--regexp", "--expression") or (arg[1] != "-" and arg.endswith("e")))
    return operands if pattern_from_flag else operands[1:]


def check_secret_reads(text: str) -> None:
    """Blocks `cat .env` and the like: permissions.deny covers the Read tool, not the shell."""
    for segment in shell_segments(text):
        found = secret_names(file_operands(segment))
        written = secret_names(redirect_targets(segment))
        if not found and not written:
            continue
        if found and SECRET_READERS.search(segment):
            deny(
                f"read of a secret file from the shell ({found[0]}): the content would end up "
                "in the transcript, which stays on disk. For a variable's name read "
                ".env.example; for its value, ask the user. (guardrail: filesystem-shell-secrets.md)"
            )
        if found and SECRET_SOURCERS.search(segment):
            ask(
                f"source of a secret file ({found[0]}): loads credentials into the command's "
                "environment. Confirm it is intended?"
            )
        # cp/mv/ln are still caught in *both* directions: `cp .env x && cat x`
        # recycles the name. Redirections are not: they count only if they write to the secret.
        if written or (found and SHELL_WRITER_CMDS.search(segment)):
            name = (written + found)[0]
            ask(f"shell write to a secret file ({name}). Confirm it is intended and that the file is gitignored.")


def removed_paths(segment: str) -> list[str]:
    """The files the command takes away from their place: rm and unlink, the source of mv, git rm/mv."""
    tokens = without_prefixes(shell_tokens(segment))
    if not tokens:
        return []
    command, args = os.path.basename(tokens[0]), tokens[1:]
    if command == "git":
        while args and args[0].startswith("-"):
            args = args[2:] if args[0] in ("-C", "-c") else args[1:]
        if not args:
            return []
        command, args = args[0], args[1:]
    operands = [a for a in args if not a.startswith("-")]
    if command in ("rm", "unlink", "shred"):
        return operands
    if command == "mv":
        return operands if any(a in ("-t", "--target-directory") for a in args) else operands[:-1]
    return []


TURNS_GUARDRAIL_OFF = "is the file that turns guardrail on in its project"


def guardrail_name(name: str) -> bool:
    """`name` denotes .guardrail.json, also as a glob (`.guardrail*`, `.[!.]*`) or with
    different case. As in bash, a glob that does not start with the dot does not
    take hidden files: `rm *.json` does not touch it."""
    name = name.lower()
    return name.startswith(".") and fnmatch.fnmatchcase(".guardrail.json", name)


def as_path(raw: str, cwd: str) -> Path:
    path = Path(os.path.expanduser(raw.strip("\"'")))
    return path if path.is_absolute() else Path(cwd or os.getcwd()) / path


def contains_guardrail(base: Path, depth: int = 2) -> bool:
    """Is `base` a directory with a .guardrail.json, up to `depth` levels below?"""
    try:
        if base.is_symlink() or not base.is_dir():
            return False
        if os.path.lexists(base / ".guardrail.json"):
            return True
        if depth == 0:
            return False
        with os.scandir(base) as entries:
            for index, entry in enumerate(entries):
                if index > 500:
                    break
                if entry.name in ("node_modules", "vendor", ".git", ".venv", "venv"):
                    continue
                if entry.is_dir(follow_symlinks=False) and contains_guardrail(Path(entry.path), depth - 1):
                    return True
    except OSError:
        return False
    return False


def empty_operand(raw: str) -> bool:
    """An operand that, quotes and backslashes removed, names nothing.

    It is the remainder of a badly split line: in `rm -f "${D}/v*" "$(f)/x"` (nvm.sh)
    splitting on `$(` leaves an orphan `"`, which as a path is the working directory.
    So `source ~/.nvm/nvm.sh` was denied as if it deleted the project.
    """
    return not raw.strip("\"'\\ \t")


def temp_roots() -> list[Path]:
    """The system's and the session's temporary folders. Never `/`: with TMPDIR=/
    everything would be a copy. The home is excluded by `temp_copy`."""
    candidates = [Path("/tmp"), Path("/var/tmp"), Path(tempfile.gettempdir())]
    candidates += [Path(os.environ[k]) for k in ("TMPDIR", "TMP", "TEMP") if os.environ.get(k)]
    roots: list[Path] = []
    for candidate in candidates:
        try:
            real = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if real != Path(real.anchor) and real not in roots:
            roots.append(real)
    return roots


def temp_copy(folder: Path, cwd: str) -> bool:
    """Is `folder` a copy in a temporary folder that this session does not use?

    A copy of the project in /tmp (`git checkout-index`, `git archive`, `cp -r`)
    carries its .guardrail.json and its .claude/ along, which however turn on and
    configure nothing: removing or rewriting them does not turn guardrail off. It
    would only if the working directory or the session's project were inside it,
    and there the check stays. The home is never a copy, even if it sits under /tmp
    (the tests create a fake one). False positive of 2026-10-04:
    `rm -rf /tmp/claude-1000/tmp.X` denied for the copy it contained.
    """
    try:
        real = folder.resolve()
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return False
    if is_inside(real, home):
        return False
    if not any(real != root and is_inside(real, root) for root in temp_roots()):
        return False
    session = [cwd or os.getcwd(), os.environ.get("CLAUDE_PROJECT_DIR", "")]
    return not any(where and is_inside(Path(where), real) for where in session)


def governed_folder(path: Path) -> Path:
    """The folder a configuration file acts on: the one containing the
    .guardrail.json, or the project containing the .claude/ (the innermost counts)."""
    parts = path.parts
    if ".claude" in parts[:-1]:
        return Path(*parts[: len(parts) - 1 - parts[::-1].index(".claude")])
    return path.parent


def link_to_guardrail(segment: str) -> bool:
    """`ln` or `cp -l/-s` with .guardrail.json among the operands: a second name for the file."""
    tokens = without_prefixes(shell_tokens(segment))
    if not tokens:
        return False
    command, args = os.path.basename(tokens[0]), tokens[1:]
    links = command == "ln" or (
        command == "cp" and any(a in ("-l", "-s", "--link", "--symbolic-link") or re.match(r"^-[a-zA-Z]*[ls]", a) for a in args)
    )
    return links and any(guardrail_name(Path(a).name) for a in args if not a.startswith("-"))


def protected_change(match: re.Match) -> None:
    path = match.group("path")
    if match.group("plugin"):
        deny(
            f"shell modification of {path}: it is the code of the Claude Code hooks and plugins, "
            "that is of guardrail itself. It is updated with /plugin, never by hand by the agent. (guardrail: RULES-CORE.md 8)"
        )
    ask(
        f"shell modification of {path}: changes the rules that bind the agent or the user's "
        "settings. The user decides. (guardrail: RULES-CORE.md 8)"
    )


def judge_inline_code(text: str) -> str:
    """The code of `node -e` and `python3 -c` is judged whole, and then removed.

    shell_segments does not look at quotes: the parentheses and the `;` of the code
    would split the line in half, and a path read inside `require(…)` would look like
    an operand of node, that is a target. It is the false positive of 2026-10-04 on
    `.claude/plugins/known_marketplaces.json`. If the code writes or launches
    processes, the protected paths it names are targets; if not, it has none.

    It stays in the line only between double quotes with `$(` or a backtick inside:
    the shell runs those, before passing the text to the interpreter. And it stays if
    node or python are not really the command, read with the quotes: in
    `tee "; python3 -c '" .guardrail.json "'"` the command is tee, and it writes to
    .guardrail.json.
    """

    def judge(m: re.Match) -> str:
        code = m.group("code")
        if code.startswith('"') and ("$(" in code or "`" in code):
            return m.group(0)
        command = final_command(m.string[: m.start("code")])
        if (
            command is None
            or not re.fullmatch(r"node|python[\d.]*", command[0])
            or not command[1]
            or not CODE_FLAG.fullmatch(command[1][-1])
            or m.string[m.end():m.end() + 1] not in ("", " ", "\t", "\n", ";", "&", "|", ")")
        ):
            return m.group(0)
        if CODE_WRITES.search(code) or SPAWNS_PROCESS.search(code):
            for match in PROTECTED_PATH.finditer(code):
                protected_change(match)
        return m.group(0)[: m.start("code") - m.start()] + "''"

    return INLINE_CODE.sub(judge, text)


def check_protected_writes(text: str, cwd: str = "") -> None:
    """Writes and removals of the files that govern guardrail and Claude Code.

    The segments are two series. First those of shell_segments, which cuts at every `;`,
    `|` or `)` even between quotes. Then those the shell sees (real_segments): in
    `tee "; x" .guardrail.json` the blind cut leaves `x" .guardrail.json`, without a
    command, and tee's write disappears. An extra series can only add
    confirmations and blocks, never remove them.
    """
    text = judge_inline_code(text)
    for segment in shell_segments(text) + (real_segments(text) or []):
        removed = None
        for raw in removed_paths(segment):
            if empty_operand(raw):
                continue
            if guardrail_name(Path(raw).name):
                if not temp_copy(as_path(raw, cwd).parent, cwd):
                    removed = raw
            elif not any(c in raw for c in "*?[") and contains_guardrail(as_path(raw, cwd)):
                if not temp_copy(as_path(raw, cwd), cwd):
                    removed = f"{raw}, which contains a .guardrail.json"
            if removed:
                break
        if removed is None and "guardrail" in segment.lower() and FIND_DELETE.search(segment):
            removed = "a .guardrail.json (find … -delete)"
        if removed:
            deny(
                f"removal of {removed}: {TURNS_GUARDRAIL_OFF}, removing it turns it off. Turning it off is "
                "the user's decision, and they do it themselves. If a rule blocks you wrongly, explain it "
                "to the user. (guardrail: RULES-CORE.md 8)"
            )
        if link_to_guardrail(segment):
            deny(
                "a link to .guardrail.json would give it a second name, from which to rewrite it without going "
                "through the confirmation. If a copy is needed, use cp without -l/-s. (guardrail: RULES-CORE.md 8)"
            )
        for target in write_targets(segment):
            if empty_operand(target):
                continue
            # Also where it leads: `note.json` can be a link to .guardrail.json.
            try:
                real = as_path(target, cwd).resolve()
            except (OSError, RuntimeError):
                real = None
            match = PROTECTED_PATH.search(target)
            if not match and cwd and real is not None:
                match = PROTECTED_PATH.search(str(real))
            if not match:
                continue
            # The name and where it leads, both: a link in /tmp can lead to the project,
            # and a project's .guardrail.json can be a link towards /tmp.
            if real is not None and all(
                temp_copy(governed_folder(p), cwd) for p in (as_path(target, cwd), real)
            ):
                continue
            protected_change(match)


# ---------------------------------------------------------------------------
# Bash: heredocs and invoked scripts
# ---------------------------------------------------------------------------

# A heredoc that writes to a file (cat > x <<EOF, tee x <<EOF) contains data, not
# commands: quoting `git push --force` in a README is not running it. A heredoc that
# feeds an interpreter (bash <<EOF, python - <<PY) remains commands and is left alone.
# Head of a heredoc that *archives* the body instead of running it. Two forms:
#   redirection or tee     `cat > docs/git.md <<EOF`
#   git/gh reading -       `git commit -F - <<EOF`, `gh issue create --body-file - <<EOF`
# git and gh with `-F -` take stdin as text to archive, never to run:
# a commit message that *describes* a blocked command does not run it, and it is the
# normal form in which this repo documents its own blocks. `bash <<EOF` stays
# out, and its body keeps being analysed. The head line and everything that
# follows the closing tag remain analysed anyway, in every case.
#
# *Who* receives the heredoc is decided the way the shell decides it: the line up to `<<`
# is read with its quotes (shlex), and what counts is the first command of the segment
# containing `<<`, prefixes removed. A regex on the line is not enough: in
# `bash -s "; python3 x" <<'EOF'` the `;` sits inside a string, and the body is
# run by bash. If the line cannot be read (unpaired quotes, `<<` inside a
# string, `<<<`), the body remains analysed. A `(` or a backtick before `<<`
# opens another command (`tee >(bash) <<EOF`, `python3 $(bash <<EOF …)`): there the
# receiver is unknown, and the body remains analysed.
#
# A data heredoc is such only if nobody re-runs what it writes: `cat > x <<EOF
# | bash` and `tee x <<EOF | bash` pass the body to a shell. And with the tag unquoted,
# `$(…)` and the backticks in the body are run by the shell, before anything else.
HEREDOC = re.compile(
    r"(?P<head>^(?P<before>[^\n]*?)(?<!<)<<(?!<)-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)(?P<after>[^\n]*)\n)"
    r"(?P<body>.*?)(?P<end>^\s*(?P=tag)\s*$)",
    re.M | re.S,
)
GIT_STDIN_FLAGS = ("-F", "--file", "--body-file", "--notes-file")


def rewrite_heredoc(text: str, should_cut) -> str:
    """Removes the body of the heredocs for which `should_cut(m, receiver)` is true.

    The receiver is read from the *whole* command up to `<<`, not from the line alone:
    a line that looks like `python3 - <<EOF` can sit inside a string opened higher
    up (`X='` newline), and then it is not a heredoc and the text that follows is run
    by the shell. The bodies of the heredocs already met do not count for the quotes:
    the shell does not interpret them, and an apostrophe inside a text opens nothing.
    If the receiver is unknown, the body stays.
    """
    pieces: list[str] = []
    structure: list[str] = []
    pos = 0
    for m in HEREDOC.finditer(text):
        outside = text[pos:m.start()]
        pieces.append(outside)
        structure.append(outside)
        receiver = final_command("".join(structure) + m.group("before"))
        cut = receiver is not None and should_cut(m, receiver)
        # With the tag unquoted the shell runs the `$(…)` and the backticks of the body
        # before handing it to anyone: body removed, the substitutions remain.
        residue = "" if m.group("q") else "".join(f"$({s})\n" for s in shell_substitutions(m.group("body")))
        pieces.append(m.group("head") + residue + m.group("end") if cut else m.group(0))
        structure.append(m.group("head") + m.group("end") if receiver is not None else m.group(0))
        pos = m.end()
    pieces.append(text[pos:])
    return "".join(pieces)


def expands_substitutions(m: re.Match) -> bool:
    """Unquoted tag and a `$` or a backtick in the body: the shell expands the body
    before passing it to anyone, and the forms of expansion are more than `$(…)`. The
    body is then not removed, it remains analysed in full. The substitutions that
    rewrite_heredoc extracts are an extra check, not this one: if the extraction
    missed one, the whole body shows it anyway."""
    body = m.group("body")
    return not m.group("q") and ("$" in body or "`" in body)


def data_heredoc(m: re.Match, receiver: tuple[str, list[str], bool]) -> bool:
    """`cat > x <<EOF`, `tee x <<EOF`, `git commit -F - <<EOF`: the body is archived."""
    # `tee x <<'EOF' >(bash)`: tee also writes into the process substitution.
    if "|" in m.group("after") or ">(" in m.group("after"):
        return False
    if expands_substitutions(m):
        return False
    name, args, output = receiver
    if name == "cat":
        return output
    if name == "tee":
        return True
    if name in ("git", "gh"):
        return any(
            (a in GIT_STDIN_FLAGS and i + 1 < len(args) and args[i + 1] == "-") or a in {f"{f}=-" for f in GIT_STDIN_FLAGS}
            for i, a in enumerate(args)
        )
    return False

# Heredoc feeding a NON-shell interpreter: `python3 - <<PY`, `node <<JS`.
# The body is commands — for that interpreter, not for the shell.
#
# The built-in rules see it only if that code can reach the shell: if it
# launches processes (`os.system("rm -rf ...")`, `subprocess`, `child_process`), if
# the interpreter is Ruby, Perl or PHP (there `system "…"` and backticks run without
# parentheses), or if the tag is unquoted and the body contains `$(` or a
# backtick, which the shell runs *before* passing the text to the interpreter.
# Otherwise a text quoted in a Python literal is not a command: a script
# that fixes a README with `find . -delete` or `base64 -d x | sh` inside was
# stopped as if it ran them. False positive of 2026-10-03/04.
#
# The PROJECT regexes instead always cut the body.
# They are arbitrary strings (a path, a flag) written to intercept a shell
# command: met inside a Python literal they describe, they do not run.
# On 2026-09-18 `ask_commands: ["scripts/clone-prod-to-dev\\.sh"]` triggered the
# confirmation on a script that merely printed that path, and its twin in
# `deny_commands` blocked the script that was diagnosing the guard — the same
# false positive of 2026-09-17, moved from the built-in rules to the project ones.
#
# `bash`/`sh`/`zsh` stay out: there the body is shell for real, and the project
# regexes must see it.
INTERPRETERS = re.compile(r"python[\d.]*|node|ruby|perl|php|Rscript")
INTERPRETERS_WITHOUT_SHELL = re.compile(r"python[\d.]*|node|Rscript")


SCRIPT_BY_INTERPRETER = re.compile(
    r"(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?P<interp>(?:ba|z|da|k)?sh|python3?|node|php|perl|ruby)\s+"
    r"(?P<flags>(?:-[\w=-]+\s+)*)(?P<path>[^\s;&|()-][^\s;&|()]*)"
)
SCRIPT_DIRECT = re.compile(r"(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?P<path>(?:\./|\.\./|~/)[^\s;&|()]+)")
SCRIPT_SOURCED = re.compile(r"(?:^|[;&|(\n]\s*)(?:source|\.)\s+(?P<path>[^\s;&|()]+)")


def strip_data_heredocs(text: str) -> str:
    return rewrite_heredoc(text, data_heredoc)


def strip_interpreter_heredocs(text: str) -> str:
    """The text the PROJECT REGEXES apply to, and only those.

    Removes the body of the heredocs directed to a non-shell interpreter. The head
    line stays: `python3 - <<PY` is still a command, and if the head contains the
    pattern looked for, the rule triggers as before.

    For the built-in rules there is `strip_inert_heredocs`, which cuts less.
    """
    return rewrite_heredoc(
        text,
        lambda m, receiver: INTERPRETERS.fullmatch(receiver[0]) is not None and not stdin_to_a_shell(m, receiver),
    )


def strip_inert_heredocs(text: str) -> str:
    """The text for the BUILT-IN rules: without the bodies of the heredocs that cannot
    reach the shell (see the comment on HEREDOC)."""

    def inert(m: re.Match, receiver: tuple[str, list[str], bool]) -> bool:
        return (
            INTERPRETERS_WITHOUT_SHELL.fullmatch(receiver[0]) is not None
            and not SPAWNS_PROCESS.search(m.group("body"))
            and not stdin_to_a_shell(m, receiver)
            and not expands_substitutions(m)
        )

    return rewrite_heredoc(text, inert)


# ---------------------------------------------------------------------------
# Command substitutions (backtick, `$(…)`) and code that launches processes
# ---------------------------------------------------------------------------


def shell_substitutions(body: str) -> list[str]:
    """The commands the shell runs *inside* the body of a heredoc with an unquoted
    tag: `$(…)` and `` `…` ``. `\\$` and `` \\` `` are escaped, the quotes in there
    do not count. A `$(` or a backtick that does not close takes the rest of the
    body: when in doubt it remains analysed."""
    found: list[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            i += 2
        elif body.startswith("$(", i):
            end, depth, quoted = n, 1, ""
            for j in range(i + 2, n):
                k = body[j]
                if quoted:
                    quoted = "" if k == quoted else quoted
                elif k in "'\"":
                    quoted = k
                elif k == "(":
                    depth += 1
                elif k == ")":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            found.append(body[i + 2:end])
            i = end + 1
        elif c == "`":
            j = i + 1
            while j < n and body[j] != "`":
                j += 2 if body[j] == "\\" else 1
            found.append(re.sub(r"\\([`$\\])", r"\1", body[i + 1:j]))
            i = j + 1
        else:
            i += 1
    return found


def _backticks_outside(text: str, keep_quotes: bool) -> str:
    """`` `cmd` `` becomes `$(cmd)` outside single quotes and comments.
    A backtick that does not close stays as it is."""
    outside: list[str] = []
    i, n = 0, len(text)
    state = ""
    while i < n:
        c = text[i]
        if state == "'":
            state = "" if c == "'" else state
            outside.append(c)
        elif c == "\\" and i + 1 < n:
            outside.append(text[i:i + 2])
            i += 1
        elif c == "'" and keep_quotes and state == "":
            state = "'"
            outside.append(c)
        elif c == '"' and keep_quotes:
            state = "" if state == '"' else ('"' if state == "" else state)
            outside.append(c)
        elif c == "#" and state == "" and keep_quotes and (not outside or outside[-1] in " \t\n;&|("):
            end = text.find("\n", i)
            end = n if end < 0 else end
            outside.append(text[i:end])
            i = end - 1
        elif c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                outside.append(text[i:])
                break
            inside = re.sub(r"\\([`$\\])", r"\1", text[i + 1:j])
            outside.append("$(" + _backticks_outside(inside, keep_quotes) + ")")
            i = j
        else:
            outside.append(c)
        i += 1
    if state == "'" and keep_quotes:
        # A quote that does not close: nobody knows what is quoted, and everything is read.
        return _backticks_outside(text, False)
    return "".join(outside)


def _receives_data(m: re.Match) -> bool:
    """The command of the segment containing `<<` archives the body instead of running it:
    `cat`, `tee`, `git`/`gh` with `-F -`. Deliberately a closed list: whoever is not in it
    (a shell in an unforeseen form, a launcher, an unknown command) could run the body,
    and its backticks remain commands. A coarse read, which does not look at quotes: it
    only serves to decide whether the backticks of a quoted body are text."""
    before = m.string[: m.start("head")] + m.group("before")
    words = [p for p in re.split(r"\$\(|[`;|&({]", before)[-1].split() if not re.fullmatch(r"\w+=\S*", p)]
    if not words:
        return False
    name, args = words[0], words[1:]
    if name in ("cat", "tee"):
        return True
    if name in ("git", "gh"):
        return any(
            (a in GIT_STDIN_FLAGS and i + 1 < len(args) and args[i + 1] == "-") or a in {f"{f}=-" for f in GIT_STDIN_FLAGS}
            for i, a in enumerate(args)
        )
    return False


def backticks_to_substitutions(text: str) -> str:
    """A command inside `` `…` `` is run by the shell like inside `$(…)`, and the rules
    only know how to read `$(…)`: it is rewritten. The bodies of the heredocs still present
    (those nobody archived) are converted without looking at quotes: they are text of
    another language, and an apostrophe must not hide a command."""
    if "`" not in text:
        return text
    pieces: list[str] = []
    pos = 0
    for m in HEREDOC.finditer(text):
        pieces.append(_backticks_outside(text[pos:m.start("body")], True))
        # Quoted tag: the shell expands nothing. The backticks of the body are
        # text only if it is received by a command that archives (`cat`, also inside
        # `"$(cat <<'EOF' …)"`); for anyone else they remain commands.
        if m.group("q") and _receives_data(m):
            pieces.append(m.group("body"))
        else:
            pieces.append(_backticks_outside(m.group("body"), False))
        pos = m.end("body")
    pieces.append(_backticks_outside(text[pos:], True))
    return "".join(pieces)


# Stdin read by the code passed to `python3 -c` / `node -e`.
READS_STDIN = re.compile(
    r"\binput\s*\(|stdin|readFileSync\s*\(\s*0\b|/dev/stdin|\bopen\s*\(\s*0\b|readline|fileinput|\bfd\s*=\s*0\b"
)


# The code of `-c`/`-e` is not read from the arguments of `final_command`: there the
# quoted punctuation is masked. If there is a flag but the text is not found, the
# worst is assumed: it reads stdin and launches processes.
UNKNOWN_CODE = "input(stdin) system("


def _inline_code(m: re.Match, args: list[str]) -> str | None:
    """The code passed with `-c`/`-e` to the interpreter that receives the heredoc `m`; None
    if the interpreter reads a program from stdin (`python3 -`, `node`)."""
    if not any(CODE_FLAG.fullmatch(a) for a in args):
        return None
    before = m.string[: m.start("head")] + m.group("before")
    found = list(INLINE_CODE.finditer(before))
    if found and not before[found[-1].end():].strip():
        return found[-1].group("code")[1:-1]
    return UNKNOWN_CODE


def stdin_to_a_shell(m: re.Match, receiver: tuple[str, list[str], bool]) -> bool:
    """`python3 -c 'os.system(input())' <<EOF`: the code reads stdin and launches
    processes, so the heredoc body can be a shell command. It remains analysed by
    the shell rules, in full: no guessing which of the two it is."""
    name, args, _ = receiver
    if INTERPRETERS_WITHOUT_SHELL.fullmatch(name) is None:
        return False
    code = _inline_code(m, args)
    return code is not None and READS_STDIN.search(code) is not None and SPAWNS_PROCESS.search(code) is not None


# --- strings the code passes to a process launcher ---------------------------

_PY_ALWAYS_SHELL = r"system|popen|getoutput|getstatusoutput|create_subprocess_shell"
_PY_WITH_SHELL = r"run|call|check_call|check_output|Popen"
_JS_ALWAYS_SHELL = r"exec|execSync"
_JS_WITH_SHELL = r"spawn|spawnSync|execFile|execFileSync"
_CALLS = {
    False: re.compile(
        rf"(?P<n>{_PY_ALWAYS_SHELL}|{_PY_WITH_SHELL}|eval|exec)\s*\("
    ),
    True: re.compile(
        rf"(?P<n>{_JS_ALWAYS_SHELL}|{_JS_WITH_SHELL}|eval)\s*\("
    ),
}
_ALWAYS_SHELL = {
    False: frozenset(_PY_ALWAYS_SHELL.split("|")),
    True: frozenset(_JS_ALWAYS_SHELL.split("|")),
}
_SHELL_ON = re.compile(r"\bshell\s*[=:]\s*(?!False\b|false\b|0\b|None\b|null\b|undefined\b)")
_STRING_PREFIX = re.compile(r"[rRbBfFuU]{1,2}(?=['\"])")
_DYNAMIC = "$DYNAMIC"


class _Unreadable(Exception):
    pass


def _string_end(src: str, i: int, js: bool) -> int:
    """Index right after the string that starts at `i` (where the quote is)."""
    q = src[i]
    triple = not js and src.startswith(q * 3, i)
    j = i + (3 if triple else 1)
    n = len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
        elif triple and src.startswith(q * 3, j):
            return j + 3
        elif not triple and c == q:
            return j + 1
        elif not triple and c == "\n" and not (js and q == "`"):
            raise _Unreadable
        else:
            j += 1
    raise _Unreadable


def _call_end(src: str, i: int, js: bool) -> int:
    """Index of the parenthesis that closes the call opened right before `i`."""
    depth, n = 1, len(src)
    while i < n:
        c = src[i]
        if c in "'\"" or (js and c == "`"):
            i = _string_end(src, i, js)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _Unreadable


def _decode(src: str, js: bool, prefix: str, raw_text: str) -> str:
    if js:
        return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)), raw_text)
    if "f" in prefix.lower():
        return re.sub(r"\{[^{}]*\}", _DYNAMIC, raw_text.replace("{{", "{").replace("}}", "}"))
    try:
        import ast

        value = ast.literal_eval(prefix + src)
        return value if isinstance(value, str) else raw_text
    except (ValueError, SyntaxError):
        return raw_text


def _first_argument(args: str, js: bool) -> str | None:
    """The first argument of a call as shell text, if it contains literals:
    `'rm -rf ' + d` becomes `rm -rf $DYNAMIC`, because what cannot be read is a
    variable, and a variable in a destructive command is forbidden. None if there is
    no literal at all (`os.system(cmd)`): there nothing is known."""
    parts: list[str] = []
    literal = False
    i, n = 0, len(args)
    try:
        while i < n:
            c = args[i]
            if c in " \t\r\n+":
                i += 1
                continue
            if c == ",":
                break
            m = None if js else _STRING_PREFIX.match(args, i)
            start = i + (m.end() - m.start() if m else 0)
            if args[start:start + 1] in ("'", '"') or (js and c == "`"):
                end = _string_end(args, start, js)
                triple = not js and args.startswith(args[start] * 3, start)
                length = 3 if triple else 1
                raw_text = args[start + length:end - length]
                text = _decode(args[start:end], js, m.group(0) if m else "", raw_text)
                # `"rm -rf %s" % d`, `"rm -rf {}".format(d)`: the placeholder is a variable.
                rest = args[end:].lstrip()
                if not js and (rest.startswith("%") or rest.startswith(".format")):
                    text = re.sub(r"%[sdr]|\{[^{}]*\}", _DYNAMIC, text)
                parts.append(text)
                literal = True
                i = end
                continue
            # An expression that is not a literal: skip up to the next `+` or `,`.
            depth = 0
            while i < n:
                k = args[i]
                if k in "'\"" or (js and k == "`"):
                    i = _string_end(args, i, js)
                    continue
                if k in "([{":
                    depth += 1
                elif k in ")]}":
                    depth -= 1
                elif depth <= 0 and k in ",+":
                    break
                i += 1
            parts.append(_DYNAMIC)
    except _Unreadable:
        return "".join(parts) if literal else None
    return "".join(parts) if literal else None


def launched_commands(src: str, js: bool, depth: int = 0, raw_mode: bool = False) -> list[str]:
    """The strings that the code `src` (Python if `js` is false, JavaScript if true)
    passes to a call that runs them as a shell command: `os.system`,
    `os.popen`, `subprocess.*(…, shell=True)`, `child_process.exec`/`execSync`, and
    also `eval`/`exec` of a literal, which are code in turn. A list of
    arguments without a shell (`subprocess.run(['git', 'status'])`) does not launch
    a shell and does not count. Comments and strings that nobody passes do not count.

    If the read gets tangled (a string that does not close), the text is reread
    *without* skipping comments and strings: more false alarms, never a gap."""
    found: list[str] = []
    if depth > MAX_DEPTH:
        return found
    call = _CALLS[js]
    i, n = 0, len(src)
    try:
        while i < n:
            c = src[i]
            if not raw_mode:
                if (c == "#" and not js) or (js and src.startswith("//", i)):
                    j = src.find("\n", i)
                    i = n if j < 0 else j
                    continue
                if js and src.startswith("/*", i):
                    j = src.find("*/", i + 2)
                    i = n if j < 0 else j + 2
                    continue
                if c in "'\"" or (js and c == "`"):
                    end = _string_end(src, i, js)
                    if js and c == "`":
                        for e in re.finditer(r"\$\{([^{}]*)\}", src[i:end]):
                            found += launched_commands(e.group(1), js, depth + 1, raw_mode)
                    i = end
                    continue
            m = call.match(src, i) if (c.isalpha() or c in "_$") and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] in "_$")) else None
            if not m:
                i += 1
                continue
            end = _call_end(src, m.end(), js)
            args = src[m.end():end]
            name = m.group("n")
            if name == "eval" or (name == "exec" and not js):
                literal = _first_argument(args, js)
                if literal is not None:
                    found += launched_commands(literal, js, depth + 1, raw_mode)
            elif name in _ALWAYS_SHELL[js] or _SHELL_ON.search(args):
                command = _first_argument(args, js)
                if command is not None and command.strip():
                    found.append(command)
            i = m.end()
    except _Unreadable:
        return launched_commands(src, js, depth, True) if not raw_mode else found
    return found


def check_code_in_heredocs(text: str, config: dict, cwd: str, depth: int) -> None:
    """A Python or Node heredoc that passes a literal string to `os.system`,
    `subprocess.*(…, shell=True)`, `child_process.exec`: that string is a shell
    command, and is judged with the same checks as a Bash command. Also applies
    if the program comes from the stdin of `python3 -c 'exec(input())'`. With the
    depth ceiling of `check_inline_shell`."""
    if depth >= MAX_DEPTH or "<<" not in text:
        return

    def look(m: re.Match, receiver: tuple[str, list[str], bool]) -> bool:
        name, args, _ = receiver
        js = name == "node"
        if not (js or re.fullmatch(r"python[\d.]*", name)):
            return False
        code = _inline_code(m, args)
        # With `-c`/`-e` the body is the program only if the code reads it from stdin.
        if code is not None and not READS_STDIN.search(code):
            return False
        for command in launched_commands(m.group("body"), js):
            try:
                check_bash(command, config, cwd, depth + 1)
            except Decision as found:
                raise Decision(
                    found.verdict,
                    f"inside a command that the code passes to the shell ({command[:70]!r}): {found.reason}",
                ) from None
        return False

    rewrite_heredoc(text, look)


def syntax_only(match: re.Match) -> bool:
    """`bash -n script.sh`: the shell reads the script and checks its syntax,
    without running any of it. Scanning it as if it started stopped precisely the
    check one does before launching it (false positive of 2026-10-03/04).
    With -i the shell is interactive and -n no longer applies."""
    if not re.fullmatch(r"(?:ba|z|da|k)?sh", match.group("interp")):
        return False
    letters = "".join(f[1:] for f in match.group("flags").split() if re.fullmatch(r"-[a-zA-Z]+", f))
    return "n" in letters and "i" not in letters


def invoked_scripts(text: str, cwd: str) -> list[Path]:
    found: list[Path] = []
    for regex in (SCRIPT_BY_INTERPRETER, SCRIPT_DIRECT, SCRIPT_SOURCED):
        for match in regex.finditer(text):
            if regex is SCRIPT_BY_INTERPRETER and syntax_only(match):
                continue
            raw = match.group("path").strip("\"'")
            if "$" in raw:
                continue
            path = Path(os.path.expanduser(raw))
            if not path.is_absolute():
                path = Path(cwd or os.getcwd()) / path
            try:
                if path.is_file() and path.stat().st_size <= SCRIPT_MAX_BYTES and path not in found:
                    found.append(path)
            except OSError:
                continue
    return found


def script_approved(path: Path, content: str, config: dict) -> str:
    """Is the script in `allow_scripts` of `.guardrail.json`?

    Four answers: "yes" (path and fingerprint match), "changed" (the path was
    approved, but the content is no longer that one), "no-fingerprint" (the entry
    does not declare a sha256, so it approves nothing), "no".

    The approval is tied to the **content**, not to the name: a script approved
    today and modified tomorrow asks for confirmation again. It is the difference
    between "I have read this script" and "I trust this file forever", and
    2026-09-11 was born from a deploy script nobody had reread.
    """
    fingerprint = hashlib.sha256(content.encode("utf-8")).hexdigest()
    outcome = "no"
    for entry in config["allow_scripts"]:
        if isinstance(entry, str):
            entry = {"path": entry}
        if not isinstance(entry, dict) or not entry.get("path"):
            continue
        if matches_any([str(entry["path"])], str(path)) is None:
            continue
        declared = str(entry.get("sha256", "")).lower()
        # Without a fingerprint nothing is exempted: declaring it is the way to say
        # "I have read *this* content".
        if not declared:
            outcome = "no-fingerprint"
            continue
        if declared == fingerprint:
            return "yes"
        outcome = "changed"
    return outcome


def check_scripts(text: str, config: dict, cwd: str) -> None:
    """A launched script is a command the hook would otherwise not see."""
    for path in invoked_scripts(text, cwd):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        approval = script_approved(path, content, config)
        try:
            check_bash(content, config, cwd, depth=1)
        except Decision as found:
            # `deny_commands` is not exempted: it is the "this is never launched"
            # list, and applies even inside an approved script. The same for the
            # removal of .guardrail.json: a script does not turn guardrail off.
            if found.reason.startswith("command forbidden by the project configuration") or TURNS_GUARDRAIL_OFF in found.reason:
                deny(f"the script {path.name} contains a forbidden command: {found.reason}")
            if approval == "yes":
                continue
            warning = ""
            if approval == "changed":
                warning = (
                    f" WARNING: {path.name} is in allow_scripts, but its content is no longer the approved "
                    "one — the fingerprint in .guardrail.json does not match."
                )
            elif approval == "no-fingerprint":
                warning = (
                    f" Note: the allow_scripts entry for {path.name} does not declare a sha256, so it "
                    "exempts nothing. Add the fingerprint of the script you read."
                )
            ask(
                f"the script {path.name} contains a command that guardrail would block if launched "
                f"directly — {found.reason} Read it, show it to the user, and let them decide.{warning}"
            )


# ---------------------------------------------------------------------------
# Bash: the main function
# ---------------------------------------------------------------------------

# Shell interpreters that accept code as a *string*. `python`, `node` and the
# like stay out: their argument is not shell, and guessing its meaning would be
# worse than declaring the limit.
SHELL_INTERPRETERS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash"})
# ssh options that carry a value: that value is not the command.
SSH_VALUE_FLAGS = frozenset({"-o", "-p", "-i", "-l", "-F", "-b", "-c", "-D", "-E", "-e", "-I",
                             "-J", "-L", "-m", "-O", "-Q", "-R", "-S", "-W", "-w"})
MAX_DEPTH = 4


def inline_shell_payloads(text: str) -> list[str]:
    """The code passed to a shell as a string: `bash -c "…"`, `sh -c '…'`,
    `eval …`, `ssh host "…"`.

    The first token of that string **is** command position, and it is the only
    place the position-anchored rules (rm, find -delete, sudo, the database CLIs)
    did not look. The recursion starts only if the interpreter is really
    invoked: in `grep -n "bash -c \\"rm -rf\\""` the command is `grep`, and
    nothing happens — the defence from the false positive of 2026-09-17 stays.
    """
    lexer = shlex.shlex(text.replace("\n", " ; "), punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    payloads: list[str] = []
    try:
        tokens = list(lexer)
    except ValueError:
        return payloads

    at_start = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token in SHELL_SEPARATORS:
            at_start = True
            continue
        if not at_start:
            continue
        if ENV_ASSIGNMENT.fullmatch(token) or token in COMMAND_WRAPPERS:
            continue
        if os.path.basename(token) == "timeout":
            index = after_timeout(tokens, index)
            continue
        at_start = False
        name = os.path.basename(token)

        # `bash -c "…"`, also with compound flags (`-lc`, `-ec`).
        if name in SHELL_INTERPRETERS:
            while index < len(tokens) and tokens[index] not in SHELL_SEPARATORS:
                flag = tokens[index]
                index += 1
                if flag.startswith("-") and not flag.startswith("--") and "c" in flag:
                    if index < len(tokens) and tokens[index] not in SHELL_SEPARATORS:
                        payloads.append(tokens[index])
                        index += 1
                    break
                if not flag.startswith("-"):
                    break  # it is the path of a script: check_scripts handles it
        # `eval rm -rf "$X"`: everything that follows is code.
        elif name == "eval":
            rest = []
            while index < len(tokens) and tokens[index] not in SHELL_SEPARATORS:
                rest.append(tokens[index])
                index += 1
            if rest:
                payloads.append(" ".join(rest))
        # `ssh [options] host "…"`: the remote command is everything that follows the host.
        elif name == "ssh":
            host_seen = False
            rest = []
            while index < len(tokens) and tokens[index] not in SHELL_SEPARATORS:
                piece = tokens[index]
                index += 1
                if not host_seen:
                    if piece in SSH_VALUE_FLAGS:
                        index += 1
                        continue
                    if piece.startswith("-"):
                        continue
                    host_seen = True
                    continue
                rest.append(piece)
            if rest:
                payloads.append(" ".join(rest))
    return payloads


def check_inline_shell(text: str, config: dict, cwd: str, depth: int) -> None:
    """Analyses the code passed to a shell as a string, with the same rules.

    Unlike a script in the repo, here `deny` is not downgraded to `ask`:
    the script was written by a human and the human decides, this string was
    written by whoever wrote the command, a moment ago.
    """
    if depth >= MAX_DEPTH:
        return
    for payload in inline_shell_payloads(text):
        try:
            check_bash(payload, config, cwd, depth + 1)
        except Decision as found:
            raise Decision(
                found.verdict,
                f"inside a string passed to a shell ({payload[:70]!r}): {found.reason}",
            ) from None


def check_bash(cmd: str, config: dict, cwd: str = "", depth: int = 0) -> None:
    text = strip_data_heredocs(re.sub(r"\\\n", " ", cmd))
    check_code_in_heredocs(text, config, cwd, depth)
    # The project regexes look at the text without the bodies of the heredocs directed
    # to an interpreter: in there a path is quoted, not run. The built-in rules
    # lose them only if that code cannot reach the shell.
    project_text = strip_interpreter_heredocs(text)
    text = backticks_to_substitutions(strip_inert_heredocs(text))

    if depth == 0 and matches_any(config["allow_commands"], project_text):
        return

    if (pattern := matches_any(config["deny_commands"], project_text)):
        deny(f"command forbidden by the project configuration (.guardrail.json, rule {pattern!r}).")

    check_inline_shell(text, config, cwd, depth)
    check_rm(text)
    check_secret_reads(text)
    check_protected_writes(text, cwd)

    # System destruction or supply chain
    if re.search(r"\bsudo\s+rm\b", text):
        deny("sudo rm: privileged deletions do not go through the agent.")
    if re.search(r"\b(mkfs(\.\w+)?|dd\s+[^|;]*of=/dev/|wsl(\.exe)?\s+--unregister)\b", text):
        deny("command that destroys a filesystem or a distro.")
    if re.search(r"\bchmod\s+(-R\s+)?[0-7]*777\b", text):
        deny("chmod 777: permissions open to everyone, never.")
    if re.search(r"\b(chmod|chown|chgrp)\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+|--recursive\s+)[^;|]*\s(?:~|\$HOME|/home/[\w.-]+|/)/?(?:\s|$)", text):
        deny("recursive chmod/chown on the home or on the root: makes the user's environment unusable.")
    if re.search(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", text):
        deny("curl|sh: running code downloaded on the fly. Download the file, read it, then run it.")
    if re.search(r"\b(base64|openssl|echo|printf|xxd)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", text):
        deny("code decoded or built on the fly and passed to sh: unreadable for whoever checks. Write it to a file, then run it.")

    # The rules that follow are regexes on the text: they apply only if the program
    # appears as a word, not inside the pattern of a grep. `mirror` is an lftp
    # command and lives inside the `-e` string: the word lftp counts.
    words = shell_words(text)

    # Deploy with deletion on the target
    if "lftp" in words and re.search(r"\bmirror\b[^;|]*--delete\b", text) and not re.search(r"\bmirror\b[^;|]*--dry-run\b", text):
        deny("lftp mirror --delete without --dry-run: deletes on the remote server everything missing locally. (guardrail: deploy-infrastructure.md)")
    if rsync_that_deletes(text):
        deny("rsync --delete without --dry-run / -n: deletes on the target. First the dry-run, then the user decides.")

    # Git
    if "git" in words:
        if re.search(r"\bgit\b[^;|]*\bpush\b[^;|]*(\s--force(?!-with-lease)\b|\s-f\b|\s\+\S+)", text):
            deny("git push --force: rewrites shared history. Never. If needed, --force-with-lease on a personal branch, with confirmation.")
        if re.search(r"\bgit\b[^;|]*\bpush\b[^;|]*--force-with-lease", text):
            ask("git push --force-with-lease: acceptable only on a personal branch. Confirm?")
        if re.search(r"\bgit\b[^;|]*\bpush\b[^;|]*(\s--delete\b|\s-d\b|\s:\S)", text):
            ask("git push --delete: deletes a branch or a tag on the remote, for everyone. Confirm?")
        if re.search(r"\bgit\b[^;|]*\bclean\b[^;|]*\s-[a-zA-Z]*[xX]", text):
            deny("git clean -x/-X: also deletes ignored files, that is .env and the local credentials.")
        if re.search(r"\bgit\b[^;|]*\bclean\b[^;|]*\s-[a-zA-Z]*f", text):
            ask("git clean -f: deletes untracked files, not recoverable. Confirm?")
        if re.search(r"\bgit\b[^;|]*\breset\s+--hard\b", text):
            ask("git reset --hard: discards uncommitted changes. Confirm?")
        if re.search(r"\bgit\b[^;|]*\b(checkout|restore)\s+(--\s+)?\.(\s|$)", text):
            ask("git checkout/restore .: discards all local changes. Confirm?")
        if re.search(r"\bgit\b[^;|]*\bbranch\b[^;|]*\s-D\b", text):
            ask("git branch -D: deletes a branch even if it has not been merged. Confirm?")
        if re.search(r"\bgit\b[^;|]*\bstash\s+(drop|clear)\b", text):
            ask("git stash drop/clear: stashed work that disappears. Confirm?")

    # Laravel: commands that destroy the schema
    if re.search(r"\bartisan\s+(migrate:fresh|db:wipe|migrate:reset)\b", text):
        deny("artisan migrate:fresh / db:wipe / migrate:reset: drop the tables, including those the migrations do not recreate. Only by hand, on a throwaway DB. (guardrail: database.md)")
    if re.search(r"\bartisan\s+migrate:rollback\b", text):
        ask("artisan migrate:rollback: undoes migrations already applied. On which DB? Confirm.")
    if re.search(r"\bartisan\s+db:seed\b[^;|]*RolePermissionSeeder", text):
        ask("RolePermissionSeeder overwrites the manual assignments of roles and permissions. Confirm that it is NOT a DB with real data.")

    # Docker: volumes = databases; the home mounted in a container = no rule
    if re.search(r"\bdocker\s+(system\s+prune|volume\s+(rm|prune)|compose\s+down\b[^;|]*(-v\b|--volumes))", text):
        ask("Docker: this operation deletes volumes, that is local databases. Confirm?")
    if re.search(r"\bdocker\b[^;|]*\s(?:-v|--volume)[\s=]+[\"']?(?:~|\$HOME|/home/[\w.-]+|/)/?:", text) or re.search(
        r"\bdocker\b[^;|]*--mount[^;|]*\bsource=[\"']?(?:~|\$HOME|/home/[\w.-]+|/)/?[,\"'\s]", text
    ):
        ask("docker with the home or the root mounted in the container: from inside, no rule applies any more. Mount a project directory. Confirm?")

    # SQL from the command line
    check_sql_cli(text, config)

    # Invoked scripts: they are read and scanned with the same rules
    if depth == 0:
        check_scripts(text, config, cwd)

    # Privileges: never silently
    if re.search(r"(?:^|[;&|(]\s*)sudo\b", text):
        ask("sudo: a privileged command. What does it do, and why does it need root? Confirm.")

    if (pattern := matches_any(config["ask_commands"], project_text)):
        ask(f"command that requires confirmation per the project configuration (rule {pattern!r}).")


RSYNC = re.compile(r"(?:[\w./~-]*/)?rsync")
DRY_RUN_SHORT = re.compile(r"-[a-zA-Z]*n[a-zA-Z]*")


def rsync_that_deletes(text: str) -> bool:
    """rsync *executed* with --delete and without dry-run.

    `--delete` counts only as an option of an rsync in the same segment, token by
    token: in `sed -i 's/rsync -a --delete-after /rsync -a /' x; grep rsync x`
    rsync is a word of the command and --delete appears in the text, but both
    sit inside the sed pattern, which was removing that --delete. False
    positive of 2026-10-03. `timeout 60 rsync …` and `find … -exec rsync …` are still
    caught: rsync is a token of the segment even if it is not the first.
    """
    for segment in shell_segments(text):
        tokens = shell_tokens(segment)
        for index, token in enumerate(tokens):
            if not RSYNC.fullmatch(token):
                continue
            options = tokens[index + 1:]
            deletes = any(o.startswith("--delete") or o == "--del" for o in options)
            dry_run = any(o == "--dry-run" or DRY_RUN_SHORT.fullmatch(o) for o in options)
            if deletes and not dry_run:
                return True
    return False


SQL_CLI_NAMES = frozenset(
    {"psql", "mysql", "mariadb", "sqlcmd", "pg_restore", "dropdb", "createdb", "mongosh", "redis-cli"}
)
# Tokens that stand before the real command without being it.
COMMAND_WRAPPERS = frozenset({"sudo", "env", "command", "exec", "time", "nohup", "xargs", "then", "do", "else", "!"})
# Separators after which a command starts again.
SHELL_SEPARATORS = frozenset({";", "|", "||", "&", "&&", "(", ")", "{", "}", "&|"})
ENV_ASSIGNMENT = re.compile(r"\w+=.*", re.S)


def invoked_commands(text: str) -> frozenset[str]:
    """The commands the text *runs*, not those it names.

    `grep -n "dropdb" hooks/guard.py` deletes no database, and neither does a
    line of code that contains that word inside a string: the name sits
    in argument position, not in command position. Looking for it as text is the
    false positive of 2026-09-17, and blocks precisely whoever is diagnosing the guard.

    A newline counts as `;`, because every line starts again with a command;
    it must be replaced first, though, not line by line: a string spanning
    several lines would leave every line with unpaired quotes.

    posix=True: `\\"` is an escape, as in the real shell. Without it, an escaped
    quote inside an argument restarts the read in the middle of a string, and a
    name quoted in there looks like a command.

    If the quotes do not balance it falls back to the textual behaviour of before
    — all the words — which errs on the side of caution.
    """
    lexer = shlex.shlex(text.replace("\n", " ; "), punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    names: set[str] = set()
    at_start = True
    skip_next = False
    in_timeout = False
    try:
        for token in lexer:
            if skip_next:  # the target of a redirection is not a command
                skip_next = False
                continue
            if token and set(token) <= {"<", ">"}:
                skip_next = True
                continue
            if token in SHELL_SEPARATORS:
                at_start = True
                in_timeout = False
                continue
            if not at_start:
                continue
            # `timeout -k 5 60 psql …`: options and duration are not the command.
            if in_timeout:
                if token in TIMEOUT_VALUE_FLAGS:
                    skip_next = True
                    continue
                if token.startswith("-"):
                    continue
                in_timeout = False
                if DURATION.fullmatch(token):
                    continue
            if os.path.basename(token) == "timeout":
                in_timeout = True
                continue
            if ENV_ASSIGNMENT.fullmatch(token):  # PGPASSWORD=x psql ...
                continue
            if token in COMMAND_WRAPPERS or token.startswith("-"):
                continue
            names.add(os.path.basename(token))
            at_start = False
    except ValueError:
        return frozenset(re.findall(r"[\w.-]+", text))
    return frozenset(names)


def shell_words(text: str) -> frozenset[str]:
    """The words the text contains *as words*, in any position.

    Broader than `invoked_commands`: `timeout 60 rsync …` and `find … -exec rsync …`
    run rsync without putting it at the head of the command, and here they count.
    Narrower than the raw text: in `grep -rlE "rsync.*--delete" scripts/` the word
    rsync is not there, there is the pattern `rsync.*--delete`, which syncs nothing.
    It is the false positive of 2026-09-23, during /guardrail:setup.

    A command substitution (`$(…)`, backtick) runs even inside double quotes,
    and unpaired quotes cannot be read: in those cases it falls back to all the
    words of the text, which errs on the side of caution.
    """
    if "$(" in text or "`" in text:
        return frozenset(re.findall(r"[\w.-]+", text))
    lexer = shlex.shlex(text.replace("\n", " ; "), punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return frozenset(os.path.basename(token) for token in lexer)
    except ValueError:
        return frozenset(re.findall(r"[\w.-]+", text))


# The target of a connection, and only that. It serves to tell apart
# `pg_dump -h prod | psql -h localhost` (a clone towards a sandbox: legitimate,
# see database.md) from `psql -h prod -f dump.sql` (a dump going back into
# production): looking for "prod" in the whole command the two are identical.
CONN_FLAGS = frozenset({"-h", "--host", "-d", "--dbname", "--database", "-U", "--username", "--service"})
# Flags that carry any value: that value is not a target.
OTHER_VALUE_FLAGS = frozenset(
    {"-c", "--command", "-f", "--file", "-o", "--output", "-p", "--port", "-P", "-v", "--set",
     "--variable", "-e", "--execute", "-L", "--log-file", "-j", "-T", "-F", "-n"}
)
CONN_ENV = re.compile(
    r"(?:PG(?:HOST|HOSTADDR|DATABASE|SERVICE)|MYSQL_(?:HOST|DATABASE)|DATABASE_URL|DB_(?:HOST|NAME|DATABASE))"
    r"=(?P<value>.*)",
    re.I | re.S,
)
CONN_URI = re.compile(r"(?:postgres(?:ql)?|mysql|mariadb)://", re.I)
LOOKS_LIKE_FILE = re.compile(r"[/\\]|\.\w+$")
# Commands that can appear in the same chain without being a target.
DUMP_COMMANDS = frozenset({"pg_dump", "pg_dumpall", "mysqldump", "cat", "zcat", "gunzip", "gzip", "sudo", "env"})


def connection_targets(segment: str) -> str:
    """The parts of a command that say *which database* it points to: host, database
    name, connection URI, environment variables.

    File names are deliberately left out: a dump is often called
    `dump_production.sql`, and a file name is not a target.
    """
    targets: list[str] = []
    pending_conn = False
    skip_value = False
    for token in shell_tokens(segment):
        if pending_conn:
            targets.append(token)
            pending_conn = False
            continue
        if skip_value:
            skip_value = False
            continue
        flag, separator, inline = token.partition("=")
        if flag in CONN_FLAGS:
            if separator:
                targets.append(inline)
            else:
                pending_conn = True
        elif flag in OTHER_VALUE_FLAGS:
            skip_value = not separator
        elif (match := CONN_ENV.fullmatch(token)):
            targets.append(match.group("value"))
        elif CONN_URI.match(token):
            targets.append(token)
        elif token.startswith("-"):
            continue
        elif not LOOKS_LIKE_FILE.search(token) and os.path.basename(token) not in SQL_CLI_NAMES | DUMP_COMMANDS:
            targets.append(token)  # the database name, positional
    return " ".join(targets)


RESTORE_CLI = re.compile(r"\b(?:psql|mysql|mariadb)\b")
# A file or a pipe as input: the SQL is carried by the file, not by the command.
FILE_INPUT = re.compile(r"(?:^|\s)(?:-f|--file)[=\s]|(?<!<)<(?![<(])")
PG_RESTORE_TARGET = re.compile(r"(?:^|\s)(?:-d|--dbname)[=\s]")


def pipeline_segments(text: str) -> list[tuple[str, bool]]:
    """Every command of the line, and whether it receives stdin from a pipe."""
    parts = re.split(r"(\|\||&&|[;\n|])", text)
    segments: list[tuple[str, bool]] = []
    from_pipe = False
    for index in range(0, len(parts), 2):
        if parts[index].strip():
            segments.append((parts[index], from_pipe))
        separator = parts[index + 1] if index + 1 < len(parts) else ""
        from_pipe = separator == "|"
    return segments


def check_restore_into_prod(text: str, config: dict) -> None:
    """A dump going back into production contains no SQL verbs: the file carries them.

    It is the reverse direction of the production → local sandbox clone, and it is the
    only way that clone can do harm: `psql -h prod -f dump.sql` rewrites the
    database without a single word of SQL appearing in the command.
    """
    for segment, from_pipe in pipeline_segments(text):
        if RESTORE_CLI.search(segment):
            fed = from_pipe or FILE_INPUT.search(segment) is not None
        elif re.search(r"\bpg_restore\b", segment):
            fed = PG_RESTORE_TARGET.search(segment) is not None
        else:
            continue
        if not fed:
            continue
        if (pattern := matches_any(config["prod_patterns"], connection_targets(segment))):
            deny(
                "a dump going back into PRODUCTION: the input file (or pipe) runs SQL that is not "
                f"visible in the command, and the target is production (rule {pattern!r}). The clone goes in "
                "one direction only, production → local. (guardrail: database.md)"
            )


def check_sql_cli(text: str, config: dict) -> None:
    invoked = invoked_commands(text)
    if not invoked & SQL_CLI_NAMES:
        return
    is_prod = matches_any(config["prod_patterns"], text) is not None

    check_restore_into_prod(text, config)

    if "dropdb" in invoked:
        deny("dropdb: deletes a whole database.") if is_prod else ask("dropdb on a non-production DB: confirm?")
    if "pg_restore" in invoked and re.search(r"\bpg_restore\b[^;|]*(--clean|-c\b)", text) and is_prod:
        deny("pg_restore --clean towards production: drops the objects before recreating them.")
    if "redis-cli" in invoked and re.search(r"\bredis-cli\b[^;|]*\b(FLUSHALL|FLUSHDB)\b", text, re.I):
        deny("FLUSHALL/FLUSHDB: empties Redis, hence cache, queues and sessions.")

    if WRITE_SQL.search(text):
        if is_prod:
            deny("write SQL towards a PRODUCTION database. Production is read only; every change goes through a migration in the repo or a human operator. (guardrail: database.md)")
        check_unbounded_writes(text)


def check_unbounded_writes(sql: str) -> None:
    if re.search(r"\bDROP\s+(DATABASE|SCHEMA)\b", sql, re.I):
        deny("DROP DATABASE/SCHEMA: never from the agent, on any environment.")
    if re.search(r"\bTRUNCATE\b", sql, re.I):
        deny("TRUNCATE: empties a table with no possibility of logical rollback. If needed, a human does it.")
    for statement in re.split(r";", sql):
        if re.search(r"\bDELETE\s+FROM\s+[\w\".]+", statement, re.I) and not re.search(r"\bWHERE\b", statement, re.I):
            deny("DELETE without WHERE: deletes the whole table. Add a tight predicate.")
        if re.search(r"\bUPDATE\s+[\w\".]+\s+SET\b", statement, re.I) and not re.search(r"\bWHERE\b", statement, re.I):
            deny("UPDATE without WHERE: rewrites the whole table. Add a tight predicate.")


# ---------------------------------------------------------------------------
# MCP: SQL servers, and all the others
# ---------------------------------------------------------------------------

MCP_TOOL = re.compile(r"^mcp__(?P<server>[^_].*?)__(?P<tool>[^_].*)$")
MCP_READ_TOOL = re.compile(r"^(get|list|read|show|describe|search|find|fetch|lookup|check|view|status|info|explain|count|export|browse|preview|query|resolve)(?=$|[_\-\s])", re.I)
# tool_input keys that describe the operation (Azure MCP: "command",
# GitHub MCP: "method"/"state"). The rest of the input is parameters, not intentions.
MCP_OP_KEYS = ("command", "operation", "action", "method", "op", "intent", "state", "mode", "verb")
MCP_DESTRUCTIVE = re.compile(
    r"\b(delete|remove|purge|destroy|drop|wipe|truncate|prune|reset|unregister|deallocate|revoke|force|closed?|dismiss|archive)\b",
    re.I,
)
MCP_MUTATING = re.compile(
    r"\b(create|update|set|write|put|patch|push|deploy|scale|restart|start|stop|merge|upload|import|restore|rotate"
    r"|assign|grant|enable|disable|apply|edit|rename|move|tag|publish|submit|send|post|add|invite|approve|reopen)\b",
    re.I,
)


# Documentation tools (context7: query-docs, resolve-library-id): their
# `query` is a natural-language question, and "with line and column" is not
# a CTE. Classifying it as SQL gave "not classifiable" (2026-10-01/04).
# They remain subject to the generic MCP tool rules below.
MCP_DOCS_TOOL = re.compile(r"(?:^|[_-])(?:docs?|documentation|librar(?:y|ies))(?:$|[_-])", re.I)
# Closing the test browser or one of its tabs deletes nothing: Playwright
# (browser_close, browser_tabs with action=close), Chrome DevTools (close_page).
MCP_BROWSER_CLOSE = re.compile(r"\b(?:browser|page|tabs?)\s+close\b|\bclose\s+(?:browser|page|tabs?)\b", re.I)


def extract_sql(tool_input: dict) -> str:
    for key in ("sql", "query", "statement", "command", "text"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def mcp_operation_text(tool: str, tool_input: dict) -> str:
    parts = [tool.replace("_", " ").replace("-", " ")]
    for key in MCP_OP_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


# Fields in which a server of `prose_mcp_servers` receives the text to write.
MCP_CONTENT_KEYS = frozenset(
    ("content", "body", "text", "markdown", "message", "description", "comment", "title", "intent", "summary", "notes")
)


def mcp_target_text(tool_input: dict, prose: bool = False) -> str:
    """The MCP parameters as text, to recognize a production target.

    By default everything counts: a `body` can carry the target in any form
    (JSON, JSON5, form-encoded, text), and trying to parse it opens the door to
    the differences between our parser and the server's. Only for a server that
    writes text, declared in `prose_mcp_servers`, the strings of the content
    fields do not count: on 2026-10-05 a document that talked about production
    was blocked as a change to production. Identifiers still count.
    No recursion: a deeply nested input would make the check fail, and an
    internal error lets the tool through.
    """
    parts: list[str] = []
    stack: list[tuple[str, object]] = [("", tool_input)]
    while stack:
        key, value = stack.pop()
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(str(k))
                stack.append((str(k), v))
        elif isinstance(value, list):
            stack.extend((key, v) for v in value)
        elif prose and isinstance(value, str) and key.lower() in MCP_CONTENT_KEYS:
            continue
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts)


def check_mcp(tool_name: str, tool_input: dict, config: dict) -> None:
    match = MCP_TOOL.match(tool_name)
    if not match:
        return
    server, tool = match.group("server"), match.group("tool")
    is_prod = server in config["prod_mcp_servers"] or matches_any(config["prod_patterns"], server) is not None
    is_shared = server in config["ask_mcp_servers"]

    sql = extract_sql(tool_input)
    # The classification tells the three possible answers apart, and the only one
    # that authorizes is "read": a read-only query stays allowed everywhere,
    # production included, even when a compared value contains a write verb.
    # Everything else is shown to whoever has to decide.
    if (
        sql
        and re.search(r"(query|sql|execute|run|statement)", tool, re.I)
        and not MCP_DOCS_TOOL.search(tool)
        and SQL_KEYWORD.search(sql)
    ):
        verdict = classify_sql(sql)
        if verdict == "read":
            return
        text = exposed_query(sql)
        if verdict == "uncertain":
            why = (
                "I cannot tell whether it reads or writes: it contains a comment, a dollar-quote, an "
                "unclosed literal or a statement that cannot be classified (CALL, DO, COPY…), and there the "
                "boundary between code and data cannot be read with certainty"
            )
            if is_prod:
                deny(
                    f"unclassifiable query on the MCP server {server!r}, which is PRODUCTION — {why}.\n"
                    f"This would have been run:\n    {text}\n"
                    "Rewrite it without comments or dollar-quotes and with the literals closed, so I can "
                    "recognize it as a read; if it really has to write, an operator runs it. "
                    "(guardrail: database.md)"
                )
            ask(
                f"unclassifiable query on the MCP server {server!r} — {why}.\n"
                f"This is about to be run:\n    {text}\nConfirm?"
            )
        if is_prod:
            deny(
                f"SQL write on the MCP server {server!r}, which is PRODUCTION. In production the agent "
                f"only reads; changes go through a migration in the repo or an operator.\n"
                f"This would have been run:\n    {text}\n(guardrail: database.md)"
            )
        check_unbounded_writes(normalized_sql(sql)[0])
        if is_shared:
            ask(
                f"SQL write on the MCP server {server!r}, shared with other people.\n"
                f"This is about to be run:\n    {text}\nConfirm?"
            )
        return

    # Every other server: Azure, GitHub, filesystem, ... The intention sits in the
    # tool name and in the fields describing the operation; the parameters say
    # whether the target is production.
    if MCP_READ_TOOL.match(tool):
        return
    operation = MCP_BROWSER_CLOSE.sub(" ", mcp_operation_text(tool, tool_input))
    prose = server in config["prose_mcp_servers"]
    targets_prod = is_prod or matches_any(config["prod_patterns"], mcp_target_text(tool_input, prose)) is not None

    if MCP_DESTRUCTIVE.search(operation):
        if targets_prod:
            deny(f"destructive operation via MCP {server!r} ({operation.strip()}) on a PRODUCTION target. Never from the agent.")
        ask(f"destructive operation via MCP {server!r}: {operation.strip()}. What disappears, and can it be recreated? Confirm.")
    if MCP_MUTATING.search(operation):
        if targets_prod:
            deny(f"change via MCP {server!r} ({operation.strip()}) on a PRODUCTION target. Production is read only; changes go through a deploy or a human operator.")
        if is_shared:
            ask(f"change via MCP {server!r} ({operation.strip()}) on a shared service. Confirm?")


# ---------------------------------------------------------------------------
# Read / Write / Edit
# ---------------------------------------------------------------------------

SECRET_NAME = re.compile(
    r"^(\.env(\..+)?|\.secrets|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_(rsa|ed25519|ecdsa|dsa)(\.pub)?|\.netrc|\.pgpass|\.my\.cnf"
    r"|\.htpasswd|\.claude\.json|\.credentials\.json|credentials\.json|\.git-credentials|\.npmrc|\.pypirc)$"
)
SECRET_TEMPLATE = re.compile(r"\.(example|sample|template|dist)$")
SECRET_DIRS = {".ssh", ".aws", ".azure", ".kube", ".gnupg"}
SECRET_TAILS = ((".docker", "config.json"), ("gh", "hosts.yml"))

# Under ~/.claude: what governs the agent's behaviour. The rest
# (projects/, todos/, debug/...) is Claude Code's internal state and is not touched here.
CLAUDE_HOME_GOVERNANCE = {"settings.json", "settings.local.json", "CLAUDE.md", "keybindings.json"}
CLAUDE_HOME_GOVERNANCE_DIRS = {"commands", "skills", "agents", "rules", "output-styles"}
CLAUDE_HOME_CODE_DIRS = {"plugins", "hooks"}


def target_path(tool_input: dict) -> Path | None:
    raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path")
    if not isinstance(raw, str) or not raw:
        return None
    return Path(os.path.expanduser(raw))


def is_secret_file(name: str) -> bool:
    return bool(SECRET_NAME.match(name)) and not SECRET_TEMPLATE.search(name)


def is_secret_path(path: Path) -> bool:
    parts = path.parts
    if any(part in SECRET_DIRS for part in parts):
        return True
    for parent, name in SECRET_TAILS:
        if len(parts) >= 2 and parts[-1] == name and parts[-2] == parent:
            return True
    return is_secret_file(path.name)


def relative_to_home(path: Path) -> Path | None:
    try:
        return path.resolve().relative_to(Path.home())
    except (ValueError, OSError):
        return None


def check_read(tool_input: dict) -> None:
    """Reads of secrets no longer depend on permissions.deny in the settings."""
    path = target_path(tool_input)
    if path is None:
        return
    if any(part == ".ssh" for part in path.parts):
        deny(f"read inside ~/.ssh ({path}): SSH keys and configuration do not go through the agent.")
    if is_secret_path(path):
        deny(
            f"read of a secret file ({path}): the content would end up in the transcript, "
            "which stays on disk. For a variable's name read .env.example; for its value, "
            "ask the user. (guardrail: filesystem-shell-secrets.md)"
        )


def is_inside(path: Path, root: Path | None) -> bool:
    if root is None:
        return False
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def check_write_guardrail(path: Path) -> None:
    """Writes on guardrail itself: its code, its configuration, the Claude Code
    settings. They apply even where guardrail is off (see `decide`).
    Where the path leads is checked too: `note.json` can be a link."""
    try:
        real = path.resolve()
    except (OSError, RuntimeError):
        real = path
    for candidate in dict.fromkeys([path, real]):
        _check_write_guardrail(candidate)


def _check_write_guardrail(path: Path) -> None:
    raw = str(path)
    name = path.name
    in_home = relative_to_home(path)
    if in_home is not None and in_home.parts[:1] == (".claude",) and len(in_home.parts) > 2 and in_home.parts[1] in CLAUDE_HOME_CODE_DIRS:
        deny(
            f"write in ~/.claude/{in_home.parts[1]} ({raw}): it is the code of the hooks and plugins, that is of "
            "guardrail itself. It is updated with /plugin, never by hand by the agent. (guardrail: RULES-CORE.md 8)"
        )

    # Confirmations: the configuration of guardrail and of Claude Code is not modified
    # on one's own, it would be the elegant way to work around a block (RULES-CORE.md, rule 8).
    if name.lower() == ".guardrail.json":
        ask(
            "change to .guardrail.json: changes the guardrail rules that bind you. "
            "The user decides, and the file must be committed with the rationale. (guardrail: RULES-CORE.md 8)"
        )
    if in_home is not None and in_home.parts[:1] == (".claude",) and (
        (len(in_home.parts) == 2 and name in CLAUDE_HOME_GOVERNANCE)
        or (len(in_home.parts) > 2 and in_home.parts[1] in CLAUDE_HOME_GOVERNANCE_DIRS)
    ):
        ask(
            f"change to the Claude Code configuration ({raw}): touches the user's permissions, hooks, commands or "
            "instructions. Show the change and have it approved."
        )
    # The same in a project's .claude/: with `enabledPlugins` or `env` its
    # settings turn guardrail off there. From the shell PROTECTED_PATH already covers it.
    parts = path.parts[:-1]
    if in_home is None or in_home.parts[:1] != (".claude",):
        if ".claude" in parts:
            rest = path.parts[len(parts) - parts[::-1].index(".claude"):]
            if rest in (("settings.json",), ("settings.local.json",), ("CLAUDE.md",)) or (
                len(rest) > 1 and rest[0] in CLAUDE_HOME_CODE_DIRS | CLAUDE_HOME_GOVERNANCE_DIRS
            ):
                ask(
                    f"change to the project's Claude Code configuration ({raw}): settings, hooks and "
                    "instructions can turn off or work around guardrail. Show the change and have it approved."
                )


def check_bash_guardrail(cmd: str, cwd: str = "", depth: int = 0) -> None:
    """From the shell, the same writes as `check_write_guardrail`, and the removal of
    .guardrail.json; also inside `bash -c "…"` and in the launched scripts."""
    text = backticks_to_substitutions(strip_inert_heredocs(strip_data_heredocs(re.sub(r"\\\n", " ", cmd))))
    check_protected_writes(text, cwd)
    if depth >= MAX_DEPTH:
        return
    for payload in inline_shell_payloads(text):
        check_bash_guardrail(payload, cwd, depth + 1)
    # Every level, not only the first: a script can launch another one.
    for path in invoked_scripts(text, cwd):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            check_bash_guardrail(content, cwd, depth + 1)
        except Decision as found:
            if found.verdict == "deny":
                deny(f"the script {path.name} contains a forbidden command: {found.reason}")
            ask(f"the script {path.name} touches the guardrail or Claude Code configuration — {found.reason}")


def check_write(tool_input: dict, cwd: str) -> None:
    path = target_path(tool_input)
    if path is None:
        return
    raw = str(path)
    name = path.name
    in_home = relative_to_home(path)

    # Hard blocks
    if any(part == ".ssh" for part in path.parts) or (SECRET_NAME.match(name) and re.search(r"id_|\.pem$|\.key$|\.p12$|\.pfx$", name)):
        deny(f"write to a private key or inside ~/.ssh ({raw}). Never from the agent.")
    if str(path).startswith("/etc/") or str(path).startswith("/usr/"):
        deny(f"write to a system file ({raw}).")
    check_write_guardrail(path)
    if is_secret_path(path):
        ask(f"write to a secret file ({raw}). Confirm it is intended and that the file is gitignored.")
    if in_home is not None and len(in_home.parts) == 1 and in_home.parts[0].startswith("."):
        ask(f"write to a home dotfile ({raw}): changes the user's environment. Confirm?")

    # Rule 5: nothing outside the project without asking. The scratchpad and Claude
    # Code's internal state (memory, todos) are legitimate working areas.
    root = project_root(cwd)
    if root is None:
        return
    allowed = [root, Path("/tmp"), Path.home() / ".claude" / "projects"]
    for env_key in ("TMPDIR", "TMP", "TEMP"):
        if os.environ.get(env_key):
            allowed.append(Path(os.environ[env_key]))
    if not any(is_inside(path, base) for base in allowed):
        ask(
            f"write outside the project ({raw}; project: {root}). The home, other repos and the "
            "system directories are touched only on explicit request. Confirm? (guardrail: RULES-CORE.md 5)"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def decide(payload: dict) -> None:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    cwd = str(payload.get("cwd") or "")

    # Where guardrail is off only the rules that protect guardrail itself apply.
    # Without them, a session opened in any folder could turn it off or loosen
    # it in the projects where it is on: by removing their .guardrail.json, by
    # writing allow_commands in ~/.guardrail.json, by touching the plugin code.
    if not is_active(cwd):
        if tool == "Bash":
            check_bash_guardrail(str(tool_input.get("command", "")), cwd)
        elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            path = target_path(tool_input)
            if path is not None:
                check_write_guardrail(path)
        return

    config = load_config(cwd)

    if tool == "Bash":
        command = str(tool_input.get("command", ""))
        try:
            check_bash_guardrail(command, cwd)
            suspended = None
        except Decision as found:
            if found.verdict == "deny":
                raise
            suspended = found
        check_bash(command, config, cwd)
        if suspended:
            raise suspended
    elif tool == "Read":
        check_read(tool_input)
    elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        check_write(tool_input, cwd)
    elif tool.startswith("mcp__"):
        check_mcp(tool, tool_input, config)


def log_decision(payload: dict, verdict: str, reason: str) -> None:
    try:
        log = Path.home() / ".claude" / "guardrail.log.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "verdict": verdict,
            "tool": payload.get("tool_name"),
            "cwd": payload.get("cwd"),
            "session": payload.get("session_id"),
            "reason": reason,
            "input": json.dumps(payload.get("tool_input"), ensure_ascii=False)[:400],
        }
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except RecursionError:
        # An input nested beyond what the parser can take cannot be judged. Letting it
        # through would mean that nesting a command is enough to skip every check.
        emit("deny", "tool input nested too deep to be checked.")
        return 0
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0

    # Masking does not follow GUARDRAIL_DISABLE: turning the checks off must not
    # put the reserved terms back in the clear. It is turned off by removing the map.
    tool = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input") or {}
    cwd = str(payload.get("cwd") or "")
    try:
        pairs = mask.load_pairs()
    except mask.InvalidMap as exc:
        # Fail-closed: with a broken map no tool result can be masked.
        log_decision(payload, "deny", str(exc))
        emit("deny", f"{exc}. Fix the map or remove it to turn masking off.")
        return 0

    # What the machine really runs (the checks are done on this, with the real
    # terms) and what the tool receives in place of the model's input.
    effective, rewritten = tool_input, None
    if pairs and tool == "Bash" and str(tool_input.get("command", "")).strip():
        command = str(tool_input["command"])
        effective = {**tool_input, "command": mask.unmask(command, pairs)}
        rewritten = {**tool_input, "command": mask.wrap_command(command)}
    elif pairs:
        rewritten = mask.unmask_tool_input(tool, tool_input, cwd, pairs)
        effective = rewritten or tool_input

    blocked = mask.blocking_reason(tool, effective, pairs)
    if blocked:
        log_decision(payload, "deny", blocked)
        emit("deny", blocked)
        return 0

    if os.environ.get("GUARDRAIL_DISABLE") == "1":
        log_decision(payload, "disabled", "GUARDRAIL_DISABLE=1")
        emit(updated_input=rewritten)
        return 0

    try:
        decide({**payload, "tool_input": effective})
    except Decision as decision:
        reason = mask.mask(decision.reason, pairs)
        log_decision(payload, decision.verdict, reason)
        emit(decision.verdict, reason, None if decision.verdict == "deny" else rewritten)
        return 0
    except Exception as exc:  # noqa: BLE001 — a bug in the guard must never block the work
        print(f"[guardrail] internal error, tool let through: {mask.mask(str(exc), pairs)}", file=sys.stderr)
    emit(updated_input=rewritten)
    return 0


def emit(verdict: str = "", reason: str = "", updated_input: dict | None = None) -> None:
    """Prints the hook's answer: the decision, if any, and the input rewritten for
    masking, if any. Neither: no output, the tool proceeds."""
    out: dict = {"hookEventName": "PreToolUse"}
    if verdict:
        out["permissionDecision"] = verdict
        out["permissionDecisionReason"] = f"[guardrail] {reason}"
    if updated_input is not None:
        out["updatedInput"] = updated_input
    if len(out) > 1:
        print(json.dumps({"hookSpecificOutput": out}, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
