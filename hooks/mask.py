#!/usr/bin/env python3
"""Guardrail — masking of reserved terms.

Some terms (names of hosts, people, places, customers) must not reach the model,
whichever way they come out: the output of a command, a document read, a search
result, the reply of an MCP server. The map lives in ~/.config/guardrail/mask.tsv,
outside every repo, one pair per line:

    real-term   placeholder        # separated by spaces or TAB; '#' comments

Without a map nothing happens. With the map, two directions:

  towards the model    every tool result goes through `mask.py output` (PostToolUse,
                       `updatedToolOutput`): every string of the result comes out with
                       the placeholders. The transcript saves the rewritten version, so
                       even a resumed session never sees the original again.
                       Bash additionally goes through `mask.py run`, which masks on the
                       way out: it is the only way to cover commands that fail, because
                       a tool's error (PostToolUseFailure) cannot be rewritten.
  towards the machine  the model writes placeholders, the tools receive real terms
                       (`unmask_tool_input`, via `updatedInput` of PreToolUse, which the
                       model does not see). Only where an error cannot send the real
                       term back: see the function.

Denied, because the result cannot be masked: the Read of PDFs, Office documents
and archives (the text is not in the bytes: via Bash pdftotext / unzip -p they come
out masked), WebFetch towards an address that contains a placeholder (a model reads
the page before any hook: for a private resource use curl via Bash), and the
commands that show the text transformed (od, xxd, base64, rev…), where the filter
no longer recognizes the words.

A prompt that contains a real term is blocked (`mask.py prompt`): a hook cannot
rewrite it, only stop it.

Not covered, and not coverable by a hook: the content of images (screenshots,
photos); the context Claude Code injects by itself (git status and recent commits,
removed with `"includeGitInstructions": false`; CLAUDE.md; files cited with @);
any other transformation of the text made on purpose to work around the filter. It
is a protection against accidental exposure, not against an agent looking for it.

Command-line usage:
    mask.py run      runs the script read from stdin with the map applied
    mask.py output   PostToolUse hook (Claude Code JSON on stdin)
    mask.py prompt   UserPromptSubmit hook (Claude Code JSON on stdin)

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent

# A term is masked only if it is not part of a longer word: `nas-warehouse` and
# `warehouse.lan` yes, `warehouses` no. The underscore counts as a separator.
_BEFORE = r"(?<![A-Za-z0-9])"
_AFTER = r"(?![A-Za-z0-9])"

# Formats whose text does not appear in the bytes (compressed or binary): the result
# of the Read cannot be masked, so it is denied. Via Bash they are converted to text.
OPAQUE_FORMATS = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".odt", ".ods", ".odp", ".epub", ".pages", ".numbers", ".key",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
})

# Commands that show a transformed text: one character per column, in hexadecimal,
# encoded, reversed. The filter works on words and there it does not recognize them:
# it happened in the first real trial, `od -c` used to understand a failed Edit
# showed the term letter by letter. A textual filter does not stop every possible
# transformation; these are the ones people reach for to "look at the bytes".
TRANSFORMING_COMMANDS = re.compile(
    r"(?:^|[\s;&|(`$])(od|xxd|hexdump|hd|base64|base32|basenc|uuencode|rev)(?=\s|$|[;&|)])"
)

# Keys of a tool result that contain encoded binary data, not text: a substitution
# in there would corrupt the image without hiding anything.
BINARY_KEYS = frozenset({"base64"})


class InvalidMap(Exception):
    pass


def map_path() -> Path:
    override = os.environ.get("GUARDRAIL_MASK_MAP")
    if override:
        return Path(override)
    return Path.home() / ".config" / "guardrail" / "mask.tsv"


def load_pairs() -> list[tuple[str, str]]:
    """[(real, placeholder)], longest terms first. Empty if there is no map.

    A map that exists but cannot be read or is inconsistent raises InvalidMap:
    whoever uses it must stop, not go on without masking.
    """
    path = map_path()
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise InvalidMap(f"map {path} unreadable: {exc}") from exc

    pairs: list[tuple[str, str]] = []
    for number, line in enumerate(lines, start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2:
            raise InvalidMap(f"map {path}, line {number}: two fields needed, real term and placeholder")
        real, fake = fields
        if real.lower() == fake.lower():
            raise InvalidMap(f"map {path}, line {number}: the placeholder coincides with the real term")
        pairs.append((real, fake))

    for real, _ in pairs:
        for _, fake in pairs:
            if _search(real).search(fake):
                raise InvalidMap(
                    f"map {path}: a placeholder contains a real term, the output would put it back in the clear"
                )
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def _search(term: str) -> re.Pattern[str]:
    return re.compile(_BEFORE + re.escape(term) + _AFTER, re.IGNORECASE)


def _same_shape(found: str, replacement: str) -> str:
    """`HOME` -> `SITE1`, `Home` -> `Site1`, the rest lowercase as in the map.

    Needed for the return trip: the model rewrites the placeholder with the capitals
    it has seen, and a sed must find the original form in the file.
    """
    if found.isupper() and len(found) > 1:
        return replacement.upper()
    if found[:1].isupper() and found[1:].islower():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def _replace(text: str, src: str, dst: str) -> str:
    return _search(src).sub(lambda m: _same_shape(m.group(0), dst), text)


def mask(text: str, pairs: list[tuple[str, str]]) -> str:
    """Real terms -> placeholders: everything that goes towards the model."""
    for real, fake in pairs:
        text = _replace(text, real, fake)
    return text


def unmask(text: str, pairs: list[tuple[str, str]]) -> str:
    """Placeholders -> real terms: what the model writes and the machine runs."""
    for real, fake in pairs:
        text = _replace(text, fake, real)
    return text


def contains_real(text: str, pairs: list[tuple[str, str]]) -> bool:
    return any(_search(real).search(text) for real, _ in pairs)


def contains_placeholder(text: str, pairs: list[tuple[str, str]]) -> bool:
    return any(_search(fake).search(text) for _, fake in pairs)


def mask_value(value: Any, pairs: list[tuple[str, str]]) -> Any:
    """Masks every string of a JSON structure, leaving keys and shape intact:
    that is the condition for Claude Code to accept the rewritten result."""
    if isinstance(value, str):
        return mask(value, pairs)
    if isinstance(value, list):
        return [mask_value(item, pairs) for item in value]
    if isinstance(value, dict):
        return {
            key: item if key in BINARY_KEYS else mask_value(item, pairs)
            for key, item in value.items()
        }
    return value


# ---------------------------------------------------------------------------
# Towards the machine: the tools' input
# ---------------------------------------------------------------------------

def wrap_command(cmd: str) -> str:
    """The Bash command rewritten: the model's text goes to the runner untouched via
    heredoc, and the runner inserts the real terms by reading the map.

    The already converted command is not put in `updatedInput`, although the model
    does not see it: the confirmation request would see it and, in auto mode, so
    would the classifier, which is itself a model.
    """
    delimiter = "__GUARDRAIL_MASK__"
    lines = cmd.splitlines()
    while delimiter in lines:
        delimiter += "_"
    runner = HERE / "run-python.sh"
    return (
        f'bash "{runner}" "{HERE / "mask.py"}" run <<\'{delimiter}\'\n'
        f"{cmd}\n"
        f"{delimiter}"
    )


def _path(raw: str, cwd: str) -> Path:
    path = Path(os.path.expanduser(raw))
    return path if path.is_absolute() or not cwd else Path(cwd) / path


def _real_path(raw: Any, cwd: str, pairs: list[tuple[str, str]]) -> Any:
    """A path with the placeholder becomes the real one only if the real one exists
    and the other does not: otherwise the "no such file" error would cite the real term."""
    if not isinstance(raw, str) or not contains_placeholder(raw, pairs):
        return raw
    real = unmask(raw, pairs)
    if _path(real, cwd).exists() and not _path(raw, cwd).exists():
        return real
    return raw


def unmask_tool_input(tool: str, tool_input: dict, cwd: str, pairs: list[tuple[str, str]]) -> dict | None:
    """The input with the placeholders turned back into real terms, or None if nothing changes.

    Only for the tools that work locally without a model in between, and only where
    a tool error cannot cite the real term: a tool's error reaches the model as it
    is (PostToolUseFailure does not rewrite it). Hence:
      - Read, Grep, Glob: the paths only if the real file exists; the pattern of Grep
        and Glob yes (an empty search is not an error).
      - Write: the content yes, a written file is not cited in the error.
    Not Edit: Claude Code checks that old_string is in the file *before* the hooks, so
    an Edit with the placeholder fails without ever getting here. Editing goes via
    Bash (sed), where the runner converts the placeholders; the session notice says so.
    Excluded: MCP servers (a server error can cite the query), WebFetch and
    WebSearch (the input ends up at a model or a search engine), Agent and the like
    (the prompt goes to another model): there the placeholder stays a placeholder.
    """
    if not pairs:
        return None
    new = dict(tool_input)

    for key in ("file_path", "path", "notebook_path"):
        if key in new:
            new[key] = _real_path(new[key], cwd, pairs)

    if tool in ("Grep", "Glob"):
        for key in ("pattern", "glob"):
            if isinstance(new.get(key), str):
                new[key] = unmask(new[key], pairs)
    elif tool == "Write":
        if isinstance(new.get("content"), str):
            new["content"] = unmask(new["content"], pairs)
    elif tool not in ("Read",):
        return None

    return new if new != tool_input else None


def blocking_reason(tool: str, tool_input: dict, pairs: list[tuple[str, str]]) -> str | None:
    """The reason to deny a tool whose result cannot be masked."""
    if not pairs:
        return None
    if tool == "Bash":
        found = TRANSFORMING_COMMANDS.search(str(tool_input.get("command", "")))
        if found:
            return (
                f"{found.group(1)} shows the text transformed (bytes, encoding, reversed) and the "
                "filter does not recognize the masked terms in it: with masking active it is not used. "
                "To understand why a text does not match, read it again with cat or grep."
            )
    if tool == "Read":
        raw = tool_input.get("file_path")
        if isinstance(raw, str) and Path(raw).suffix.lower() in OPAQUE_FORMATS:
            return (
                f"{Path(raw).name}: the text of this format cannot be masked in the result of the "
                "Read. Convert it via Bash (pdftotext file -, unzip -p, …): there the output already "
                "comes out with the placeholders."
            )
    if tool == "WebFetch":
        url = tool_input.get("url")
        if isinstance(url, str) and (contains_placeholder(url, pairs) or contains_real(url, pairs)):
            return (
                "the address contains a masked term: WebFetch has a model read the page "
                "before any hook. For a private resource use curl via Bash."
            )
    return None


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def cmd_run() -> int:
    script = sys.stdin.read()
    try:
        pairs = load_pairs()
    except InvalidMap as exc:
        # The message contains no real terms: it cites only path and line number.
        print(f"[guardrail] {exc}: command not run", file=sys.stderr)
        return 1

    proc = subprocess.Popen(
        ["bash", "-c", unmask(script, pairs)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.stdout is not None
    out = sys.stdout.buffer
    for line in iter(proc.stdout.readline, b""):
        text = line.decode("utf-8", errors="surrogateescape")
        out.write(mask(text, pairs).encode("utf-8", errors="surrogateescape"))
        out.flush()
    code = proc.wait()
    # Killed by a signal: the same code the shell would have returned.
    return 128 - code if code < 0 else code


def _read_payload() -> dict:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def cmd_output() -> int:
    payload = _read_payload()
    try:
        pairs = load_pairs()
    except InvalidMap:
        return 0  # guard.py has already denied the tool before it started
    if not pairs or "tool_response" not in payload:
        return 0
    result = payload["tool_response"]
    masked = mask_value(result, pairs)
    if masked != result:
        print(json.dumps({
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": masked}
        }, ensure_ascii=False))
    return 0


def cmd_prompt() -> int:
    payload = _read_payload()
    prompt = str(payload.get("prompt", ""))
    try:
        pairs = load_pairs()
    except InvalidMap as exc:
        print(json.dumps({"decision": "block", "reason": f"[guardrail] {exc}"}))
        return 0
    found = [fake for real, fake in pairs if _search(real).search(prompt)]
    if found:
        # The user reads the reason, not the model: the blocked prompt never starts.
        print(json.dumps({
            "decision": "block",
            "reason": (
                "[guardrail] the prompt contains a masked term: rewrite it using "
                f"the placeholder ({', '.join(sorted(set(found)))})."
            ),
        }, ensure_ascii=False))
    return 0


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "run":
        return cmd_run()
    if command == "output":
        return cmd_output()
    if command == "prompt":
        return cmd_prompt()
    print("usage: mask.py run|output|prompt", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
