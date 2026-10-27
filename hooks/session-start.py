#!/usr/bin/env python3
"""SessionStart hook: injects the core rules into the agent's context.

Guardrail applies only in the projects that chose it, with a `.guardrail.json` (see
`guard.is_active`). There it prints RULES-CORE.md to stdout (short, ~30 lines): Claude
Code adds the stdout of SessionStart hooks to the session context. The full rules
per service live in services/ and are loaded with the `guardrail` skill.

Elsewhere it injects nothing, and the first time a session starts in that folder it
asks the agent to ask the user whether to turn it on: yes with /guardrail:setup, yes
with the basic rules, or no. The choice is the user's; the question is not repeated,
so a folder left off on purpose does not become noise.

At the end, once per kind, it also reports what the hook cannot do by itself: the
sandbox being off. The state lives in ~/.claude/guardrail.state.json.
"""
import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
STATE = Path.home() / ".claude" / "guardrail.state.json"


def read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def cwd_from_stdin() -> Path:
    if sys.stdin.isatty():
        return Path(os.getcwd())
    try:
        payload = json.load(sys.stdin)
        return Path(payload.get("cwd") or os.getcwd())
    except (ValueError, OSError, AttributeError):
        return Path(os.getcwd())


def project_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return start


def project_active(cwd: Path) -> bool:
    try:
        import guard

        return guard.is_active(str(cwd))
    except Exception:  # noqa: BLE001 — when in doubt the rules go in: they cost little
        return True


cwd = cwd_from_stdin()
active = project_active(cwd)

if active:
    try:
        text = (root / "RULES-CORE.md").read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    if text:
        print("<!-- guardrail: core rules, injected at every session -->")
        print(text)
        print(f"<!-- full rules per service: {root / 'services'} (skill: guardrail) -->")

# With the map active the model must know that the placeholders count as real
# terms, otherwise it tries to "correct" them. Only the placeholders are listed. It
# applies also in projects where guardrail is off: masking follows the map.
try:
    import mask

    placeholders = sorted({fake for _, fake in mask.load_pairs()})
except Exception:  # noqa: BLE001 — a broken map is reported by guard.py at the first tool
    placeholders = []
if placeholders:
    print(
        "\n<!-- guardrail: masking of reserved terms active -->\n"
        f"Some reserved terms are masked: in every tool result (commands, files read, "
        f"searches, MCP) they appear as {', '.join(placeholders)}. Treat them as the real terms and use "
        "them as such in Bash commands, in paths, in Grep/Glob patterns and in Write: guardrail "
        "converts them before execution. Do not try to reconstruct the originals, and do not look at "
        "the bytes (od, xxd, base64) to understand why a text does not match. The Edit tool does not "
        "recognize the placeholders: to modify a text that contains them use sed via Bash. PDFs, "
        "Office documents and archives are not read with Read: convert them via Bash (pdftotext file -, "
        "unzip -p). For a private resource use curl via Bash, not WebFetch."
    )
    # The git status and the recent commits enter the context before any hook.
    # Repeated at every session as long as it stays so: it is a leak, not advice.
    settings_main = read_json(Path.home() / ".claude" / "settings.json")
    if (
        os.environ.get("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS") != "1"
        and settings_main.get("includeGitInstructions") is not False
    ):
        print(
            "\n<!-- guardrail: to report to the user in the first message -->\n"
            "- masking is active, but Claude Code puts the git status and the recent commits "
            "in the context before any hook: file names and commit messages reach the model "
            'in the clear. It is removed with `"includeGitInstructions": false` in ~/.claude/settings.json.'
        )


def notices(cwd: Path) -> list[tuple[str, str]]:
    """[(state key, text)] — only what the hook cannot do by itself."""
    project = project_root(cwd)
    if not active:
        hints = [
            name for name in (".mcp.json", "docker-compose.yml", "docker-compose.yaml", "scripts/deploy")
            if (project / name).exists()
        ]
        surface = f" There is production surface here: {', '.join(hints)}." if hints else ""
        return [(
            f"inactive:{project}",
            f"guardrail is not active in this folder ({project}): there is no .guardrail.json, so "
            "destructive commands, writes to production and reads of secrets are not checked."
            f"{surface}\n"
            "  BEFORE dealing with the user's request, ask them whether they want to turn it on here (with "
            "AskUserQuestion, if available), with three answers: «Yes, configure it» → run /guardrail:setup; "
            "«Yes, basic rules» → create a .guardrail.json with `{}` in the project root; «No» → "
            "do nothing. The question is not repeated for this folder: if the user changes their mind, "
            "/guardrail:setup. The user decides: do not answer in their place. Then move on to their request.",
        )]

    settings = read_json(Path.home() / ".claude" / "settings.json")
    if not (settings.get("sandbox") or {}).get("enabled"):
        return [(
            "sandbox",
            "the Bash command sandbox is off in ~/.claude/settings.json "
            '(`"sandbox": {"enabled": true, "autoAllowBashIfSandboxed": true}`). '
            "It is the only protection that no hook can turn on in the user's place.",
        )]
    return []


try:
    state = read_json(STATE)
    # Old state files (before the English keys) are read as well: `avvisi_mostrati`
    # list and `inattivo:<folder>` keys count as already shown. Only the new key is written.
    seen = [
        key.replace("inattivo:", "inactive:", 1) if isinstance(key, str) and key.startswith("inattivo:") else key
        for name in ("notices_shown", "avvisi_mostrati")
        for key in (state.get(name) if isinstance(state.get(name), list) else [])
    ]
    new = [(key, text) for key, text in notices(cwd) if key not in seen]
    if new:
        print("\n<!-- guardrail: to report to the user in the first message, one line per point -->")
        for _, text in new:
            print(f"- {text}")
        STATE.parent.mkdir(parents=True, exist_ok=True)
        state["notices_shown"] = seen + [key for key, _ in new]
        STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
except Exception:  # noqa: BLE001 — a notice must never break the session start
    pass
