#!/usr/bin/env python3
"""End-to-end test of masking: the command rewritten by guard.py is really run
with bash, as Claude Code would, and what reaches the model is checked.

It also checks the rewriting of tool results (`mask.py output`, PostToolUse) and
the UserPromptSubmit hook (`mask.py prompt`). Uses the test map
tests/fixtures/mask.tsv. Exits 1 if even a single check fails.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
MASK = ROOT / "hooks" / "mask.py"
MAP = ROOT / "tests" / "fixtures" / "mask.tsv"
ENV = dict(
    os.environ,
    GUARDRAIL_MASK_MAP=str(MAP),
    GUARDRAIL_CONFIG=str(ROOT / "tests" / "guardrail.test.json"),
)
ENV.pop("GUARDRAIL_DISABLE", None)


def rewrite(command: str) -> str:
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(ROOT), "session_id": "test"}
    proc = subprocess.run(
        [sys.executable, str(GUARD)], input=json.dumps(payload), capture_output=True, text=True, env=ENV, check=True
    )
    return json.loads(proc.stdout)["hookSpecificOutput"]["updatedInput"]["command"]


def run_command(command: str) -> subprocess.CompletedProcess:
    """Like the Bash tool: the rewritten command goes to a shell."""
    return subprocess.run(
        ["bash", "-c", rewrite(command)], capture_output=True, text=True, env=ENV, cwd=ROOT, timeout=30, check=False
    )


def prompt(text: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(MASK), "prompt"],
        input=json.dumps({"prompt": text, "session_id": "test"}),
        capture_output=True, text=True, env=ENV, check=True,
    )
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def output(tool: str, result) -> object:
    """The result the model would see after the PostToolUse hook, or None if the
    hook leaves it as it is."""
    proc = subprocess.run(
        [sys.executable, str(MASK), "output"],
        input=json.dumps({"tool_name": tool, "tool_input": {}, "tool_response": result}),
        capture_output=True, text=True, env=ENV, check=True,
    )
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)["hookSpecificOutput"]["updatedToolOutput"]


def check(name: str, condition: bool) -> int:
    print(("ok   " if condition else "FAIL ") + name)
    return 0 if condition else 1


def main() -> int:
    failures = 0

    r = run_command("echo nas-warehouse.net.lan NAS-WAREHOUSE Warehouse")
    failures += check(
        "the output comes out masked, with the capitals of the original",
        r.stdout == "nas-site1.net.lan NAS-SITE1 Site1\n",
    )

    r = run_command("printf '%s\\n' nas-site1.net.lan | tr a-z A-Z")
    failures += check(
        "the placeholder in the command becomes the real term, and on the way out it is a placeholder again",
        r.stdout == "NAS-SITE1.NET.LAN\n",
    )

    r = run_command("ls /no/such/dir/warehouse")
    failures += check(
        "even the error of a failed command comes out masked",
        "site1" in r.stdout and "warehouse" not in r.stdout.lower() and r.returncode != 0,
    )

    r = run_command("echo warehouses megawarehouse")
    failures += check("a word that contains the name is untouched", r.stdout == "warehouses megawarehouse\n")

    r = run_command("echo warehouse >&2; exit 3")
    failures += check("stderr masked and exit code preserved", r.stdout == "site1\n" and r.returncode == 3)

    r = run_command("cat <<'__GUARDRAIL_MASK__'\nwarehouse\n__GUARDRAIL_MASK__")
    failures += check("a heredoc with the runner's delimiter does not break the command", r.stdout == "site1\n")

    r = run_command("echo db-production.example.com")
    failures += check("names with dots", r.stdout == "dbone\n")

    rewritten = rewrite("ping -c1 nas-site1.net.lan")
    failures += check("the rewritten command contains no real names", "warehouse" not in rewritten.lower())

    outcome = prompt("ping nas-Warehouse.net.lan")
    failures += check(
        "prompt with a real name: blocked, and the reason suggests the placeholder",
        outcome.get("decision") == "block" and "site1" in outcome.get("reason", ""),
    )
    failures += check("prompt without real names: passes", prompt("ping nas-site1.net.lan") == {})

    read = {"type": "text", "file": {"filePath": "/x/nas-warehouse.txt", "content": "Warehouse and WAREHOUSE\n", "numLines": 1}}
    failures += check(
        "Read result: every string masked, keys and numbers intact",
        output("Read", read) == {"type": "text", "file": {
            "filePath": "/x/nas-site1.txt", "content": "Site1 and SITE1\n", "numLines": 1,
        }},
    )
    mcp = [{"type": "text", "text": "host warehouse up"}]
    failures += check(
        "MCP result in blocks: masked",
        output("mcp__x__y", mcp) == [{"type": "text", "text": "host site1 up"}],
    )
    image = {"type": "image", "file": {"base64": "AAA/warehouse+BBB", "type": "image/png"}}
    failures += check("base64 data of an image: untouched", output("Read", image) is None)
    failures += check(
        "result without real terms: no rewriting",
        output("Grep", {"mode": "content", "content": "nothing to hide", "numLines": 1}) is None,
    )

    print(f"\n{'all green' if not failures else f'{failures} checks failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
