#!/usr/bin/env python3
"""Proves that a deeply nested MCP input does not skip the checks.

An internal error of the hook lets the tool through: if reading the parameters
went into recursion, nesting the target would be enough to bypass both the
production block and the confirmation for destructive operations. The cases
are here and not in cases.jsonl because a line a thousand levels deep is unreadable.
Exits 1 at the first failure.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
LEVELS = 5000


def nested(leaf: dict, levels: int = LEVELS) -> dict:
    for _ in range(levels):
        leaf = {"x": leaf}
    return leaf


def outcome(tool_input: dict) -> tuple[str, str]:
    env = dict(
        os.environ,
        GUARDRAIL_CONFIG=str(ROOT / "tests" / "guardrail.test.json"),
        GUARDRAIL_MASK_MAP=str(ROOT / "tests" / "no-map.tsv"),
    )
    env.pop("GUARDRAIL_DISABLE", None)
    payload = {"tool_name": "mcp__internal-api__resources", "tool_input": tool_input, "cwd": str(ROOT), "session_id": "test"}
    proc = subprocess.run(
        [sys.executable, str(GUARD)], input=json.dumps(payload), capture_output=True, text=True, env=env, check=False
    )
    out = proc.stdout.strip()
    verdict = json.loads(out)["hookSpecificOutput"].get("permissionDecision", "allow") if out else "allow"
    return verdict, proc.stderr.strip()


CASES = [
    ("update with the prod target deeply nested", {"action": "update", "parameters": nested({"resourceGroup": "rg-prod"})}, "deny"),
    ("delete deeply nested, without prod: asks for confirmation", {"action": "delete", "parameters": nested({"name": "app-dev"})}, "ask"),
    ("update with a deeply nested JSON body", {"action": "update", "body": json.dumps(nested({"host": "db-prod"}))}, "deny"),
]


def raw_outcome(text: str) -> tuple[str, int]:
    """Like outcome(), but with the input already serialized: json.dumps cannot take the
    depth needed to make the hook's parser give up."""
    env = dict(os.environ, GUARDRAIL_CONFIG=str(ROOT / "tests" / "guardrail.test.json"))
    env.pop("GUARDRAIL_DISABLE", None)
    proc = subprocess.run([sys.executable, str(GUARD)], input=text, capture_output=True, text=True, env=env, check=False)
    out = proc.stdout.strip()
    return (json.loads(out)["hookSpecificOutput"].get("permissionDecision", "allow") if out else "allow"), proc.returncode


def main() -> int:
    for name, tool_input, expected in CASES:
        got, error = outcome(tool_input)
        if got != expected or "internal error" in error:
            print(f"FAIL  expected={expected} got={got}  {name}\n      {error[:200]}")
            return 1
        print(f"ok    {name}")

    # Beyond the JSON parser's limit the hook cannot read the input: it must block.
    deep = 200_000
    text = (
        '{"tool_name": "Bash", "session_id": "test", "tool_input": {"command": "true", "x": '
        + '{"x": ' * deep + "0" + "}" * deep + "}}"
    )
    got, code = raw_outcome(text)
    if got != "deny" or code != 0:
        print(f"FAIL  expected=deny got={got} exit={code}  input beyond the parser's limit")
        return 1
    print("ok    input beyond the parser's limit: blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
