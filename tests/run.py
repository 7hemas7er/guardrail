#!/usr/bin/env python3
"""Runs hooks/guard.py on every case in tests/cases.jsonl and compares the outcome.

Usage: python3 tests/run.py [-v]
Exits 1 if even a single case fails, or if the hook takes longer than
TIMEOUT_SECONDS to answer. Uses tests/guardrail.test.json as the configuration
(via GUARDRAIL_CONFIG), so the tests do not depend on the machine.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
CASES = ROOT / "tests" / "cases.jsonl"
CONFIG = ROOT / "tests" / "guardrail.test.json"
TIMEOUT_SECONDS = 3


def run_case(case: dict) -> str:
    payload = {
        "tool_name": case["tool_name"],
        "tool_input": case.get("tool_input", {}),
        "cwd": case.get("cwd", str(ROOT)),
        "session_id": "test",
    }
    # `config` per case: for the cases that verify this repo's own configuration
    # (.guardrail.json) instead of the fixture. The value is relative to the root.
    config = ROOT / case["config"] if case.get("config") else CONFIG
    # `mask_map`: the masking map for the case. Without it, a map that does not exist,
    # so the machine's real map does not change the outcome of the other cases.
    mask_map = ROOT / case["mask_map"] if case.get("mask_map") else ROOT / "tests" / "no-map.tsv"
    env = dict(
        os.environ,
        GUARDRAIL_CONFIG=str(config),
        GUARDRAIL_MASK_MAP=str(mask_map),
        HOME=os.environ.get("HOME", "/home/master"),
    )
    env.pop("GUARDRAIL_DISABLE", None)
    # Claude Code gives the hook 10 s (hooks/hooks.json): beyond that, the verdict never
    # arrives. A case must stay well below, so a regex that explodes (backtracking) fails
    # here instead of passing with the right verdict in 20 seconds.
    try:
        proc = subprocess.run(
            [sys.executable, str(GUARD)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"over {TIMEOUT_SECONDS} s", "", None
    if proc.returncode != 0:
        return f"exit {proc.returncode}: {proc.stderr.strip()[:200]}", "", None
    out = proc.stdout.strip()
    if not out:
        return "allow", "", None
    try:
        outcome = json.loads(out)["hookSpecificOutput"]
        # Without permissionDecision the hook only rewrote the input: the tool proceeds.
        return outcome.get("permissionDecision", "allow"), outcome.get("permissionDecisionReason", ""), outcome.get("updatedInput")
    except (ValueError, KeyError, AttributeError):
        return f"invalid output: {out[:200]}", "", None


def main() -> int:
    verbose = "-v" in sys.argv
    failures = 0
    total = 0
    with open(CASES, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            case = json.loads(line)
            total += 1
            got, reason, rewritten_input = run_case(case)
            command = (rewritten_input or {}).get("command") if case["tool_name"] == "Bash" else None
            # `reason_contains`: for the cases where *what* the hook says matters too,
            # not only the verdict (e.g. the notice that an allow_scripts entry no longer applies).
            expected_in_reason = case.get("reason_contains", "")
            ok = got == case["expect"] and expected_in_reason in reason
            # `rewritten`: true if the Bash command must come out rewritten, false if untouched.
            # `rewritten_excludes`: text that must not appear in the rewritten input
            # (a real term), nor in the reason.
            # `updated_input`: the fields the rewritten input must have (tools other than Bash).
            if "rewritten" in case:
                rewritten = command is not None
                ok = ok and rewritten == case["rewritten"]
                if rewritten and case["rewritten"]:
                    ok = ok and case["tool_input"]["command"] in command
            for field, value in case.get("updated_input", {}).items():
                ok = ok and (rewritten_input or {}).get(field) == value
            visible = json.dumps(rewritten_input or {}, ensure_ascii=False).lower() + reason.lower()
            for forbidden in case.get("rewritten_excludes", []):
                ok = ok and forbidden.lower() not in visible
            failures += 0 if ok else 1
            if verbose or not ok:
                mark = "ok " if ok else "FAIL"
                print(f"{mark}  expected={case['expect']:<5} got={got:<5}  {case['name']}")
                if not ok and expected_in_reason and expected_in_reason not in reason:
                    print(f"      expected reason containing {expected_in_reason!r}, got: {reason[:160]!r}")
    print(f"\n{total - failures}/{total} cases green")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
