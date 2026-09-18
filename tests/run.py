#!/usr/bin/env python3
"""Esegue hooks/guard.py su ogni caso di tests/cases.jsonl e confronta l'esito.

Uso: python3 tests/run.py [-v]
Esce 1 se anche un solo caso fallisce. Usa tests/guardrail.test.json come
configurazione (via GUARDRAIL_CONFIG), così i test non dipendono dalla macchina.
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


def run_case(case: dict) -> str:
    payload = {
        "tool_name": case["tool_name"],
        "tool_input": case.get("tool_input", {}),
        "cwd": case.get("cwd", str(ROOT)),
        "session_id": "test",
    }
    # `config` per caso: serve ai casi che verificano la configurazione di questo
    # repo (.guardrail.json) invece della fixture. Il valore è relativo alla root.
    config = ROOT / case["config"] if case.get("config") else CONFIG
    env = dict(os.environ, GUARDRAIL_CONFIG=str(config), HOME=os.environ.get("HOME", "/home/master"))
    env.pop("GUARDRAIL_DISABLE", None)
    proc = subprocess.run(
        [sys.executable, str(GUARD)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        return f"exit {proc.returncode}: {proc.stderr.strip()[:200]}", ""
    out = proc.stdout.strip()
    if not out:
        return "allow", ""
    try:
        esito = json.loads(out)["hookSpecificOutput"]
        return esito["permissionDecision"], esito.get("permissionDecisionReason", "")
    except (ValueError, KeyError):
        return f"output non valido: {out[:200]}", ""


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
            got, reason = run_case(case)
            # `reason_contains`: per i casi in cui conta anche *cosa* dice il hook,
            # non solo il verdetto (es. l'avviso che un allow_scripts non vale più).
            atteso_nel_motivo = case.get("reason_contains", "")
            ok = got == case["expect"] and atteso_nel_motivo in reason
            failures += 0 if ok else 1
            if verbose or not ok:
                mark = "ok " if ok else "FAIL"
                print(f"{mark}  atteso={case['expect']:<5} ottenuto={got:<5}  {case['name']}")
                if not ok and atteso_nel_motivo and atteso_nel_motivo not in reason:
                    print(f"      motivo atteso contenente {atteso_nel_motivo!r}, ottenuto: {reason[:160]!r}")
    print(f"\n{total - failures}/{total} casi verdi")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
