#!/usr/bin/env python3
"""Prova che un input MCP annidato a fondo non faccia saltare i controlli.

Un errore interno del hook lascia passare il tool: se la lettura dei parametri
andasse in ricorsione, bastarebbe annidare il bersaglio per scavalcare sia il
blocco sulla produzione sia la conferma per le operazioni distruttive. I casi
sono qui e non in cases.jsonl perché una riga da mille livelli non si legge.
Esce 1 al primo fallimento.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
LIVELLI = 5000


def annidato(foglia: dict, livelli: int = LIVELLI) -> dict:
    for _ in range(livelli):
        foglia = {"x": foglia}
    return foglia


def esito(tool_input: dict) -> tuple[str, str]:
    env = dict(
        os.environ,
        GUARDRAIL_CONFIG=str(ROOT / "tests" / "guardrail.test.json"),
        GUARDRAIL_MASK_MAP=str(ROOT / "tests" / "nessuna-mappa.tsv"),
    )
    env.pop("GUARDRAIL_DISABLE", None)
    payload = {"tool_name": "mcp__api-interna__risorse", "tool_input": tool_input, "cwd": str(ROOT), "session_id": "test"}
    proc = subprocess.run(
        [sys.executable, str(GUARD)], input=json.dumps(payload), capture_output=True, text=True, env=env, check=False
    )
    out = proc.stdout.strip()
    verdetto = json.loads(out)["hookSpecificOutput"].get("permissionDecision", "allow") if out else "allow"
    return verdetto, proc.stderr.strip()


CASI = [
    ("update con il bersaglio di prod annidato a fondo", {"action": "update", "parameters": annidato({"resourceGroup": "rg-prod"})}, "deny"),
    ("delete annidato a fondo, senza prod: chiede conferma", {"action": "delete", "parameters": annidato({"name": "app-dev"})}, "ask"),
    ("update con un body JSON annidato a fondo", {"action": "update", "body": json.dumps(annidato({"host": "db-prod"}))}, "deny"),
]


def main() -> int:
    for nome, tool_input, atteso in CASI:
        ottenuto, errore = esito(tool_input)
        if ottenuto != atteso or "errore interno" in errore:
            print(f"FAIL  atteso={atteso} ottenuto={ottenuto}  {nome}\n      {errore[:200]}")
            return 1
        print(f"ok    {nome}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
