#!/usr/bin/env python3
"""Prova end-to-end del mascheramento: il comando riscritto da guard.py viene eseguito
davvero con bash, come farebbe Claude Code, e si controlla cosa arriva al modello.

Verifica anche l'hook UserPromptSubmit (`mask.py prompt`). Usa la mappa di prova
tests/fixtures/mask.tsv. Esce 1 se anche un solo controllo fallisce.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
MASK = ROOT / "hooks" / "mask.py"
MAPPA = ROOT / "tests" / "fixtures" / "mask.tsv"
ENV = dict(
    os.environ,
    GUARDRAIL_MASK_MAP=str(MAPPA),
    GUARDRAIL_CONFIG=str(ROOT / "tests" / "guardrail.test.json"),
)
ENV.pop("GUARDRAIL_DISABLE", None)


def riscrivi(comando: str) -> str:
    payload = {"tool_name": "Bash", "tool_input": {"command": comando}, "cwd": str(ROOT), "session_id": "test"}
    proc = subprocess.run(
        [sys.executable, str(GUARD)], input=json.dumps(payload), capture_output=True, text=True, env=ENV, check=True
    )
    return json.loads(proc.stdout)["hookSpecificOutput"]["updatedInput"]["command"]


def esegui(comando: str) -> subprocess.CompletedProcess:
    """Come il tool Bash: il comando riscritto passa a una shell."""
    return subprocess.run(
        ["bash", "-c", riscrivi(comando)], capture_output=True, text=True, env=ENV, cwd=ROOT, timeout=30, check=False
    )


def prompt(testo: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(MASK), "prompt"],
        input=json.dumps({"prompt": testo, "session_id": "test"}),
        capture_output=True, text=True, env=ENV, check=True,
    )
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def check(nome: str, condizione: bool) -> int:
    print(("ok   " if condizione else "FAIL ") + nome)
    return 0 if condizione else 1


def main() -> int:
    falliti = 0

    r = esegui("echo nas-magazzino.rete.lan NAS-MAGAZZINO")
    falliti += check("l'output esce mascherato, maiuscole comprese", r.stdout == "nas-sede1.rete.lan NAS-sede1\n")

    r = esegui("printf '%s\\n' nas-sede1.rete.lan | tr a-z A-Z")
    falliti += check(
        "il segnaposto nel comando diventa il nome reale, e in uscita torna segnaposto",
        r.stdout == "NAS-sede1.RETE.LAN\n",
    )

    r = esegui("echo casale magazzinone")
    falliti += check("una parola che contiene il nome non si tocca", r.stdout == "casale magazzinone\n")

    r = esegui("echo magazzino >&2; exit 3")
    falliti += check("stderr mascherato ed exit code conservato", r.stdout == "sede1\n" and r.returncode == 3)

    r = esegui("cat <<'__GUARDRAIL_MASK__'\nmagazzino\n__GUARDRAIL_MASK__")
    falliti += check("un heredoc col delimitatore del runner non spezza il comando", r.stdout == "sede1\n")

    r = esegui("echo db-produzione.esempio.com")
    falliti += check("nomi con i punti", r.stdout == "dbuno\n")

    riscritto = riscrivi("ping -c1 nas-sede1.rete.lan")
    falliti += check("il comando riscritto non contiene nomi reali", "magazzino" not in riscritto.lower())

    esito = prompt("fai un ping a nas-Magazzino.rete.lan")
    falliti += check(
        "prompt con un nome reale: bloccato, e il motivo suggerisce il segnaposto",
        esito.get("decision") == "block" and "sede1" in esito.get("reason", ""),
    )
    falliti += check("prompt senza nomi reali: passa", prompt("fai un ping a nas-sede1.rete.lan") == {})

    print(f"\n{'tutto verde' if not falliti else f'{falliti} controlli falliti'}")
    return 1 if falliti else 0


if __name__ == "__main__":
    sys.exit(main())
