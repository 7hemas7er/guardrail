#!/usr/bin/env python3
"""Prova hooks/session-start.py con una home e un progetto finti.

Verifica che le regole essenziali entrino solo nei progetti con un
.guardrail.json, che una cartella senza riceva una volta sola l'avviso che guardrail
è spento, e che l'avviso sul sandbox compaia una volta sola, e solo dove guardrail
è acceso. Esce 1 al primo fallimento.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session-start.py"


def run(home: Path, cwd: Path) -> str:
    env = dict(os.environ, HOME=str(home))
    env.pop("GUARDRAIL_CONFIG", None)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"cwd": str(cwd), "session_id": "test"}),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(f"exit {proc.returncode}: {proc.stderr[:300]}")
    return proc.stdout


def check(name: str, condition: bool) -> int:
    print(("ok   " if condition else "FAIL ") + name)
    return 0 if condition else 1


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="guardrail-ss-") as tmp:
        base = Path(tmp)
        home = base / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        progetto = base / "progetto"
        (progetto / ".git").mkdir(parents=True)
        (progetto / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")

        out = run(home, progetto)
        failures += check("cartella non configurata: niente regole", "Produzione si legge" not in out)
        failures += check("cartella non configurata: avviso che guardrail è spento", "non è attivo" in out and "/guardrail:setup" in out)
        failures += check("l'avviso cita la superficie di produzione", ".mcp.json" in out)
        failures += check("l'agente deve chiedere sì/no all'utente", "AskUserQuestion" in out and "«No»" in out)
        failures += check("cartella non configurata: niente avviso sul sandbox", "sandbox" not in out)
        failures += check("stato salvato", (home / ".claude" / "guardrail.state.json").is_file())

        out2 = run(home, progetto)
        failures += check("avviso non ripetuto alla seconda sessione", "da segnalare" not in out2)
        failures += check("ancora niente regole", "Produzione si legge" not in out2)

        # Una cartella qualunque, senza indizi di produzione: stesso avviso, senza superficie.
        semplice = base / "semplice"
        (semplice / ".git").mkdir(parents=True)
        out3 = run(home, semplice)
        failures += check("cartella senza MCP né deploy: avviso anche qui", "non è attivo" in out3)
        failures += check("cartella senza MCP né deploy: nessuna superficie citata", "superficie" not in out3)

        # L'utente lo accende: regole, e l'avviso sul sandbox spento una volta sola.
        (progetto / ".guardrail.json").write_text("{}", encoding="utf-8")
        out4 = run(home, progetto)
        failures += check("progetto acceso: regole essenziali stampate", "regole essenziali" in out4 and "Produzione si legge" in out4)
        failures += check("progetto acceso: avviso sandbox spento", "sandbox" in out4 and "spento" in out4)
        failures += check("progetto acceso: nessun avviso di guardrail spento", "non è attivo" not in out4)
        out5 = run(home, progetto)
        failures += check("progetto acceso: regole anche dopo", "Produzione si legge" in out5)
        failures += check("progetto acceso: avvisi non ripetuti", "da segnalare" not in out5)

        # ~/.guardrail.json da solo non accende niente.
        (home / ".guardrail.json").write_text("{}", encoding="utf-8")
        out6 = run(home, semplice)
        failures += check("~/.guardrail.json non accende le cartelle sotto la home", "Produzione si legge" not in out6)

        # Configurato e con sandbox acceso: nessun avviso.
        (home / ".claude" / "settings.json").write_text('{"sandbox": {"enabled": true}}', encoding="utf-8")
        altro = base / "altro"
        (altro / ".git").mkdir(parents=True)
        (altro / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
        (altro / ".guardrail.json").write_text('{"prod_mcp_servers": ["postgres"]}', encoding="utf-8")
        out7 = run(home, altro)
        failures += check("progetto configurato e sandbox acceso: nessun avviso", "da segnalare" not in out7)

    print(f"\nsession-start: {'tutto verde' if not failures else f'{failures} fallimenti'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
