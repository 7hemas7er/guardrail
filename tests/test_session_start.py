#!/usr/bin/env python3
"""Prova hooks/session-start.py con una home e un progetto finti.

Verifica che le regole essenziali vengano stampate sempre, che gli avvisi
(sandbox spento, .guardrail.json mancante) compaiano una volta sola, e che un
progetto configurato non ne riceva. Esce 1 al primo fallimento.
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
        failures += check("regole essenziali stampate", "regole essenziali" in out and "Produzione si legge" in out)
        failures += check("avviso sandbox spento alla prima sessione", "sandbox" in out and "spento" in out)
        failures += check("avviso .guardrail.json mancante alla prima sessione", ".guardrail.json" in out and "/guardrail:setup" in out)
        failures += check("stato salvato", (home / ".claude" / "guardrail.state.json").is_file())

        out2 = run(home, progetto)
        failures += check("regole essenziali stampate anche dopo", "Produzione si legge" in out2)
        failures += check("avvisi non ripetuti alla seconda sessione", "da segnalare" not in out2)

        # Un secondo progetto, configurato e con sandbox acceso: nessun avviso.
        (home / ".claude" / "settings.json").write_text('{"sandbox": {"enabled": true}}', encoding="utf-8")
        altro = base / "altro"
        (altro / ".git").mkdir(parents=True)
        (altro / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
        (altro / ".guardrail.json").write_text('{"prod_mcp_servers": ["postgres"]}', encoding="utf-8")
        out3 = run(home, altro)
        failures += check("progetto configurato e sandbox acceso: nessun avviso", "da segnalare" not in out3)

        # Un progetto senza indizi di produzione: nessun avviso di configurazione.
        (home / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        semplice = base / "semplice"
        (semplice / ".git").mkdir(parents=True)
        out4 = run(home, semplice)
        failures += check("progetto senza MCP né deploy: nessun avviso di configurazione", "/guardrail:setup" not in out4)

    print(f"\nsession-start: {'tutto verde' if not failures else f'{failures} fallimenti'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
