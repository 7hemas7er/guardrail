#!/usr/bin/env python3
"""Prova che guardrail controlli solo i progetti che l'hanno scelto.

Esegue hooks/guard.py senza GUARDRAIL_CONFIG, con una home e delle cartelle finte:
un comando vietato deve passare dove non c'è un .guardrail.json ed essere bloccato
dove c'è, anche in una sottocartella, sotto una directory superiore configurata, o
dopo un `cd` fuori dal progetto. Dove è spento valgono solo le regole che
proteggono guardrail stesso, e il mascheramento, che vale ovunque ci sia la mappa.
Esce 1 al primo fallimento.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
VIETATO = {"tool_name": "Bash", "tool_input": {"command": 'rm -rf "$GUARDRAIL_CANARY"'}}


def esito(home: Path, cwd: Path, progetto: Path | None = None, mappa: Path | None = None, tool: dict = VIETATO) -> str:
    env = dict(os.environ, HOME=str(home), GUARDRAIL_MASK_MAP=str(mappa or home / "nessuna-mappa.tsv"))
    for chiave in ("GUARDRAIL_CONFIG", "GUARDRAIL_DISABLE", "CLAUDE_PROJECT_DIR"):
        env.pop(chiave, None)
    if progetto:
        env["CLAUDE_PROJECT_DIR"] = str(progetto)
    proc = subprocess.run(
        [sys.executable, str(GUARD)],
        input=json.dumps({**tool, "cwd": str(cwd), "session_id": "test"}),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(f"exit {proc.returncode}: {proc.stderr[:300]}")
    if not proc.stdout.strip():
        return "allow"
    return json.loads(proc.stdout)["hookSpecificOutput"].get("permissionDecision", "allow")


def check(name: str, ottenuto: str, atteso: str) -> int:
    ok = ottenuto == atteso
    print(f"{'ok  ' if ok else 'FAIL'}  atteso={atteso:<5} ottenuto={ottenuto:<5}  {name}")
    return 0 if ok else 1


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="guardrail-att-") as tmp:
        base = Path(tmp)
        home = base / "home"
        home.mkdir()

        libero = home / "libero"
        (libero / ".git").mkdir(parents=True)
        failures += check("cartella senza .guardrail.json: spento", esito(home, libero), "allow")

        (home / ".guardrail.json").write_text('{"deny_commands": ["^ls$"]}', encoding="utf-8")
        failures += check("~/.guardrail.json da solo non accende niente", esito(home, libero), "allow")

        scelto = home / "scelto"
        (scelto / ".git").mkdir(parents=True)
        (scelto / "src").mkdir()
        (scelto / ".guardrail.json").write_text("{}", encoding="utf-8")
        failures += check("progetto con .guardrail.json vuoto: acceso", esito(home, scelto), "deny")
        failures += check("sottocartella del progetto: acceso", esito(home, scelto / "src"), "deny")
        ls = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        failures += check("progetto acceso: le liste di ~/.guardrail.json valgono", esito(home, scelto, tool=ls), "deny")

        cliente = home / "cliente"
        (cliente / "repo-a" / ".git").mkdir(parents=True)
        (cliente / ".guardrail.json").write_text("{}", encoding="utf-8")
        failures += check("directory superiore configurata: acceso", esito(home, cliente / "repo-a"), "deny")

        failures += check("cd fuori dal progetto acceso: resta acceso", esito(home, libero, progetto=scelto), "deny")
        failures += check("cd dentro un progetto acceso: acceso", esito(home, scelto, progetto=libero), "deny")

        # Da una cartella spenta non si spegne né si allenta guardrail dove è acceso.
        def bash(cmd: str) -> dict:
            return {"tool_name": "Bash", "tool_input": {"command": cmd}}

        def write(path: Path) -> dict:
            return {"tool_name": "Write", "tool_input": {"file_path": str(path), "content": '{"allow_commands": [".*"]}'}}

        failures += check("spento: rm del .guardrail.json di un altro progetto", esito(home, libero, tool=bash(f"rm {scelto}/.guardrail.json")), "deny")
        failures += check("spento: lo stesso dentro bash -c", esito(home, libero, tool=bash(f"bash -c 'rm {scelto}/.guardrail.json'")), "deny")
        failures += check("spento: Write su ~/.guardrail.json", esito(home, libero, tool=write(home / ".guardrail.json")), "ask")
        failures += check("spento: redirect su ~/.guardrail.json", esito(home, libero, tool=bash("echo '{}' > ~/.guardrail.json")), "ask")
        failures += check("spento: Write nel codice del plugin", esito(home, libero, tool=write(home / ".claude" / "plugins" / "x" / "guard.py")), "deny")
        failures += check("spento: Write su ~/.claude/settings.json", esito(home, libero, tool=write(home / ".claude" / "settings.json")), "ask")
        failures += check("spento: il resto passa", esito(home, libero, tool=write(libero / "note.txt")), "allow")

        (base / "mask.tsv").write_text("magazzino\tsede1\n", encoding="utf-8")
        od = {"tool_name": "Bash", "tool_input": {"command": "od -c nota.txt"}}
        failures += check("progetto spento: il mascheramento vale lo stesso", esito(home, libero, mappa=base / "mask.tsv", tool=od), "deny")

    print(f"\nattivazione: {'tutto verde' if not failures else f'{failures} fallimenti'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
