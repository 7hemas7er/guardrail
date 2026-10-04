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
        failures += check("spento: find -delete del .guardrail.json", esito(home, libero, tool=bash(f"find {scelto} -name .guardrail.json -delete")), "deny")
        failures += check("spento: ln -sf al posto del .guardrail.json", esito(home, libero, tool=bash(f"ln -sf /dev/null {scelto}/.guardrail.json")), "deny")
        impostazioni = write(scelto / ".claude" / "settings.local.json")
        failures += check("spento: Write sulle settings di un altro progetto", esito(home, libero, tool=impostazioni), "ask")
        failures += check("acceso: Write sulle settings del progetto", esito(home, scelto, tool=impostazioni), "ask")
        failures += check("spento: Write nei hook di un progetto", esito(home, libero, tool=write(scelto / ".claude" / "hooks" / "x.sh")), "ask")
        failures += check("spento: Write su un file qualunque in .claude/", esito(home, libero, tool=write(scelto / ".claude" / "note.md")), "allow")

        # Uno script scritto apposta non è una via laterale.
        (libero / "togli.sh").write_text(f"#!/bin/sh\nrm {scelto}/.guardrail.json\n", encoding="utf-8")
        failures += check("spento: script che toglie un .guardrail.json", esito(home, libero, tool=bash("bash togli.sh")), "deny")
        (scelto / "togli.sh").write_text("#!/bin/sh\nrm .guardrail.json\n", encoding="utf-8")
        failures += check("acceso: script che toglie il .guardrail.json", esito(home, scelto, tool=bash("bash togli.sh")), "deny")
        (libero / "innocuo.sh").write_text('#!/bin/sh\nrm -rf "$X"\n', encoding="utf-8")
        failures += check("spento: script con altro dentro passa", esito(home, libero, tool=bash("bash innocuo.sh")), "allow")

        # Uno script che ne lancia un altro: si legge anche il secondo.
        (libero / "primo.sh").write_text("#!/bin/sh\nbash togli.sh\n", encoding="utf-8")
        failures += check("spento: script che lancia lo script che toglie", esito(home, libero, tool=bash("bash primo.sh")), "deny")

        # Glob, maiuscole, cartelle intere, secondi nomi.
        failures += check("spento: rm con glob", esito(home, libero, tool=bash(f"rm {scelto}/.guardrail*")), "deny")
        failures += check("spento: rm con maiuscole (NTFS)", esito(home, libero, tool=bash(f"rm {scelto}/.GUARDRAIL.JSON")), "deny")
        failures += check("spento: rm *.json non prende i file nascosti", esito(home, libero, tool=bash(f"rm {scelto}/*.json")), "allow")
        failures += check("spento: rm -rf del progetto acceso", esito(home, libero, tool=bash(f"rm -rf {scelto}")), "deny")
        failures += check("spento: rm -rf della cartella sopra", esito(home, libero, tool=bash(f"rm -rf {cliente}")), "deny")
        failures += check("acceso: git rm -r .", esito(home, scelto, tool=bash("git rm -r .")), "deny")
        failures += check("acceso: mv del progetto", esito(home, scelto, tool=bash(f"mv {scelto} {home}/altrove")), "deny")
        failures += check("acceso: rm -rf di una sottocartella normale", esito(home, scelto, tool=bash("rm -rf src")), "allow")
        failures += check("spento: ln -s verso .guardrail.json", esito(home, libero, tool=bash(f"ln -s {scelto}/.guardrail.json note.json")), "deny")
        failures += check("spento: cp -l di .guardrail.json", esito(home, libero, tool=bash(f"cp -l {scelto}/.guardrail.json copia.json")), "deny")
        failures += check("spento: cp normale di .guardrail.json", esito(home, libero, tool=bash(f"cp {scelto}/.guardrail.json copia.json")), "allow")
        (libero / "note.json").symlink_to(scelto / ".guardrail.json")
        failures += check("spento: Write su un link al .guardrail.json", esito(home, libero, tool=write(libero / "note.json")), "ask")
        failures += check("spento: redirect su un link al .guardrail.json", esito(home, libero, tool=bash("echo '{}' > note.json")), "ask")

        # Dove è acceso, allow_commands non esenta la rimozione, e una conferma sul
        # .guardrail.json non nasconde un blocco delle altre regole.
        (scelto / ".guardrail.json").write_text('{"allow_commands": ["^rm "]}', encoding="utf-8")
        failures += check("acceso: allow_commands non esenta la rimozione", esito(home, scelto, tool=bash("rm .guardrail.json")), "deny")
        failures += check("acceso: conferma sul .guardrail.json + rm -rf $X: vince il blocco",
                          esito(home, scelto, tool=bash('echo x >> .guardrail.json; cat nota | rm -rf "$X"')), "deny")
        (scelto / ".guardrail.json").write_text("{}", encoding="utf-8")

        # Una copia del progetto in una cartella temporanea (fuori dalla home) non
        # accende niente: toglierla non spegne guardrail. Finché la sessione non ci lavora.
        copia = base / "copia-progetto"
        (copia / ".git").mkdir(parents=True)
        (copia / ".claude").mkdir()
        (copia / ".guardrail.json").write_text("{}", encoding="utf-8")
        failures += check("copia in /tmp: rm -rf passa", esito(home, scelto, tool=bash(f"rm -rf {copia}")), "allow")
        failures += check("copia in /tmp: rm del suo .guardrail.json passa", esito(home, scelto, tool=bash(f"rm {copia}/.guardrail.json")), "allow")
        failures += check("copia in /tmp: anche da una cartella spenta", esito(home, libero, tool=bash(f"rm -rf {copia}")), "allow")
        failures += check("copia in /tmp: le sue settings si scrivono", esito(home, scelto, tool=bash(f"echo '{{}}' > {copia}/.claude/settings.json")), "allow")
        failures += check("copia in /tmp in cui si lavora: rm -rf negato", esito(home, copia, tool=bash(f"rm -rf {copia}")), "deny")
        failures += check("copia in /tmp che è il progetto della sessione: negato", esito(home, scelto, progetto=copia, tool=bash(f"rm -rf {copia}")), "deny")
        failures += check("copia in /tmp tolta per variabile: negato", esito(home, scelto, tool=bash('C=x; rm "$C/.guardrail.json"')), "deny")
        # Un .guardrail.json che è un link verso /tmp resta la configurazione del progetto.
        legato = home / "legato"
        (legato / ".git").mkdir(parents=True)
        (base / "conf-legata.json").write_text("{}", encoding="utf-8")
        (legato / ".guardrail.json").symlink_to(base / "conf-legata.json")
        failures += check("link verso /tmp al posto del .guardrail.json: la scrittura chiede", esito(home, legato, tool=bash("echo '{}' > .guardrail.json")), "ask")

        # Un link a /dev/null al posto del file non spegne guardrail.
        linkato = home / "linkato"
        (linkato / ".git").mkdir(parents=True)
        (linkato / ".guardrail.json").symlink_to("/dev/null")
        failures += check("link a /dev/null al posto del .guardrail.json: resta acceso", esito(home, linkato), "deny")

        (base / "mask.tsv").write_text("magazzino\tsede1\n", encoding="utf-8")
        od = {"tool_name": "Bash", "tool_input": {"command": "od -c nota.txt"}}
        failures += check("progetto spento: il mascheramento vale lo stesso", esito(home, libero, mappa=base / "mask.tsv", tool=od), "deny")

    print(f"\nattivazione: {'tutto verde' if not failures else f'{failures} fallimenti'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
