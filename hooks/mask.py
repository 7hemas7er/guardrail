#!/usr/bin/env python3
"""Guardrail — mascheramento dei nomi di rete.

Alcuni nomi (host, domini, luoghi) non devono arrivare al modello. La mappa sta in
~/.config/guardrail/mask.tsv, fuori da ogni repo, una coppia per riga:

    nome-reale   segnaposto        # separati da spazi o TAB; '#' commenta

Senza mappa non succede nulla. Con la mappa:

    Bash              guard.py riscrive il comando perché passi da `mask.py run`:
                      segnaposto -> nome reale nel comando, nome reale -> segnaposto
                      nell'output. Il modello vede solo i segnaposto, anche nel
                      comando riscritto: la mappa la legge il runner, non il hook.
    Read              negato sui file che contengono un nome reale (l'output del
                      tool Read non si può riscrivere): va letto con cat via Bash.
    UserPromptSubmit  `mask.py prompt` blocca il prompt che contiene un nome reale
                      (un hook non può riscrivere il prompt, solo fermarlo).

Grep e Glob non sono coperti: il loro output arriva al modello così com'è.

Uso da riga di comando:
    mask.py run      esegue lo script letto da stdin con la mappa applicata
    mask.py prompt   hook UserPromptSubmit (JSON di Claude Code su stdin)

Solo libreria standard.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Un nome è mascherato solo se non è parte di una parola più lunga: `nas-magazzino`
# e `magazzino.lan` sì, `magazzinone` no. L'underscore conta come separatore.
_PRIMA = r"(?<![A-Za-z0-9])"
_DOPO = r"(?![A-Za-z0-9])"

# Oltre questa dimensione il Read di un file non viene scansionato per intero.
READ_SCAN_MAX_BYTES = 8 * 1024 * 1024


class MappaNonValida(Exception):
    pass


def map_path() -> Path:
    override = os.environ.get("GUARDRAIL_MASK_MAP")
    if override:
        return Path(override)
    return Path.home() / ".config" / "guardrail" / "mask.tsv"


def load_pairs() -> list[tuple[str, str]]:
    """[(reale, segnaposto)], i nomi più lunghi prima. Vuota se la mappa non c'è.

    Una mappa che esiste ma non si legge o è incoerente solleva MappaNonValida:
    chi la usa deve fermarsi, non procedere senza mascheramento.
    """
    path = map_path()
    if not path.exists():
        return []
    try:
        righe = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise MappaNonValida(f"mappa {path} illeggibile: {exc}") from exc

    pairs: list[tuple[str, str]] = []
    for numero, riga in enumerate(righe, start=1):
        riga = riga.split("#", 1)[0].strip()
        if not riga:
            continue
        campi = riga.split()
        if len(campi) != 2:
            raise MappaNonValida(f"mappa {path}, riga {numero}: servono due campi, nome reale e segnaposto")
        reale, finto = campi
        if reale.lower() == finto.lower():
            raise MappaNonValida(f"mappa {path}, riga {numero}: il segnaposto coincide con il nome reale")
        pairs.append((reale, finto))

    for reale, _ in pairs:
        for _, finto in pairs:
            if _cerca_reale(reale).search(finto):
                raise MappaNonValida(
                    f"mappa {path}: un segnaposto contiene un nome reale, l'output lo rimetterebbe in chiaro"
                )
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def _cerca_reale(reale: str) -> re.Pattern[str]:
    return re.compile(_PRIMA + re.escape(reale) + _DOPO, re.IGNORECASE)


def _cerca_finto(finto: str) -> re.Pattern[str]:
    return re.compile(_PRIMA + re.escape(finto) + _DOPO)


def mask(text: str, pairs: list[tuple[str, str]]) -> str:
    """Nomi reali -> segnaposto: tutto ciò che va verso il modello."""
    for reale, finto in pairs:
        text = _cerca_reale(reale).sub(finto, text)
    return text


def unmask(text: str, pairs: list[tuple[str, str]]) -> str:
    """Segnaposto -> nomi reali: ciò che il modello scrive e la macchina esegue."""
    for reale, finto in pairs:
        text = _cerca_finto(finto).sub(lambda _m, r=reale: r, text)
    return text


def contains_real(text: str, pairs: list[tuple[str, str]]) -> bool:
    return any(_cerca_reale(reale).search(text) for reale, _ in pairs)


def wrap_command(cmd: str) -> str:
    """Il comando riscritto: il testo del modello passa intatto al runner via heredoc.

    Resta leggibile per chi approva e per il classificatore della modalità auto;
    i nomi reali li inserisce il runner, a esecuzione, leggendo la mappa.
    """
    delimitatore = "__GUARDRAIL_MASK__"
    righe = cmd.splitlines()
    while delimitatore in righe:
        delimitatore += "_"
    runner = HERE / "run-python.sh"
    return (
        f'bash "{runner}" "{HERE / "mask.py"}" run <<\'{delimitatore}\'\n'
        f"{cmd}\n"
        f"{delimitatore}"
    )


def file_contains_real(path: Path, pairs: list[tuple[str, str]]) -> bool:
    try:
        with open(path, "rb") as handle:
            data = handle.read(READ_SCAN_MAX_BYTES)
    except OSError:
        return False
    return contains_real(data.decode("utf-8", errors="replace"), pairs)


# ---------------------------------------------------------------------------
# Riga di comando
# ---------------------------------------------------------------------------

def cmd_run() -> int:
    script = sys.stdin.read()
    try:
        pairs = load_pairs()
    except MappaNonValida as exc:
        # Il messaggio non contiene nomi reali: cita solo path e numero di riga.
        print(f"[guardrail] {exc}: comando non eseguito", file=sys.stderr)
        return 1

    proc = subprocess.Popen(
        ["bash", "-c", unmask(script, pairs)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.stdout is not None
    out = sys.stdout.buffer
    for riga in iter(proc.stdout.readline, b""):
        testo = riga.decode("utf-8", errors="surrogateescape")
        out.write(mask(testo, pairs).encode("utf-8", errors="surrogateescape"))
        out.flush()
    codice = proc.wait()
    # Ucciso da un segnale: lo stesso codice che avrebbe restituito la shell.
    return 128 - codice if codice < 0 else codice


def cmd_prompt() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    prompt = str(payload.get("prompt", "")) if isinstance(payload, dict) else ""
    try:
        pairs = load_pairs()
    except MappaNonValida as exc:
        print(json.dumps({"decision": "block", "reason": f"[guardrail] {exc}"}))
        return 0
    trovati = [finto for reale, finto in pairs if _cerca_reale(reale).search(prompt)]
    if trovati:
        # Il motivo lo legge l'utente, non il modello: il prompt bloccato non parte.
        print(json.dumps({
            "decision": "block",
            "reason": (
                "[guardrail] il prompt contiene un nome di rete mascherato: riscrivilo usando "
                f"il segnaposto ({', '.join(sorted(set(trovati)))})."
            ),
        }, ensure_ascii=False))
    return 0


def main() -> int:
    comando = sys.argv[1] if len(sys.argv) > 1 else ""
    if comando == "run":
        return cmd_run()
    if comando == "prompt":
        return cmd_prompt()
    print("uso: mask.py run|prompt", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
