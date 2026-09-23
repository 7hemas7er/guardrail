#!/usr/bin/env python3
"""Guardrail — mascheramento dei termini riservati.

Alcuni termini (nomi di host, di persone, di luoghi, di clienti) non devono arrivare
al modello, da qualunque parte escano: l'output di un comando, un documento letto,
un risultato di ricerca, la risposta di un server MCP. La mappa sta in
~/.config/guardrail/mask.tsv, fuori da ogni repo, una coppia per riga:

    termine-reale   segnaposto        # separati da spazi o TAB; '#' commenta

Senza mappa non succede nulla. Con la mappa, due direzioni:

  verso il modello   ogni risultato di tool passa da `mask.py output` (PostToolUse,
                     `updatedToolOutput`): ogni stringa del risultato esce con i
                     segnaposto. Il transcript salva la versione riscritta, quindi
                     anche una sessione ripresa non rivede l'originale.
                     Bash in più passa da `mask.py run`, che maschera già in uscita:
                     è l'unico modo di coprire i comandi che falliscono, perché
                     l'errore di un tool (PostToolUseFailure) non si può riscrivere.
  verso la macchina  il modello scrive segnaposto, i tool ricevono termini reali
                     (`unmask_tool_input`, via `updatedInput` di PreToolUse, che il
                     modello non vede). Solo dove un errore non può rimandare
                     indietro il termine reale: vedi la funzione.

Negato, perché il risultato non si può mascherare: il Read di PDF, documenti Office
e archivi (il testo non è nei byte: via Bash pdftotext / unzip -p escono mascherati),
WebFetch verso un indirizzo che contiene un segnaposto (la pagina la legge un
modello prima di qualunque hook: per una risorsa privata si usa curl via Bash), e i
comandi che mostrano il testo trasformato (od, xxd, base64, rev…), dove il filtro
non riconosce più le parole.

Il prompt che contiene un termine reale è bloccato (`mask.py prompt`): un hook non
può riscriverlo, solo fermarlo.

Non coperto, e non copribile da un hook: il contenuto delle immagini (screenshot,
foto); il contesto che Claude Code inietta da sé (git status e commit recenti, che
si tolgono con `"includeGitInstructions": false`; CLAUDE.md; i file citati con @);
qualunque altra trasformazione del testo fatta apposta per aggirare il filtro. È una
protezione contro l'esposizione accidentale, non contro un agente che la cerca.

Uso da riga di comando:
    mask.py run      esegue lo script letto da stdin con la mappa applicata
    mask.py output   hook PostToolUse (JSON di Claude Code su stdin)
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
from typing import Any

HERE = Path(__file__).resolve().parent

# Un termine è mascherato solo se non è parte di una parola più lunga: `nas-magazzino`
# e `magazzino.lan` sì, `magazzinone` no. L'underscore conta come separatore.
_PRIMA = r"(?<![A-Za-z0-9])"
_DOPO = r"(?![A-Za-z0-9])"

# Formati il cui testo non compare nei byte (compresso o binario): il risultato del
# Read non si può mascherare, quindi si nega. Via Bash si convertono in testo.
FORMATI_OPACHI = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".odt", ".ods", ".odp", ".epub", ".pages", ".numbers", ".key",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
})

# Comandi che mostrano un testo trasformato: un carattere per colonna, in esadecimale,
# codificato, al contrario. Il filtro lavora sulle parole e lì non le riconosce: è
# successo nella prima prova reale, `od -c` usato per capire un Edit fallito ha
# mostrato il termine lettera per lettera. Un filtro testuale non ferma ogni
# trasformazione possibile; questi sono quelli a cui si ricorre per "guardare i byte".
COMANDI_TRASFORMANTI = re.compile(
    r"(?:^|[\s;&|(`$])(od|xxd|hexdump|hd|base64|base32|basenc|uuencode|rev)(?=\s|$|[;&|)])"
)

# Chiavi del risultato di un tool che contengono dati binari codificati, non testo:
# una sostituzione lì dentro corromperebbe l'immagine senza nascondere nulla.
CHIAVI_BINARIE = frozenset({"base64"})


class MappaNonValida(Exception):
    pass


def map_path() -> Path:
    override = os.environ.get("GUARDRAIL_MASK_MAP")
    if override:
        return Path(override)
    return Path.home() / ".config" / "guardrail" / "mask.tsv"


def load_pairs() -> list[tuple[str, str]]:
    """[(reale, segnaposto)], i termini più lunghi prima. Vuota se la mappa non c'è.

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
            raise MappaNonValida(f"mappa {path}, riga {numero}: servono due campi, termine reale e segnaposto")
        reale, finto = campi
        if reale.lower() == finto.lower():
            raise MappaNonValida(f"mappa {path}, riga {numero}: il segnaposto coincide con il termine reale")
        pairs.append((reale, finto))

    for reale, _ in pairs:
        for _, finto in pairs:
            if _cerca(reale).search(finto):
                raise MappaNonValida(
                    f"mappa {path}: un segnaposto contiene un termine reale, l'output lo rimetterebbe in chiaro"
                )
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def _cerca(termine: str) -> re.Pattern[str]:
    return re.compile(_PRIMA + re.escape(termine) + _DOPO, re.IGNORECASE)


def _stessa_forma(trovato: str, sostituto: str) -> str:
    """`CASA` -> `SEDE1`, `Casa` -> `Sede1`, il resto minuscolo come nella mappa.

    Serve al viaggio di ritorno: il modello riscrive il segnaposto con le maiuscole
    che ha visto, e un sed deve ritrovare nel file la forma originale.
    """
    if trovato.isupper() and len(trovato) > 1:
        return sostituto.upper()
    if trovato[:1].isupper() and trovato[1:].islower():
        return sostituto[:1].upper() + sostituto[1:]
    return sostituto


def _sostituisci(text: str, da: str, a: str) -> str:
    return _cerca(da).sub(lambda m: _stessa_forma(m.group(0), a), text)


def mask(text: str, pairs: list[tuple[str, str]]) -> str:
    """Termini reali -> segnaposto: tutto ciò che va verso il modello."""
    for reale, finto in pairs:
        text = _sostituisci(text, reale, finto)
    return text


def unmask(text: str, pairs: list[tuple[str, str]]) -> str:
    """Segnaposto -> termini reali: ciò che il modello scrive e la macchina esegue."""
    for reale, finto in pairs:
        text = _sostituisci(text, finto, reale)
    return text


def contains_real(text: str, pairs: list[tuple[str, str]]) -> bool:
    return any(_cerca(reale).search(text) for reale, _ in pairs)


def contains_placeholder(text: str, pairs: list[tuple[str, str]]) -> bool:
    return any(_cerca(finto).search(text) for _, finto in pairs)


def mask_value(value: Any, pairs: list[tuple[str, str]]) -> Any:
    """Maschera ogni stringa di una struttura JSON, lasciando intatte chiavi e forma:
    è la condizione perché Claude Code accetti il risultato riscritto."""
    if isinstance(value, str):
        return mask(value, pairs)
    if isinstance(value, list):
        return [mask_value(item, pairs) for item in value]
    if isinstance(value, dict):
        return {
            key: item if key in CHIAVI_BINARIE else mask_value(item, pairs)
            for key, item in value.items()
        }
    return value


# ---------------------------------------------------------------------------
# Verso la macchina: l'input dei tool
# ---------------------------------------------------------------------------

def wrap_command(cmd: str) -> str:
    """Il comando Bash riscritto: il testo del modello passa intatto al runner via
    heredoc, e i termini reali li inserisce il runner leggendo la mappa.

    Non si mette il comando già convertito in `updatedInput`, benché il modello non
    lo veda: lo vedrebbero la richiesta di conferma e, in modalità auto, il
    classificatore, che è a sua volta un modello.
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


def _percorso(raw: str, cwd: str) -> Path:
    path = Path(os.path.expanduser(raw))
    return path if path.is_absolute() or not cwd else Path(cwd) / path


def _percorso_reale(raw: Any, cwd: str, pairs: list[tuple[str, str]]) -> Any:
    """Un percorso col segnaposto diventa quello reale solo se quello reale esiste e
    l'altro no: altrimenti l'errore "file inesistente" citerebbe il termine reale."""
    if not isinstance(raw, str) or not contains_placeholder(raw, pairs):
        return raw
    reale = unmask(raw, pairs)
    if _percorso(reale, cwd).exists() and not _percorso(raw, cwd).exists():
        return reale
    return raw


def unmask_tool_input(tool: str, tool_input: dict, cwd: str, pairs: list[tuple[str, str]]) -> dict | None:
    """L'input con i segnaposto tornati termini reali, o None se non cambia nulla.

    Solo per i tool che lavorano in locale senza un modello di mezzo, e solo dove un
    errore del tool non può citare il termine reale: l'errore di un tool arriva al
    modello così com'è (PostToolUseFailure non lo riscrive). Per questo:
      - Read, Grep, Glob: i percorsi solo se il file reale esiste; il pattern di Grep
        e Glob sì (una ricerca vuota non è un errore).
      - Write: il contenuto sì, un file scritto non viene citato nell'errore.
    Edit no: Claude Code verifica che old_string sia nel file *prima* dei hook, quindi
    un Edit col segnaposto fallisce senza mai arrivare qui. Si modifica via Bash
    (sed), dove il runner converte i segnaposto; l'avviso di sessione lo dice.
    Esclusi i server MCP (un errore del server può citare la query), WebFetch e
    WebSearch (l'input finisce a un modello o a un motore di ricerca), Agent e simili
    (il prompt va a un altro modello): lì il segnaposto resta segnaposto.
    """
    if not pairs:
        return None
    nuovo = dict(tool_input)

    for chiave in ("file_path", "path", "notebook_path"):
        if chiave in nuovo:
            nuovo[chiave] = _percorso_reale(nuovo[chiave], cwd, pairs)

    if tool in ("Grep", "Glob"):
        for chiave in ("pattern", "glob"):
            if isinstance(nuovo.get(chiave), str):
                nuovo[chiave] = unmask(nuovo[chiave], pairs)
    elif tool == "Write":
        if isinstance(nuovo.get("content"), str):
            nuovo["content"] = unmask(nuovo["content"], pairs)
    elif tool not in ("Read",):
        return None

    return nuovo if nuovo != tool_input else None


def blocking_reason(tool: str, tool_input: dict, pairs: list[tuple[str, str]]) -> str | None:
    """Il motivo per negare un tool il cui risultato non si può mascherare."""
    if not pairs:
        return None
    if tool == "Bash":
        trovato = COMANDI_TRASFORMANTI.search(str(tool_input.get("command", "")))
        if trovato:
            return (
                f"{trovato.group(1)} mostra il testo trasformato (byte, codifica, al contrario) e il "
                "filtro non vi riconosce i termini mascherati: con il mascheramento attivo non si usa. "
                "Per capire perché un testo non corrisponde, rileggilo con cat o grep."
            )
    if tool == "Read":
        raw = tool_input.get("file_path")
        if isinstance(raw, str) and Path(raw).suffix.lower() in FORMATI_OPACHI:
            return (
                f"{Path(raw).name}: il testo di questo formato non si può mascherare nel risultato del "
                "Read. Convertilo via Bash (pdftotext file -, unzip -p, …): lì l'output esce già "
                "con i segnaposto."
            )
    if tool == "WebFetch":
        url = tool_input.get("url")
        if isinstance(url, str) and (contains_placeholder(url, pairs) or contains_real(url, pairs)):
            return (
                "l'indirizzo contiene un termine mascherato: WebFetch fa leggere la pagina a un modello "
                "prima di qualunque hook. Per una risorsa privata usa curl via Bash."
            )
    return None


# ---------------------------------------------------------------------------
# Riga di comando
# ---------------------------------------------------------------------------

def cmd_run() -> int:
    script = sys.stdin.read()
    try:
        pairs = load_pairs()
    except MappaNonValida as exc:
        # Il messaggio non contiene termini reali: cita solo path e numero di riga.
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


def _leggi_payload() -> dict:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def cmd_output() -> int:
    payload = _leggi_payload()
    try:
        pairs = load_pairs()
    except MappaNonValida:
        return 0  # guard.py ha già negato il tool prima che partisse
    if not pairs or "tool_response" not in payload:
        return 0
    risultato = payload["tool_response"]
    mascherato = mask_value(risultato, pairs)
    if mascherato != risultato:
        print(json.dumps({
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": mascherato}
        }, ensure_ascii=False))
    return 0


def cmd_prompt() -> int:
    payload = _leggi_payload()
    prompt = str(payload.get("prompt", ""))
    try:
        pairs = load_pairs()
    except MappaNonValida as exc:
        print(json.dumps({"decision": "block", "reason": f"[guardrail] {exc}"}))
        return 0
    trovati = [finto for reale, finto in pairs if _cerca(reale).search(prompt)]
    if trovati:
        # Il motivo lo legge l'utente, non il modello: il prompt bloccato non parte.
        print(json.dumps({
            "decision": "block",
            "reason": (
                "[guardrail] il prompt contiene un termine mascherato: riscrivilo usando "
                f"il segnaposto ({', '.join(sorted(set(trovati)))})."
            ),
        }, ensure_ascii=False))
    return 0


def main() -> int:
    comando = sys.argv[1] if len(sys.argv) > 1 else ""
    if comando == "run":
        return cmd_run()
    if comando == "output":
        return cmd_output()
    if comando == "prompt":
        return cmd_prompt()
    print("uso: mask.py run|output|prompt", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
