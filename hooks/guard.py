#!/usr/bin/env python3
"""Guardrail — hook PreToolUse per Claude Code.

Legge da stdin il JSON che Claude Code passa ai hook:
    {"tool_name": "...", "tool_input": {...}, "cwd": "...", "session_id": "..."}
e risponde su stdout con una decisione:
    allow  -> nessun output (il tool procede)
    ask    -> chiede conferma. ⚠️ NON garantisce un umano: in modalità auto la
              concede l'agente. Solo `deny` non è scavalcabile.
    deny   -> blocca il tool e spiega a Claude il motivo

Quattro famiglie di regole, tutte nella funzione `decide`:
    Bash        comandi distruttivi, deploy con cancellazione, SQL da CLI su prod,
                letture di segreti da shell (cat .env), scritture da shell alla
                configurazione di guardrail, script invocati (letti e scansionati)
    mcp__*__*   query SQL via server MCP: scritture su prod, DELETE/UPDATE senza WHERE;
                ogni altro server MCP: operazioni distruttive o di modifica
    Write/Edit  file di segreti, dotfile della home, ~/.claude, la configurazione
                di guardrail stessa, e tutto ciò che sta fuori dal progetto
    Read        file di segreti, ~/.ssh e le altre directory di credenziali

Con ~/.config/guardrail/mask.tsv presente, in più riporta ai termini reali i
segnaposto nell'input dei tool, fa passare ogni comando Bash dal runner di
mascheramento e nega i tool il cui risultato non si può mascherare (vedi
hooks/mask.py). Senza la mappa, nessuna differenza.

Guardrail vale solo nei progetti che l'hanno scelto: quelli con un `.guardrail.json`
nella root o in una directory superiore (vedi `attivo`). Altrove valgono solo le
regole che proteggono guardrail stesso (la sua configurazione, il suo codice, le
impostazioni di Claude Code) e il mascheramento, che segue la mappa e non il progetto.
Le liste di `.guardrail.json` si sommano a quelle di `~/.guardrail.json`, che però
non accende niente da solo. Vedi README.md.

Solo libreria standard. Nessuna dipendenza, nessuna rete.
"""
from __future__ import annotations

import fnmatch
import functools
import hashlib
import itertools
import json
import os
import re
import shlex
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

import mask  # hooks/mask.py: mascheramento dei termini riservati, attivo solo con la mappa

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    # Regex (case-insensitive) che, se compaiono nel comando o nel nome del
    # server MCP, marcano il bersaglio come PRODUZIONE.
    "prod_patterns": [r"\bprod(uction|uzione)?\b", r"\blive\b"],
    # Nomi esatti di server MCP che sono produzione (spesso solo "postgres").
    "prod_mcp_servers": [],
    # Server MCP condivisi ma non prod: le scritture chiedono conferma.
    "ask_mcp_servers": [],
    # Server MCP che scrivono testo (documenti, note): il testo dei loro campi di
    # contenuto non conta per riconoscere un bersaglio di produzione. Solo per nome
    # esatto, dichiarato da chi configura il progetto.
    "prose_mcp_servers": [],
    # Regex aggiuntive sul comando Bash: blocco secco / conferma / eccezione.
    "deny_commands": [],
    "ask_commands": [],
    "allow_commands": [],
    # Script già letti e approvati: {"path": regex, "sha256": impronta}. Esentano
    # solo la scansione del contenuto, e solo finché il contenuto non cambia.
    "allow_scripts": [],
}

# Le voci di queste chiavi sono oggetti, non regex: non vanno convertite in stringa.
OBJECT_KEYS = frozenset({"allow_scripts"})

WRITE_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|REPLACE|MERGE|RENAME|VACUUM\s+FULL)\b",
    re.I,
)
READ_ONLY_START = re.compile(r"^\s*(SELECT|WITH|EXPLAIN|SHOW|DESCRIBE|DESC|TABLE|VALUES|\\d)", re.I)

# Parole che dicono "qui c'è del SQL". Servono a non trattare come query il
# campo `query` di un server MCP che SQL non ne parla affatto.
SQL_KEYWORD = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|MERGE|REPLACE"
    r"|CALL|DO|COPY|EXPLAIN|SHOW|DESCRIBE|VACUUM|ANALYZE|REFRESH|BEGIN|COMMIT|ROLLBACK)\b",
    re.I,
)
# Istruzioni che non leggono e non scrivono: delimitano una transazione o
# toccano lo stato di sessione. Non rendono una lettura una scrittura.
SQL_NEUTRAL = re.compile(r"^\s*(BEGIN|START\s+TRANSACTION|COMMIT|ROLLBACK|END|SET|SHOW)\b", re.I)
# `SELECT ... INTO tabella` crea una tabella: legge come una lettura, scrive.
SELECT_INTO = re.compile(r"^\s*SELECT\b(?![^;]*\bINSERT\b)[^;]*\bINTO\s+[\w\".]+", re.I | re.S)
# Funzioni che dentro una SELECT non sono letture: eseguono SQL altrove, toccano
# il filesystem, interrompono sessioni, avanzano sequenze. `SELECT` da solo non
# dimostra niente, e il SQL che queste eseguono sta dentro un literal, cioè
# esattamente dove lo scheletro non guarda.
SQL_UNSAFE_FUNC = re.compile(
    r"\b(dblink(_exec)?|query_to_xml|pg_terminate_backend|pg_cancel_backend|pg_read_(binary_)?file"
    r"|pg_ls_dir|lo_(import|export|unlink)|pg_stat_statements_reset|pg_logical_slot_get_changes"
    r"|setval|nextval|load_file|sys_exec|sys_eval)\s*\(",
    re.I,
)
# MySQL: `SELECT … INTO OUTFILE` scrive un file sul server.
SELECT_OUTFILE = re.compile(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", re.I)
# Apertura di un dollar-quote: $$ oppure $tag$.
DOLLAR_TAG = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")


def sql_normalizzato(sql: str) -> tuple[str, bool]:
    """Il SQL con literal e commenti svuotati, e se ci si può fidare del risultato.

    Attraversa il testo una volta sola tenendo lo stato — testo, literal fra
    apici (con `''` raddoppiato), dollar-quote con tag, commento di riga,
    commento a blocco annidabile — perché letterali e commenti si intrecciano e
    nessun ordine di sostituzioni regge: un apice dentro `/* … */` non è un
    apice per il database, ma per una regex sì, e lì dentro ci si può nascondere
    una `DELETE`.

    Si applica solo al SQL puro (payload di un tool MCP), MAI a una riga di
    shell: lì gli apici delimitano il payload di `psql -c '...'` e svuotarli
    nasconderebbe la scrittura vera.

    Il secondo valore è falso quando a fine testo un literal o un commento è
    rimasto aperto: il testo non si capisce, e chi non capisce non autorizza.
    """
    pezzi: list[str] = []
    affidabile = True
    i, n = 0, len(sql)
    while i < n:
        if sql.startswith("--", i):
            fine = sql.find("\n", i)
            pezzi.append(" ")
            i = n if fine == -1 else fine
            continue
        if sql.startswith("/*", i):
            livello, j = 1, i + 2
            while j < n and livello:
                if sql.startswith("/*", j):
                    livello, j = livello + 1, j + 2
                elif sql.startswith("*/", j):
                    livello, j = livello - 1, j + 2
                else:
                    j += 1
            affidabile = affidabile and livello == 0
            pezzi.append(" ")
            i = j
            continue
        if sql[i] == "'":
            j, chiuso = i + 1, False
            while j < n:
                if sql[j] != "'":
                    j += 1
                elif j + 1 < n and sql[j + 1] == "'":
                    j += 2
                else:
                    chiuso, j = True, j + 1
                    break
            affidabile = affidabile and chiuso
            pezzi.append(" '' ")
            i = j
            continue
        if (apertura := DOLLAR_TAG.match(sql, i)):
            tag = apertura.group(0)
            chiusura = sql.find(tag, apertura.end())
            affidabile = affidabile and chiusura != -1
            pezzi.append(" '' ")
            i = n if chiusura == -1 else chiusura + len(tag)
            continue
        pezzi.append(sql[i])
        i += 1
    return "".join(pezzi), affidabile


def classifica_sql(sql: str) -> str:
    """`lettura`, `scrittura` o `incerta`.

    `incerta` non è un ripiego: è la risposta onesta per un `DO $$ … $$`, una
    `CALL`, un `COPY … FROM`, un literal non chiuso. Chi la riceve non deve
    tirare a indovinare — su produzione si ferma e mostra la query.
    """
    scheletro, affidabile = sql_normalizzato(sql)
    if not affidabile:
        return "incerta"
    istruzioni = [s for s in scheletro.split(";") if s.strip()]
    if not istruzioni:
        return "incerta"
    if any(WRITE_SQL.search(s) or SELECT_INTO.match(s) or SELECT_OUTFILE.search(s) for s in istruzioni):
        return "scrittura"
    if any(SQL_UNSAFE_FUNC.search(s) for s in istruzioni):
        return "incerta"
    if all(READ_ONLY_START.match(s) or SQL_NEUTRAL.match(s) for s in istruzioni):
        return "lettura"
    return "incerta"


def query_esposta(sql: str, limite: int = 300) -> str:
    """La query dentro il messaggio: chi decide deve vedere cosa girerebbe.

    Le credenziali si redigono — una connection string in un payload finirebbe
    nella trascrizione e nel log — e il testo si tronca, perché serve a decidere,
    non ad archiviare. I valori restano visibili: sono ciò che rende la query
    giudicabile. Possono però essere dati personali, e il messaggio lo ricorda.
    """
    pulita = re.sub(r"(?i)\b(password|pwd|passwd|token|secret|api[_-]?key)\s*=\s*('[^']*'|[^\s')]+)", r"\1=***", sql)
    pulita = re.sub(r"(?i)(://[^:\s/@]+):[^@\s/]+@", r"\1:***@", pulita)
    pulita = " ".join(pulita.split())
    if len(pulita) > limite:
        pulita = f"{pulita[:limite]}… (+{len(pulita) - limite} caratteri)"
    return pulita

# Dimensione massima di uno script invocato che il hook accetta di leggere.
SCRIPT_MAX_BYTES = 256 * 1024


def _read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def config_progetto(start: str) -> Path | None:
    """Il .guardrail.json che vale per `start`: il primo risalendo verso la radice.

    Quello nella home non conta: sono le liste comuni dell'utente, e se valesse come
    configurazione di progetto accenderebbe guardrail in ogni cartella sotto la home.
    """
    if not start:
        return None
    try:
        current = Path(start).resolve()
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return None
    # Conta qualunque voce con quel nome, non solo un file: un link a /dev/null o una
    # directory al suo posto non devono spegnere guardrail.
    for candidate in [current, *current.parents]:
        probe = candidate / ".guardrail.json"
        if candidate != home and os.path.lexists(probe):
            return probe
    return None


def attivo(cwd: str) -> bool:
    """Guardrail è acceso qui? Solo dove un .guardrail.json lo dice.

    Basta che ce l'abbia la directory di lavoro o il progetto da cui è partita la
    sessione (CLAUDE_PROJECT_DIR): un `cd` fuori dal progetto non lo spegne.
    """
    if os.environ.get("GUARDRAIL_CONFIG"):
        return True
    return any(config_progetto(start) for start in (cwd or os.getcwd(), os.environ.get("CLAUDE_PROJECT_DIR", "")))


def load_config(cwd: str) -> dict:
    """Unisce default, ~/.guardrail.json e il .guardrail.json del progetto."""
    config = {key: list(value) for key, value in DEFAULT_CONFIG.items()}

    sources: list[Path] = []
    override = os.environ.get("GUARDRAIL_CONFIG")
    if override:
        sources.append(Path(override))
    else:
        sources.append(Path.home() / ".guardrail.json")
        progetto = config_progetto(cwd or os.getcwd()) or config_progetto(os.environ.get("CLAUDE_PROJECT_DIR", ""))
        if progetto:
            sources.append(progetto)

    for source in sources:
        for key, value in _read_json(source).items():
            if key in config and isinstance(value, list):
                config[key].extend(value if key in OBJECT_KEYS else (str(item) for item in value))
    return config


def project_root(cwd: str) -> Path | None:
    """La root git del progetto (o la cwd stessa se non è un repo)."""
    if not cwd:
        return None
    try:
        current = Path(cwd).resolve()
    except OSError:
        return None
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return current


# ---------------------------------------------------------------------------
# Decisioni
# ---------------------------------------------------------------------------

class Decision(Exception):
    def __init__(self, verdict: str, reason: str):
        super().__init__(reason)
        self.verdict = verdict
        self.reason = reason


def deny(reason: str) -> None:
    raise Decision("deny", reason)


def ask(reason: str) -> None:
    raise Decision("ask", reason)


def matches_any(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.I):
                return pattern
        except re.error:
            continue
    return None


# ---------------------------------------------------------------------------
# Bash: il comando vero
# ---------------------------------------------------------------------------
#
# Ogni controllo che chiede «questo comando è rm? è find? è uno script?» deve
# chiederlo qui. Prima ognuno aveva la sua regex e la sua lista di prefissi
# (`command`, `env`, `nohup`, `FOO=1`…), e ogni prefisso dimenticato era un buco:
# la forma nuda era bloccata, la stessa con `nice`, `then`, `/bin/` o `\` davanti
# passava. Due pezzi, e nient'altro:
#
#   comandi(testo)           spezza il testo in comandi come lo fa la shell
#   comando_effettivo(parole)  salta ciò che sta davanti al comando vero

MAX_ANNIDAMENTO = 12
# Quanti caratteri, in tutto, si rileggono cercando dove si chiude una `(`, una `"` o
# un backtick, per carattere del testo. Un comando vero ne spende pochi (uno per
# livello di annidamento); `$( ` ripetuto e mai chiuso li rilegge ogni volta fino in
# fondo, ed è quadratico.
SPESA_PER_CARATTERE = 40
_spesa = [0, 0]  # [spesa fin qui, tetto] del testo che `comandi` sta leggendo


class Comando(NamedTuple):
    """Un comando semplice, letto con le virgolette."""

    parole: tuple[str, ...]  # nome e argomenti, senza virgolette né backslash, senza redirezioni
    uscite: tuple[str, ...]  # bersagli di `>`, `>>`, `&>`, `>|`
    entrate: tuple[str, ...]  # bersagli di `<`
    testo: str  # com'era scritto, per le regole che guardano il testo


# Un pezzo di parola senza niente di speciale: si consuma in un colpo solo.
CORRENTE = re.compile(r"[^\s'\"\\$`;&|()<>#]+")
REDIREZIONE = re.compile(r"&>>?|<<<|<<-?|<>|>>|>\||[<>]&?")
# `2>&1`, `>&-`: duplica un descrittore, non scrive su un file.
FD_DUPLICATO = re.compile(r"\d+-?|-")


def _addebita(da: int, a: int) -> None:
    _spesa[0] += a - da
    if _spesa[0] > _spesa[1]:
        deny(
            "comando troppo intricato per essere controllato: virgolette, backtick o `$(` aperti e mai chiusi. "
            "Riscrivilo in più comandi semplici. (guardrail: filesystem-shell-segreti.md)"
        )


def _fine_backtick(testo: str, i: int) -> int:
    """L'indice del backtick che chiude quello in `i`, o -1."""
    j, n = i + 1, len(testo)
    while j < n:
        if testo[j] == "\\":
            j += 2
        elif testo[j] == "`":
            break
        else:
            j += 1
    else:
        j = -1
    _addebita(i, n if j < 0 else j)
    return j


def _fine_virgolette(testo: str, i: int, prof: int) -> int:
    """L'indice della `"` che chiude quella in `i`, o -1. Dentro le virgolette
    doppie `$(…)` e i backtick contano: la shell li esegue."""
    if prof > MAX_ANNIDAMENTO:
        _troppo_annidato()
    j, n = i + 1, len(testo)
    while j < n:
        c = testo[j]
        if c == "\\":
            j += 2
        elif c == '"':
            _addebita(i, j)
            return j
        elif testo.startswith("$(", j):
            k = _chiudi_parentesi(testo, j + 2, prof + 1)
            j = k + 1 if k >= 0 else j + 2
        elif c == "`":
            k = _fine_backtick(testo, j)
            j = k + 1 if k >= 0 else j + 1
        else:
            j += 1
    _addebita(i, n)
    return -1


def _chiudi_parentesi(testo: str, i: int, prof: int) -> int:
    """L'indice della `)` che chiude la `(` aperta subito prima di `i`, o -1."""
    if prof > MAX_ANNIDAMENTO:
        _troppo_annidato()
    profondita, n, inizio = 1, len(testo), i
    while i < n:
        c = testo[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = testo.find("'", i + 1)
            i = j + 1 if j >= 0 else i + 1
            continue
        if c == '"':
            j = _fine_virgolette(testo, i, prof)
            i = j + 1 if j >= 0 else i + 1
            continue
        if c == "`":
            j = _fine_backtick(testo, i)
            i = j + 1 if j >= 0 else i + 1
            continue
        if c == "(":
            profondita += 1
        elif c == ")":
            profondita -= 1
            if profondita == 0:
                _addebita(inizio, i)
                return i
        i += 1
    _addebita(inizio, n)
    return -1


def _fine_graffe(testo: str, i: int) -> int:
    """L'indice della `}` che chiude la `${` che comincia in `i`, o -1. Si legge come
    la shell: `${a:-${b}}` annida, `${a:-"x}"}` e `${a:-'}'}` hanno la `}` fra virgolette,
    `\\}` è escapata, e `$(…)` e i backtick dentro hanno le loro."""
    j, n, profondita = i + 2, len(testo), 1
    while j < n:
        c = testo[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            k = testo.find("'", j + 1)
            if k < 0:
                break
            j = k + 1
            continue
        if c == '"':
            k = _fine_virgolette(testo, j, 1)
            if k < 0:
                break
            j = k + 1
            continue
        if c == "`":
            k = _fine_backtick(testo, j)
            if k < 0:
                break
            j = k + 1
            continue
        if testo.startswith("$(", j):
            k = _chiudi_parentesi(testo, j + 2, 1)
            if k < 0:
                break
            j = k + 1
            continue
        if testo.startswith("${", j):
            profondita += 1
            j += 2
            continue
        if c == "}":
            profondita -= 1
            if profondita == 0:
                _addebita(i, j)
                return j
        j += 1
    _addebita(i, n)
    return -1


def _troppo_annidato() -> None:
    # Un bug del guard lascia passare il tool: un annidamento che non si sa leggere
    # non può diventare un errore interno, o basterebbe annidare per saltare tutto.
    deny(
        "comando annidato troppo a fondo ($(…), virgolette e backtick uno dentro l'altro) per essere "
        "controllato. Spezzalo in più comandi. (guardrail: filesystem-shell-segreti.md)"
    )


def _senza_escape(dentro_virgolette: str) -> str:
    """Il testo fra virgolette doppie com'è per la shell: `\\"`, `\\$`, `\\\\` e `\\``
    perdono il backslash, a capo escapato sparisce, ogni altro `\\x` resta."""
    return re.sub(r"\\([$`\"\\\n])", lambda m: "" if m.group(1) == "\n" else m.group(1), dentro_virgolette)


def _sostituzioni(frammento: str, prof: int) -> list[Comando]:
    """I comandi dentro `$(…)` e backtick di un frammento fra virgolette doppie o `${…}`."""
    trovati: list[Comando] = []
    i, n = 0, len(frammento)
    while i < n:
        if frammento[i] == "\\":
            i += 2
        elif frammento.startswith("$(", i):
            k = _chiudi_parentesi(frammento, i + 2, prof + 1)
            if k >= 0:
                trovati.extend(_leggi(frammento[i + 2:k], prof + 1))
            i = k + 1 if k >= 0 else i + 2
        elif frammento[i] == "`":
            k = _fine_backtick(frammento, i)
            if k >= 0:
                trovati.extend(_leggi(frammento[i + 1:k].replace("\\`", "`"), prof + 1))
            i = k + 1 if k >= 0 else i + 1
        else:
            i += 1
    return trovati


class _Lettore:
    """Spezza un testo in comandi. Separatori: `;`, `&`, `|`, `(`, `)`, a capo, fuori
    da virgolette, escape e commenti. Le virgolette spaiate valgono come carattere
    qualunque: la shell darebbe errore, e il guard preferisce vedere un comando in
    più che perderlo dietro un apostrofo."""

    def __init__(self, testo: str, prof: int) -> None:
        if prof > MAX_ANNIDAMENTO:
            _troppo_annidato()
        self.testo, self.prof = testo, prof
        self.citata = False  # la parola in corso ha almeno un pezzo fra virgolette o escapato
        self.trovati: list[Comando] = []
        self.parole: list[str] = []
        self.uscite: list[str] = []
        self.entrate: list[str] = []
        self.pezzi: list[str] = []
        self.in_parola = False
        self.attesa: str | None = None  # la redirezione che aspetta il suo bersaglio
        self.heredoc: list[tuple[str, bool]] = []  # (tag, fra virgolette) degli heredoc aperti sulla riga
        self.inizio = 0
        self.riga_da = 0  # quanti comandi erano già in `trovati` quando la riga è cominciata

    def aggiungi(self, pezzo: str, citato: bool = False) -> None:
        self.pezzi.append(pezzo)
        self.in_parola = True
        self.citata = self.citata or citato

    def chiudi_parola(self) -> None:
        if not self.in_parola:
            return
        parola = "".join(self.pezzi)
        citata, self.citata = self.citata, False
        self.pezzi.clear()
        self.in_parola = False
        operatore, self.attesa = self.attesa, None
        if operatore is None:
            self.parole.append(parola)
        elif ">" in operatore:
            if not (operatore.endswith("&") and FD_DUPLICATO.fullmatch(parola)):
                self.uscite.append(parola)
        elif operatore == "<":
            self.entrate.append(parola)
        elif operatore in ("<<", "<<-"):
            self.heredoc.append((parola, citata))
        # `<<<` e `<&`: una stringa o un descrittore, non un file

    def chiudi_comando(self, fine: int) -> None:
        self.chiudi_parola()
        if self.parole or self.uscite or self.entrate:
            self.trovati.append(
                Comando(tuple(self.parole), tuple(self.uscite), tuple(self.entrate), self.testo[self.inizio:fine].strip())
            )
        self.parole, self.uscite, self.entrate = [], [], []
        self.attesa = None
        self.inizio = fine + 1

    def corpi_heredoc(self, pos: int, di_dati: bool) -> int:
        """Il corpo degli heredoc aperti sulla riga che finisce, da `pos` fino al tag.
        Ogni riga si legge da sola, senza il contesto di virgolette delle altre: il
        corpo non è sintassi di shell (un `'` in un testo non apre niente), ma può
        essere codice che una shell riceve, e una riga che comincia con `rm` va vista."""
        t = self.testo
        for tag, citato in self.heredoc:
            # Con il tag fra virgolette la shell non espande il corpo, ma chi lo riceve
            # può eseguirlo. È testo solo se lo riceve un comando che archivia dati
            # (`riceve_dati`); per chiunque altro il corpo resta analizzato.
            letterale = citato and di_dati
            while pos < len(t):
                fine = t.find("\n", pos)
                fine = len(t) if fine < 0 else fine
                riga, pos = t[pos:fine], fine + 1
                if riga.strip() == tag:
                    break
                if not letterale:
                    self.trovati.extend(_leggi(riga, self.prof))
                elif riga.split():
                    # Testo: niente separatori né sostituzioni (le `(` e i `;` di una frase
                    # non aprono comandi), ma una riga che *comincia* con un comando si vede.
                    self.trovati.append(Comando(tuple(riga.split()), (), (), riga.strip()))
        self.heredoc.clear()
        return min(pos, len(t))

    def sostituzione(self, i: int, apre: int) -> int:
        """`$(…)`, `<(…)`, `>(…)` che comincia in `i`: la parola lo contiene, i suoi
        comandi si leggono a parte. Il nuovo indice, o -1 se non si chiude."""
        k = _chiudi_parentesi(self.testo, i + apre, self.prof + 1)
        if k < 0:
            return -1
        self.aggiungi(self.testo[i:k + 1])
        self.trovati.extend(_leggi(self.testo[i + apre:k], self.prof + 1))
        return k + 1

    def dollaro(self, i: int) -> int:
        t = self.testo
        if t.startswith("$(", i):
            if (k := self.sostituzione(i, 2)) >= 0:
                return k
        elif t.startswith("${", i) and (k := _fine_graffe(t, i)) >= 0:
            self.aggiungi(t[i:k + 1])
            self.trovati.extend(_sostituzioni(t[i + 2:k], self.prof))
            return k + 1
        self.aggiungi("$")
        return i + 1

    def redirezione(self, i: int) -> int:
        """`<`, `>`, `&` fuori dalle virgolette: una redirezione, una process
        substitution o, per `&` da solo, un separatore."""
        t = self.testo
        if t[i] in "<>" and t.startswith("(", i + 1) and (k := self.sostituzione(i, 2)) >= 0:
            return k
        m = REDIREZIONE.match(t, i)
        if m is None:
            self.chiudi_comando(i)
            return i + 1
        if self.in_parola and "".join(self.pezzi).isdigit():
            self.pezzi.clear()  # `2>`: il descrittore, non un argomento
            self.in_parola = False
        else:
            self.chiudi_parola()
        self.attesa = m.group()
        return m.end()

    def esegui(self) -> list[Comando]:
        t, n = self.testo, len(self.testo)
        i = 0
        while i < n:
            c = t[i]
            if (m := CORRENTE.match(t, i)) is not None:
                self.aggiungi(m.group())
                i = m.end()
            elif c in " \t":
                self.chiudi_parola()
                i += 1
            elif c == "\n":
                self.chiudi_parola()
                # Un solo comando sulla riga, e che archivia dati: con `;`, `|` o `&&` il
                # corpo potrebbe andare a un altro, e allora resta analizzato.
                di_dati = (
                    bool(self.heredoc) and len(self.trovati) == self.riga_da and riceve_dati(comando_effettivo(self.parole))
                )
                self.chiudi_comando(i)
                i += 1
                if self.heredoc:
                    i = self.corpi_heredoc(i, di_dati)
                    self.inizio = i
                self.riga_da = len(self.trovati)
            elif c == "\\":
                if i + 1 < n and t[i + 1] != "\n":
                    self.aggiungi(t[i + 1], True)
                i += 2
            elif c == "'":
                j = t.find("'", i + 1)
                if j < 0:
                    self.aggiungi(c)
                    i += 1
                else:
                    self.aggiungi(t[i + 1:j], True)
                    i = j + 1
            elif c == '"':
                j = _fine_virgolette(t, i, self.prof)
                if j < 0:
                    self.aggiungi(c)
                    i += 1
                else:
                    self.aggiungi(_senza_escape(t[i + 1:j]), True)
                    self.trovati.extend(_sostituzioni(t[i + 1:j], self.prof))
                    i = j + 1
            elif c == "$":
                i = self.dollaro(i)
            elif c == "`":
                j = _fine_backtick(t, i)
                if j < 0:
                    self.aggiungi(c)
                    i += 1
                else:
                    self.aggiungi(t[i:j + 1])
                    self.trovati.extend(_leggi(t[i + 1:j].replace("\\`", "`"), self.prof + 1))
                    i = j + 1
            elif c == "#":
                if self.in_parola:  # `$#`, `a#b`
                    self.aggiungi(c)
                    i += 1
                else:
                    j = t.find("\n", i)
                    i = n if j < 0 else j
            elif c in "<>&":
                i = self.redirezione(i)
            else:  # ; | ( )
                self.chiudi_comando(i)
                i += 1
        self.chiudi_comando(n)
        return self.trovati


def _leggi(testo: str, prof: int) -> list[Comando]:
    return _Lettore(testo, prof).esegui()


def riceve_dati(comando: Effettivo) -> bool:
    """Il comando archivia il corpo di un heredoc invece di eseguirlo: `cat`, `tee`,
    `git`/`gh` con `-F -`. Elenco chiuso di proposito: chi non c'è (una shell, ssh,
    un interprete, un comando sconosciuto) potrebbe eseguirlo, e il corpo resta
    analizzato. L'elenco inverso, quello delle shell, lasciava passare chi mancava."""
    if comando.lanciatori:
        return False
    if comando.nome in ("cat", "tee"):
        return True
    if comando.nome in ("git", "gh"):
        args = comando.args
        return any(
            (a in GIT_STDIN_FLAGS and i + 1 < len(args) and args[i + 1] == "-") or a in {f"{f}=-" for f in GIT_STDIN_FLAGS}
            for i, a in enumerate(args)
        )
    return False


@functools.lru_cache(maxsize=64)
def comandi(testo: str) -> tuple[Comando, ...]:
    """I comandi che `testo` contiene, anche dentro `$(…)`, backtick e process
    substitution. Un testo che si limita a *citare* un comando (`grep "rm -rf" f`,
    `echo 'f() { rm -rf "$1"; }'`) ne ha uno solo: grep, echo."""
    _spesa[:] = [0, SPESA_PER_CARATTERE * len(testo) + 10_000]
    return tuple(_leggi(testo, 0))


# Parole chiave dopo le quali comincia un comando: `then rm`, `do rm`, `{ rm`, `! rm`.
PAROLE_CHIAVE = frozenset({"if", "then", "elif", "else", "while", "until", "do", "!", "{", "}"})
# `FOO=1`, `PATH+=:x`, `a[1]=x`: il valore è già senza virgolette.
ASSEGNAMENTO = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")


class Lanciatore(NamedTuple):
    valori: frozenset[str] = frozenset()  # opzioni che si portano dietro un valore (non è il comando)
    posizionali: int = 0  # argomenti fissi prima del comando: la durata di timeout, il file di flock
    stringa: frozenset[str] = frozenset()  # opzioni il cui valore è una riga di comando (env -S)


# Comandi che si limitano a lanciare il comando che li segue: davanti a rm non
# cambiano cosa si cancella. `command rm -rf "${D}"` è la forma di nvm.sh. Le
# opzioni sono quelle di ciascuno, non un insieme comune: `sudo -n` non ha valore e
# `nice -n` sì, e con un solo insieme `sudo -n rm .guardrail.json` prenderebbe rm
# per il valore di -n. È una lista, e una lista ha sempre un buco: copre le forme
# che si scrivono davvero. Un lanciatore che manca qui, davanti a rm, lo nasconde.
LANCIATORI: dict[str, Lanciatore] = {
    "sudo": Lanciatore(frozenset({"-u", "-g", "-U", "-C", "-D", "-R", "-T", "-p", "-r", "-t", "--user", "--group", "--chdir", "--prompt"})),
    "doas": Lanciatore(frozenset({"-u", "-C"})),
    "command": Lanciatore(),
    "builtin": Lanciatore(),
    "env": Lanciatore(frozenset({"-u", "-C", "--unset", "--chdir"}), stringa=frozenset({"-S", "--split-string"})),
    "exec": Lanciatore(frozenset({"-a"})),
    "nohup": Lanciatore(),
    "setsid": Lanciatore(),
    "time": Lanciatore(frozenset({"-f", "-o", "--format", "--output"})),
    "timeout": Lanciatore(frozenset({"-s", "-k", "--signal", "--kill-after"}), posizionali=1),
    "nice": Lanciatore(frozenset({"-n", "--adjustment"})),
    "ionice": Lanciatore(frozenset({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"})),
    "stdbuf": Lanciatore(frozenset({"-i", "-o", "-e", "--input", "--output", "--error"})),
    "flock": Lanciatore(
        frozenset({"-w", "-E", "--timeout", "--wait", "--conflict-exit-code"}), posizionali=1, stringa=frozenset({"-c", "--command"})
    ),
    "unshare": Lanciatore(frozenset({"-S", "-G", "--setuid", "--setgid", "--propagation"})),
    "xargs": Lanciatore(
        frozenset({"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--eof",
                   "--max-args", "--max-lines", "--max-procs", "--max-chars"})
    ),
    "watch": Lanciatore(frozenset({"-n", "--interval"})),
    "busybox": Lanciatore(),
    "chroot": Lanciatore(frozenset({"--userspec", "--groups"}), posizionali=1),
}
# Chi alza i privilegi: `doas qualunque` si tratta come `sudo qualunque`.
PRIVILEGIATI = frozenset({"sudo", "doas"})


class Effettivo(NamedTuple):
    nome: str  # il comando vero, senza path: `rm` per `/bin/rm`, `\rm`, `'rm'`
    parole: tuple[str, ...]  # dal comando in poi, nome com'è scritto (con il path) e argomenti
    lanciatori: tuple[str, ...]  # ciò che gli stava davanti: ("sudo", "nice")

    @property
    def args(self) -> tuple[str, ...]:
        return self.parole[1:]

    @property
    def con_privilegi(self) -> bool:
        return bool(PRIVILEGIATI.intersection(self.lanciatori))


def _command_stampa(args: tuple[str, ...] | list[str]) -> bool:
    """`command -v rm`, `-V`, `-pv`: stampa dove sta il comando, non lo lancia."""
    for a in args:
        if not a.startswith("-") or a == "--":
            return False
        if re.fullmatch(r"-[pvV]*[vV][pvV]*", a):
            return True
    return False


def _dopo_opzioni(parole: list[str], j: int, spec: Lanciatore) -> tuple[list[str], int]:
    """L'indice del comando che un lanciatore lancia: dopo le sue opzioni, i valori
    che si portano dietro e i suoi argomenti fissi. Se un'opzione porta una riga di
    comando (`env -S 'rm -rf x'`), la riga prende il posto delle opzioni."""
    corti = {v[1] for v in spec.valori if len(v) == 2}
    posizionali, opzioni, n = spec.posizionali, True, len(parole)
    while j < n:
        w = parole[j]
        if opzioni and w == "--":
            opzioni = False
            j += 1
        elif opzioni and w.startswith("-") and len(w) > 1:
            base, uguale, valore = w.partition("=")
            if base in spec.stringa:
                if not uguale:
                    valore = parole[j + 1] if j + 1 < n else ""
                    j += 1
                try:
                    riga = shlex.split(valore)
                except ValueError:
                    riga = valore.split()
                return riga + parole[j + 1:], 0
            if base in spec.valori:
                j += 1 if uguale else 2
            elif w[1] != "-" and (k := next((x for x, ch in enumerate(w[1:]) if ch in corti), None)) is not None:
                # `-nu deploy`: l'ultima lettera con un valore si prende la parola dopo;
                # se non è l'ultima, il valore è attaccato (`-n10`).
                j += 2 if k == len(w) - 2 else 1
            else:
                j += 1
        elif posizionali > 0:
            posizionali -= 1
            j += 1
        else:
            break
    return parole, min(j, n)


def comando_effettivo(parole: tuple[str, ...] | list[str]) -> Effettivo:
    """Il comando vero di una riga di parole (`Comando.parole`), con i suoi argomenti.

    Salta ciò che gli sta davanti senza essere lui: parole chiave (`then`, `do`, `{`,
    `!`), assegnamenti (`FOO="a b"`, `PATH+=x`) e lanciatori (`sudo -u deploy`,
    `nice -n 10`, `timeout 60`, `env -i -u HOME`, `flock f`…), ciascuno con le sue
    opzioni. Il nome è senza path, backslash e apici: `/bin/rm`, `\\rm` e `'rm'`
    sono rm. Chi non ha un comando (`FOO=1`, `sudo -v`) ha il nome vuoto, e i suoi
    lanciatori restano: `sudo` senza comando è comunque un `sudo`.
    """
    parole = list(parole)
    lanciatori: list[str] = []
    i = 0
    while i < len(parole):
        p = parole[i]
        if p in PAROLE_CHIAVE or ASSEGNAMENTO.match(p):
            i += 1
            continue
        nome = os.path.basename(p)
        spec = LANCIATORI.get(nome)
        if spec is None or (nome == "command" and _command_stampa(parole[i + 1:])):
            break
        lanciatori.append(nome)
        parole, i = _dopo_opzioni(parole, i + 1, spec)
    if i >= len(parole):
        return Effettivo("", (), tuple(lanciatori))
    return Effettivo(os.path.basename(parole[i]), tuple(parole[i:]), tuple(lanciatori))


@functools.lru_cache(maxsize=64)
def effettivi(testo: str) -> tuple[Effettivo, ...]:
    """Il comando vero di ogni comando di `testo`."""
    return tuple(comando_effettivo(c.parole) for c in comandi(testo))


# ---------------------------------------------------------------------------
# Bash: cancellazioni
# ---------------------------------------------------------------------------

RM_RECURSIVE_FLAG = re.compile(r"(?:^|\s)(?:-[a-zA-Z]*r[a-zA-Z]*|--recursive)(?:\s|$)")
DANGEROUS_RM_TARGET = re.compile(
    r"""^(?:["']?)(?:
        \$|\{\$|              # variabile: $HOME, $S, ${X}
        ~|                    # home
        /home/[^/\s"']+/?["']?$ |  # /home/utente
        /root/?["']?$ |
        /(?:[a-z]+/?)?["']?$ |     # /, /usr, /etc ...
        \.\.?["']?$ |         # . oppure ..
        \.\*|\.\[|\.\.\?\*|   # glob nascosti: .* .[!.]* ..?*
        \*["']?$              # * da solo
    )""",
    re.X,
)
FIND_ESEGUE = frozenset({"-exec", "-execdir", "-ok", "-okdir"})


def find_che_cancella(e: Effettivo) -> list[str] | None:
    """Le radici di un find che cancella (`-delete`, o `-exec`/`-execdir` di rm, anche
    dietro `command`, `sudo`…, o di un rsync --delete), o None se non cancella o `e`
    non è un find."""
    if e.nome != "find":
        return None
    args = list(e.args)
    k = 0
    while k < len(args) and not args[k].startswith("-") and args[k] not in ("(", "!"):
        k += 1
    radici, cancella = args[:k] or ["."], False
    while k < len(args):
        if args[k] == "-delete":
            cancella = True
        elif args[k] in FIND_ESEGUE:
            fine = k + 1
            while fine < len(args) and args[fine] not in (";", "+"):
                fine += 1
            eseguito = comando_effettivo(args[k + 1:fine])
            cancella = cancella or eseguito.nome == "rm" or (
                eseguito.nome == "rsync" and any(a.startswith("--delete") for a in eseguito.args)
            )
            k = fine
        k += 1
    return radici if cancella else None


def check_rm(cmd: str) -> None:
    for e in effettivi(cmd):
        if e.nome == "rm":
            giudica_rm(list(e.args))
        elif (radici := find_che_cancella(e)) is not None:
            for root in radici:
                if root != "." and DANGEROUS_RM_TARGET.match(root):
                    deny(f"find … -delete / -exec rm a partire da {root!r}: cancellazione ricorsiva su un bersaglio non sicuro.")
            ask(
                f"find … -delete / -exec rm a partire da {radici[0]!r}: cancella tutto ciò che il predicato seleziona. "
                "Prima lo stesso find senza -delete, mostrato all'utente. Conferma?"
            )


def giudica_rm(args: list[str]) -> None:
    recursive = RM_RECURSIVE_FLAG.search(" " + " ".join(args)) is not None
    variable_only: str | None = None
    for arg in args:
        if arg.startswith("-") or not DANGEROUS_RM_TARGET.match(arg):
            continue
        # Un rm non ricorsivo su una variabile ha raggio limitato: conferma,
        # non blocco. Tutto il resto (ricorsivo, home, radici, glob) è blocco.
        if not recursive and re.match(r"""^["']?[$\{]""", arg):
            variable_only = variable_only or arg
            continue
        deny(
            f"rm{' ricorsivo' if recursive else ''} su un bersaglio non sicuro: {arg!r}. "
            "Vietati: variabili ($HOME, $DIR...), ~, radici di sistema, '.', '..', glob nascosti (.*, .[!.]*) e '*'. "
            "Usa un path letterale e relativo al progetto, oppure chiedi all'utente di cancellare a mano. "
            "(guardrail: filesystem-shell-segreti.md)"
        )
    if variable_only:
        ask(
            f"rm su una variabile ({variable_only!r}): il bersaglio dipende dal valore al momento "
            "dell'esecuzione, e una variabile vuota o con spazi cancella altro. Stampa il path, "
            "mostralo, e usa quello letterale. Conferma?"
        )


# ---------------------------------------------------------------------------
# Bash: segreti e configurazione
# ---------------------------------------------------------------------------

# `\.env(?:\.[\w-]+)*` prende la catena *intera* dei suffissi: con un solo
# segmento `.env.azure.example` si fermerebbe a `.env.azure`, e l'esenzione
# template (ancorata in fondo) non vedrebbe mai `.example`.
# `.env` è un nome di file solo se comincia lì: in `process.env.HOME` e
# `os.environ` è un pezzo di identificatore, e leggerlo come il file `.env.HOME`
# è il falso positivo del 2026-09-28 (9 volte in una settimana). Davanti ci può
# stare l'inizio, `/`, uno spazio, una virgoletta, `=`; mai una lettera o `$`.
SECRET_FILE = re.compile(
    r"(?:[\w./~-]*/)?(?:(?<![\w$])\.env(?:rc)?(?:\.[\w-]+)*(?![A-Za-z0-9])|\.secrets|\.netrc|\.pgpass|\.my\.cnf|\.htpasswd"
    r"|\.claude\.json|\.credentials\.json|credentials\.json|\.git-credentials|\.npmrc|\.pypirc"
    r"|\.aws/credentials|\.docker/config\.json|\.kube/config|gh/hosts\.yml|\.gnupg/[^\s\"']+"
    r"|[\w.-]+\.(?:pem|key|p12|pfx)|id_(?:rsa|ed25519|ecdsa|dsa))"
)
# Comandi che stampano o trasformano il contenuto di un file: il segreto finisce
# nella trascrizione della sessione, che resta su disco.
SECRET_READERS = frozenset(
    {"cat", "bat", "tac", "less", "more", "head", "tail", "nl", "od", "xxd", "strings", "grep", "egrep",
     "fgrep", "rg", "ag", "awk", "sed", "cut", "base64", "jq", "tee"}
)
SECRET_SOURCERS = frozenset({"source", "."})
# Comandi il cui primo operando è un'espressione, non un file: in
# `grep "\.env" casi.jsonl` quel `.env` è una regex e non si legge nessun segreto.
PATTERN_COMMANDS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "perl"}
# ...a meno che il pattern arrivi da un flag: allora ogni operando è un file.
# Anche in forma composta (`sed -ne`, `grep -ve`, `awk -f`).
PATTERN_FLAGS = {"-e", "--regexp", "-f", "--file", "--expression"}
PATTERN_SHORT_FLAG = re.compile(r"-[a-zA-Z]*[ef]")

# File che governano guardrail e Claude Code: modificarli da shell è il modo di
# aggirare un blocco senza passare da Write/Edit.
PROTECTED_PATH = re.compile(
    r"(?:^|[\s/\"'=])(?P<path>\.guardrail\.json|\.claude/settings(?:\.local)?\.json|\.claude/CLAUDE\.md"
    r"|\.claude/(?P<plugin>plugins|hooks)(?:/[^\s\"']*)?|\.claude/(?:commands|skills|agents|rules)(?:/[^\s\"']*)?)",
    re.I,  # su NTFS (WSL, /mnt/c) .GUARDRAIL.JSON è lo stesso file
)
SHELL_WRITER_CMDS = frozenset(
    {"tee", "cp", "mv", "rm", "sed", "perl", "truncate", "ln", "install", "chmod", "chattr", "dd", "rsync",
     "python", "python3", "node"}
)

# Chi scrive, e *dove*. Nominare un path non è modificarlo: `ls .claude/hooks/`
# legge, `cp .claude/hooks/x /tmp/` copia *da* lì. Conta la direzione, cioè quali
# operandi sono bersaglio della scrittura:
#   all      ogni operando (rm, tee, chmod: sono tutti bersagli)
#   last     solo l'ultimo (cp, mv, ln, rsync, install: gli altri sono sorgenti)
#   inplace  solo se c'è il flag di modifica sul posto (sed -i, perl -pi)
#   of       solo l'operando of= (dd)
#   opaque   non ispezionabile da fuori (python, node): tutti, per prudenza
WRITER_TARGETS = {
    "tee": "all", "rm": "all", "rmdir": "all", "shred": "all", "truncate": "all",
    "mkdir": "all", "touch": "all", "chmod": "all", "chown": "all", "chattr": "all",
    "cp": "last", "mv": "last", "ln": "last", "rsync": "last", "install": "last",
    "sed": "inplace", "perl": "inplace",
    "dd": "of",
    "python": "opaque", "python3": "opaque", "node": "opaque",
}

IN_PLACE_FLAG = re.compile(r"^--in-place|^-[a-zA-Z]*i")
# Codice (Python, JavaScript) che scrive, cancella o sposta file. Largo di
# proposito: un falso allarme qui riporta solo al comportamento prudente di prima.
CODE_WRITES = re.compile(
    r"\b(?:write\w*|append\w*|dump\w*|save\w*|unlink\w*|rename\w*|rm\w*|remove\w*|copy\w*|cp\w*|move\w*"
    r"|symlink\w*|link\w*|mkdir\w*|makedirs|truncate\w*|chmod\w*|chown\w*|utime\w*|touch|replace|extract\w*"
    r"|urlretrieve|createWriteStream)\s*\("
    r"|\bopen\w*\s*\([^\n]*?['\"][rbt]*[wax+][rwabxt+]*['\"]"
    r"|\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\b|\bshutil\b|\bfs\.promises\b"
)
# Codice che lancia processi: lì una stringa può diventare un comando di shell
# (`os.system("rm -rf …")`, `execSync(…)`), e le regole della shell devono vederla.
# Niente `\b` davanti: `asyncio.create_subprocess_shell` e `os.execvp` contano.
# L'accesso dinamico (`getattr(os, 'sys' + 'tem')`, `__import__`, `eval`) vale
# come un lancio: da fuori non si sa cosa chiama. È comunque una lista nera, e
# protegge da un agente che sbaglia, non da uno che cerca il buco.
SPAWNS_PROCESS = re.compile(
    r"(?:subprocess|child_process|Open3|getattr|__import__|importlib|builtins|process\.binding)"
    r"|(?:system|popen|exec\w*|spawn\w*|shell_exec|passthru|proc_open|eval|Function|globals)\s*\("
)
# `node -e '…'`, `python3 -c "…"`: il codice passato come stringa, intero. La
# regex trova i candidati; che node o python siano davvero il comando lo decide
# `comando_finale`, che legge la riga con le virgolette (vedi giudica_codice_inline).
INLINE_CODE = re.compile(
    r"\b(?:node\s+(?:-[\w=-]+\s+)*?(?:-[ep]+|--eval|--print)|python[\d.]*\s+(?:-[\w=-]+\s+)*?-[a-zA-Z]*c)"
    r"""\s+(?P<code>'[^']*'|"(?:[^"\\]|\\.)*")"""
)
CODE_FLAG = re.compile(r"-[ep]+|--eval|--print|-[a-zA-Z]*c")
SHELL_PUNCTUATION = frozenset("();<>|&")


def ultimo_segmento(testo: str) -> str | None:
    """Il testo dopo l'ultimo separatore *vero*: `;`, `|`, `&`, `(`, `)` o a capo
    fuori da virgolette, escape e commenti. Nel segmento la punteggiatura citata o
    escapata (`";"`, `\\>`) diventa `_`, perché nessuno la scambi dopo per un
    operatore: shlex in modo posix toglie le virgolette, e `";"` tornerebbe `;`.

    Un `\\` fuori dalle virgolette si porta via il carattere che segue, a capo
    compreso: `bash -s \\` a capo `python3` è un comando solo, bash. Un `#` a
    inizio parola apre un commento fino a capo, e lì niente è un operatore.
    None se `testo` finisce dentro una stringa, un escape o un commento: chi
    chiede del comando finale di una riga che non si chiude non sa niente.
    """
    corrente: list[str] = []
    stato = ""  # "" fuori, "'" o '"' dentro una stringa, "#" in un commento
    i, n = 0, len(testo)
    _spesa[:] = [0, SPESA_PER_CARATTERE * n + 10_000]  # il tetto di _fine_graffe, per questo testo
    while i < n:
        c = testo[i]
        if stato == "#":
            if c == "\n":
                stato, corrente = "", []
            i += 1
            continue
        if stato == "'":
            stato = "" if c == "'" else stato
            corrente.append("_" if c in "();<>|&" else c)
            i += 1
            continue
        if c == "\\":
            if i + 1 >= n:
                return None
            if testo[i + 1] != "\n":
                seguente = testo[i + 1]
                corrente.append("\\" + ("_" if seguente in "();<>|&" else seguente))
            i += 2
            continue
        if c == "$" and testo.startswith("{", i + 1):
            # `${X:-;}`: il `;` e la `}` dentro non separano niente. Se non si riesce
            # a leggerla con certezza, chi riceve il testo resta ignoto.
            fine = _fine_graffe(testo, i)
            if fine < 0:
                return None
            corrente.append("".join("_" if ch in "();<>|&'\"`\\{}" else ch for ch in testo[i:fine + 1]))
            i = fine + 1
            continue
        if stato == '"':
            stato = "" if c == '"' else stato
            corrente.append("_" if c in "();<>|&" else c)
            i += 1
            continue
        if c in "'\"":
            stato = c
            corrente.append(c)
        elif c == "#" and (not corrente or corrente[-1] in " \t"):
            stato = "#"
        elif c in ";|&()\n":
            corrente = []
        else:
            corrente.append(c)
        i += 1
    if stato:
        return None
    return "".join(corrente)


def comando_finale(testo: str) -> tuple[str, list[str], bool] | None:
    """Il comando in corso alla fine di `testo`, letto come lo legge la shell:
    virgolette comprese, separatori (`;`, `&&`, `|`, `(`, a capo) e prefissi
    (`sudo`, `env`, `FOO=1`, `timeout 60`) esclusi. Nome, argomenti, e se ha una
    redirezione in uscita.

    None se non si sa: la fine di `testo` sta dentro una stringa, dopo un escape
    o in un commento; c'è un backtick; il segmento non ha comando. Chi riceve
    None non deve concludere niente di favorevole.
    """
    segmento = ultimo_segmento(testo)
    if segmento is None or "`" in segmento:
        return None
    lexer = shlex.shlex(segmento, punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    comando: list[str] = []
    uscita = salta = False
    for token in tokens:
        if salta:
            salta = False
            continue
        if token and set(token) <= {"<", ">"}:
            uscita = uscita or ">" in token
            salta = True
            continue
        comando.append(token)
    effettivo = comando_effettivo(comando)
    if not effettivo.nome:
        return None
    return effettivo.nome, list(effettivo.args), uscita
# Il bersaglio di una redirezione non è un argomento del comando che la contiene:
# `ls .claude/hooks 2>/dev/null` scrive su /dev/null, non sui hook. `comandi` lo
# tiene a parte, in `Comando.uscite`.


def shell_tokens(segment: str) -> list[str]:
    """Token di un segmento scritto a mano (le pipeline del SQL), tolte le redirezioni
    in uscita. Virgolette sbilanciate: best effort."""
    cleaned = re.sub(r"(?:^|\s)\d*>>?\s*[^\s;&|<>()]+", " ", segment)
    try:
        return shlex.split(cleaned)
    except ValueError:
        return cleaned.split()


def write_targets(comando: Comando) -> list[str]:
    """Gli operandi su cui il comando *scrive*. Un comando di lettura non ne ha."""
    targets = list(comando.uscite)
    e = comando_effettivo(comando.parole)
    mode = WRITER_TARGETS.get(e.nome)
    if mode is None:
        return targets
    args = list(e.args)
    flags = [a for a in args if a.startswith("-")]
    operands = [a for a in args if not a.startswith("-")]
    if mode == "of":
        return targets + [a.split("=", 1)[1] for a in args if a.startswith("of=")]
    if mode == "inplace" and not any(IN_PLACE_FLAG.match(f) for f in flags):
        return targets
    if mode == "last" and not any(f in ("-t", "--target-directory") for f in flags):
        operands = operands[-1:]
    return targets + operands


def secret_names(values: list[str]) -> list[str]:
    """I nomi di file di segreti fra `values`, esclusi i template (.env.example)."""
    return [
        m.group(0)
        for value in values
        for m in SECRET_FILE.finditer(value)
        if not SECRET_TEMPLATE.search(m.group(0))
    ]


def file_operands(comando: Comando) -> list[str]:
    """Gli operandi che il comando tratta come file, senza il pattern di grep/sed/awk.
    Un file in ingresso (`cat < .env`) è un operando."""
    e = comando_effettivo(comando.parole)
    args = e.args
    if e.nome not in PATTERN_COMMANDS:
        return [a for a in args if not a.startswith("-")] + list(comando.entrate)
    operands: list[str] = []
    pattern_da_flag = salta = False
    for arg in args:
        if salta:
            salta = False
            continue
        if not arg.startswith("-"):
            operands.append(arg)
        elif arg.split("=", 1)[0] in PATTERN_FLAGS or PATTERN_SHORT_FLAG.fullmatch(arg):
            pattern_da_flag = True
            # Il valore di -e è il pattern (`sed -e "s/x/os.environ['A']/"`): non è un
            # file. Quello di -f sì, e si legge.
            salta = "=" not in arg and (arg in ("--regexp", "--expression") or (arg[1] != "-" and arg.endswith("e")))
    return (operands if pattern_da_flag else operands[1:]) + list(comando.entrate)


def check_secret_reads(text: str) -> None:
    """Blocca `cat .env` e affini: permissions.deny copre il tool Read, non la shell."""
    for comando in comandi(text):
        e = comando_effettivo(comando.parole)
        found = secret_names(file_operands(comando))
        written = secret_names(list(comando.uscite))
        if not found and not written:
            continue
        if found and e.nome in SECRET_READERS:
            deny(
                f"lettura di un file di segreti da shell ({found[0]}): il contenuto finirebbe "
                "nella trascrizione, che resta su disco. Per il nome di una variabile leggi "
                ".env.example; per il valore, chiedilo all'utente. (guardrail: filesystem-shell-segreti.md)"
            )
        if found and e.nome in SECRET_SOURCERS:
            ask(
                f"source di un file di segreti ({found[0]}): carica credenziali nell'ambiente "
                "del comando. Conferma che è voluto?"
            )
        # cp/mv/ln restano presi in *entrambe* le direzioni: `cp .env x && cat x`
        # ricicla il nome. Le redirezioni no: contano solo se scrivono sul segreto.
        if written or (found and e.nome in SHELL_WRITER_CMDS):
            name = (written + found)[0]
            ask(f"scrittura da shell su un file di segreti ({name}). Conferma che è voluto e che il file è gitignorato.")


def removed_paths(comando: Comando) -> list[str]:
    """I file che il comando toglie dal loro posto: rm e unlink, la sorgente di mv, git rm/mv."""
    e = comando_effettivo(comando.parole)
    command, args = e.nome, list(e.args)
    if command == "git":
        while args and args[0].startswith("-"):
            args = args[2:] if args[0] in ("-C", "-c") else args[1:]
        if not args:
            return []
        command, args = args[0], args[1:]
    operands = [a for a in args if not a.startswith("-")]
    if command in ("rm", "unlink", "shred"):
        return operands
    if command == "mv":
        return operands if any(a in ("-t", "--target-directory") for a in args) else operands[:-1]
    return []


SPEGNE_GUARDRAIL = "è il file che accende guardrail nel suo progetto"


def nome_guardrail(nome: str) -> bool:
    """`nome` indica .guardrail.json, anche come glob (`.guardrail*`, `.[!.]*`) o con
    maiuscole diverse. Come in bash, un glob che non comincia con il punto non
    prende i file nascosti: `rm *.json` non lo tocca."""
    nome = nome.lower()
    return nome.startswith(".") and fnmatch.fnmatchcase(".guardrail.json", nome)


def percorso(raw: str, cwd: str) -> Path:
    path = Path(os.path.expanduser(raw.strip("\"'")))
    return path if path.is_absolute() else Path(cwd or os.getcwd()) / path


def contiene_guardrail(base: Path, profondita: int = 2) -> bool:
    """`base` è una directory con un .guardrail.json, fino a `profondita` livelli sotto?"""
    try:
        if base.is_symlink() or not base.is_dir():
            return False
        if os.path.lexists(base / ".guardrail.json"):
            return True
        if profondita == 0:
            return False
        with os.scandir(base) as voci:
            for indice, voce in enumerate(voci):
                if indice > 500:
                    break
                if voce.name in ("node_modules", "vendor", ".git", ".venv", "venv"):
                    continue
                if voce.is_dir(follow_symlinks=False) and contiene_guardrail(Path(voce.path), profondita - 1):
                    return True
    except OSError:
        return False
    return False


def operando_vuoto(raw: str) -> bool:
    """Un operando che, tolte virgolette e backslash, non nomina niente.

    È il resto di una riga spezzata male: in `rm -f "${D}/v*" "$(f)/x"` (nvm.sh)
    dividere su `$(` lascia un `"` orfano, che come path è la directory di lavoro.
    Così `source ~/.nvm/nvm.sh` era negato come se cancellasse il progetto.
    """
    return not raw.strip("\"'\\ \t")


def radici_temporanee() -> list[Path]:
    """Le cartelle temporanee di sistema e della sessione. Mai `/`: con TMPDIR=/
    tutto sarebbe una copia. La home la esclude `copia_temporanea`."""
    candidati = [Path("/tmp"), Path("/var/tmp"), Path(tempfile.gettempdir())]
    candidati += [Path(os.environ[k]) for k in ("TMPDIR", "TMP", "TEMP") if os.environ.get(k)]
    radici: list[Path] = []
    for candidato in candidati:
        try:
            reale = candidato.resolve()
        except (OSError, RuntimeError):
            continue
        if reale != Path(reale.anchor) and reale not in radici:
            radici.append(reale)
    return radici


def copia_temporanea(cartella: Path, cwd: str) -> bool:
    """`cartella` è una copia in una cartella temporanea che questa sessione non usa?

    Una copia del progetto in /tmp (`git checkout-index`, `git archive`, `cp -r`)
    si porta dietro il suo .guardrail.json e il suo .claude/, che però non accendono
    né configurano niente: toglierli o riscriverli non spegne guardrail. Lo
    spegnerebbe solo se la directory di lavoro o il progetto della sessione ci
    stessero dentro, e lì il controllo resta. La home non è mai una copia, anche se
    sta sotto /tmp (i test ne creano una finta). Falso positivo del 2026-10-04:
    `rm -rf /tmp/claude-1000/tmp.X` negato per la copia che conteneva.
    """
    try:
        reale = cartella.resolve()
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return False
    if is_inside(reale, home):
        return False
    if not any(reale != radice and is_inside(reale, radice) for radice in radici_temporanee()):
        return False
    sessione = [cwd or os.getcwd(), os.environ.get("CLAUDE_PROJECT_DIR", "")]
    return not any(dove and is_inside(Path(dove), reale) for dove in sessione)


def cartella_governata(path: Path) -> Path:
    """La cartella su cui agisce un file di configurazione: quella che contiene il
    .guardrail.json, o il progetto che contiene il .claude/ (vale il più interno)."""
    parti = path.parts
    if ".claude" in parti[:-1]:
        return Path(*parti[: len(parti) - 1 - parti[::-1].index(".claude")])
    return path.parent


def link_al_guardrail(comando: Comando) -> bool:
    """`ln` o `cp -l/-s` con .guardrail.json fra gli operandi: un secondo nome per il file."""
    e = comando_effettivo(comando.parole)
    command, args = e.nome, e.args
    collega = command == "ln" or (
        command == "cp" and any(a in ("-l", "-s", "--link", "--symbolic-link") or re.match(r"^-[a-zA-Z]*[ls]", a) for a in args)
    )
    return collega and any(nome_guardrail(Path(a).name) for a in args if not a.startswith("-"))


def modifica_protetta(match: re.Match) -> None:
    path = match.group("path")
    if match.group("plugin"):
        deny(
            f"modifica da shell di {path}: è il codice dei hook e dei plugin di Claude Code, "
            "cioè di guardrail stesso. Si aggiorna con /plugin, mai a mano dall'agente. (guardrail: RULES-CORE.md 8)"
        )
    ask(
        f"modifica da shell di {path}: cambia le regole che vincolano l'agente o le impostazioni "
        "dell'utente. Decide l'utente. (guardrail: RULES-CORE.md 8)"
    )


def giudica_codice_inline(text: str) -> str:
    """Il codice di `node -e` e `python3 -c` si giudica intero, e poi si toglie.

    Un path letto dentro `require(…)` sembrerebbe un operando di node, cioè un
    bersaglio. È il falso positivo del 2026-10-04 su
    `.claude/plugins/known_marketplaces.json`. Se il codice scrive o lancia
    processi, i path protetti che nomina sono bersagli; se no, non ne ha.

    Resta nella riga solo fra virgolette doppie con dentro `$(` o un backtick: quelli
    li esegue la shell, prima di passare il testo all'interprete. E resta se node o
    python non sono davvero il comando, letto con le virgolette: in
    `tee "; python3 -c '" .guardrail.json "'"` il comando è tee, e scrive su
    .guardrail.json.
    """

    def giudica(m: re.Match) -> str:
        codice = m.group("code")
        if codice.startswith('"') and ("$(" in codice or "`" in codice):
            return m.group(0)
        comando = comando_finale(m.string[: m.start("code")])
        if (
            comando is None
            or not re.fullmatch(r"node|python[\d.]*", comando[0])
            or not comando[1]
            or not CODE_FLAG.fullmatch(comando[1][-1])
            or m.string[m.end():m.end() + 1] not in ("", " ", "\t", "\n", ";", "&", "|", ")")
        ):
            return m.group(0)
        if CODE_WRITES.search(codice) or SPAWNS_PROCESS.search(codice):
            for match in PROTECTED_PATH.finditer(codice):
                modifica_protetta(match)
        return m.group(0)[: m.start("code") - m.start()] + "''"

    return INLINE_CODE.sub(giudica, text)


def check_protected_writes(text: str, cwd: str = "") -> None:
    text = giudica_codice_inline(text)
    for comando in comandi(text):
        tolto = None
        for raw in removed_paths(comando):
            if operando_vuoto(raw):
                continue
            if nome_guardrail(Path(raw).name):
                if not copia_temporanea(percorso(raw, cwd).parent, cwd):
                    tolto = raw
            elif not any(c in raw for c in "*?[") and contiene_guardrail(percorso(raw, cwd)):
                if not copia_temporanea(percorso(raw, cwd), cwd):
                    tolto = f"{raw}, che contiene un .guardrail.json"
            if tolto:
                break
        if (
            tolto is None
            and "guardrail" in comando.testo.lower()
            and find_che_cancella(comando_effettivo(comando.parole)) is not None
        ):
            tolto = "un .guardrail.json (find … -delete)"
        if tolto:
            deny(
                f"rimozione di {tolto}: {SPEGNE_GUARDRAIL}, toglierlo lo spegne. Spegnerlo è una "
                "decisione dell'utente, che lo fa da sé. Se una regola ti blocca a torto, spiegalo "
                "all'utente. (guardrail: RULES-CORE.md 8)"
            )
        if link_al_guardrail(comando):
            deny(
                "un link a .guardrail.json gli darebbe un secondo nome, da cui riscriverlo senza passare "
                "dalla conferma. Se serve una copia, usa cp senza -l/-s. (guardrail: RULES-CORE.md 8)"
            )
        for target in write_targets(comando):
            if operando_vuoto(target):
                continue
            # Anche dove porta: `note.json` può essere un link a .guardrail.json.
            try:
                reale = percorso(target, cwd).resolve()
            except (OSError, RuntimeError):
                reale = None
            match = PROTECTED_PATH.search(target)
            if not match and cwd and reale is not None:
                match = PROTECTED_PATH.search(str(reale))
            if not match:
                continue
            # Il nome e dove porta, tutti e due: un link in /tmp può portare al progetto,
            # e il .guardrail.json di un progetto può essere un link verso /tmp.
            if reale is not None and all(
                copia_temporanea(cartella_governata(p), cwd) for p in (percorso(target, cwd), reale)
            ):
                continue
            modifica_protetta(match)


# ---------------------------------------------------------------------------
# Bash: heredoc e script invocati
# ---------------------------------------------------------------------------

# Un heredoc che scrive su file (cat > x <<EOF, tee x <<EOF) contiene dati, non
# comandi: citare `git push --force` in un README non è eseguirlo. Un heredoc che
# alimenta un interprete (bash <<EOF, python - <<PY) resta comandi e non si tocca.
# Testa di un heredoc che *archivia* il corpo invece di eseguirlo. Due forme:
#   redirezione o tee     `cat > docs/git.md <<EOF`
#   git/gh che legge -    `git commit -F - <<EOF`, `gh issue create --body-file - <<EOF`
# git e gh con `-F -` prendono lo stdin come testo da archiviare, mai da eseguire:
# un messaggio di commit che *descrive* un comando bloccato non lo esegue, ed è la
# forma normale in cui questo repo documenta i propri blocchi. `bash <<EOF` resta
# fuori, e il suo corpo continua a essere analizzato. La riga di testa e tutto ciò
# che segue il tag di chiusura restano comunque analizzati, in ogni caso.
#
# *Chi* riceve l'heredoc si decide come lo decide la shell: la riga fino a `<<`
# si legge con le virgolette (shlex), e conta il primo comando del segmento che
# contiene `<<`, tolti i prefissi. Una regex sulla riga non basta: in
# `bash -s "; python3 x" <<'EOF'` il `;` sta dentro una stringa, e il corpo lo
# esegue bash. Se la riga non si legge (virgolette spaiate, `<<` dentro una
# stringa, `<<<`), il corpo resta analizzato. Un `(` o un backtick prima di `<<`
# apre un altro comando (`tee >(bash) <<EOF`, `python3 $(bash <<EOF …)`): lì chi
# riceve non si sa, e il corpo resta analizzato.
#
# Un heredoc di dati è tale solo se nessuno riesegue ciò che scrive: `cat > x <<EOF
# | bash` e `tee x <<EOF | bash` passano il corpo a una shell. E con il tag senza
# virgolette `$(…)` e i backtick nel corpo li esegue la shell, prima di tutto.
HEREDOC = re.compile(
    r"(?P<head>^(?P<prima>[^\n]*?)(?<!<)<<(?!<)-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)(?P<dopo>[^\n]*)\n)"
    r"(?P<body>.*?)(?P<end>^\s*(?P=tag)\s*$)",
    re.M | re.S,
)
GIT_STDIN_FLAGS = ("-F", "--file", "--body-file", "--notes-file")


def riscrivi_heredoc(text: str, da_tagliare) -> str:
    """Toglie il corpo degli heredoc per cui `da_tagliare(m, ricevente)` è vero.

    Il ricevente si legge dal comando *intero* fino a `<<`, non dalla sola riga:
    una riga che sembra `python3 - <<EOF` può stare dentro una stringa aperta più
    su (`X='` a capo), e allora non è un heredoc e il testo che segue lo esegue la
    shell. I corpi degli heredoc già incontrati non contano per le virgolette: la
    shell non li interpreta, e un apostrofo dentro un testo non apre niente.
    Se il ricevente non si sa, il corpo resta.
    """
    pezzi: list[str] = []
    struttura: list[str] = []
    pos = 0
    for m in HEREDOC.finditer(text):
        fuori = text[pos:m.start()]
        pezzi.append(fuori)
        struttura.append(fuori)
        ricevente = comando_finale("".join(struttura) + m.group("prima"))
        taglia = ricevente is not None and da_tagliare(m, ricevente)
        pezzi.append(m.group("head") + m.group("end") if taglia else m.group(0))
        struttura.append(m.group("head") + m.group("end") if ricevente is not None else m.group(0))
        pos = m.end()
    pezzi.append(text[pos:])
    return "".join(pezzi)


def heredoc_di_dati(m: re.Match, ricevente: tuple[str, list[str], bool]) -> bool:
    """`cat > x <<EOF`, `tee x <<EOF`, `git commit -F - <<EOF`: il corpo si archivia."""
    if "|" in m.group("dopo"):
        return False
    if not m.group("q") and ("$(" in m.group("body") or "`" in m.group("body")):
        return False
    nome, args, uscita = ricevente
    if nome == "cat":
        return uscita
    if nome == "tee":
        return True
    if nome in ("git", "gh"):
        return any(
            (a in GIT_STDIN_FLAGS and i + 1 < len(args) and args[i + 1] == "-") or a in {f"{f}=-" for f in GIT_STDIN_FLAGS}
            for i, a in enumerate(args)
        )
    return False

# Heredoc che alimenta un interprete NON-shell: `python3 - <<PY`, `node <<JS`.
# Il corpo sono comandi — per quell'interprete, non per la shell.
#
# Le regole built-in lo vedono solo se quel codice può arrivare alla shell: se
# lancia processi (`os.system("rm -rf ...")`, `subprocess`, `child_process`), se
# l'interprete è Ruby, Perl o PHP (lì `system "…"` e i backtick eseguono senza
# parentesi), o se il tag non è fra virgolette e il corpo contiene `$(` o un
# backtick, che la shell esegue *prima* di passare il testo all'interprete.
# Altrimenti un testo citato in un letterale Python non è un comando: uno script
# che corregge un README con dentro `find . -delete` o `base64 -d x | sh` veniva
# fermato come se li eseguisse. Falso positivo del 2026-10-03/04.
#
# Le regex di PROGETTO tagliano invece sempre il corpo.
# Sono stringhe arbitrarie (un path, un flag) scritte per intercettare un comando
# della shell: incontrate dentro un letterale Python descrivono, non eseguono.
# Il 2026-09-18 `ask_commands: ["scripts/clone-prod-to-dev\\.sh"]` ha fatto
# scattare la conferma su uno script che quel path lo stampava soltanto, e la
# gemella in `deny_commands` ha bloccato lo script che stava diagnosticando il
# guard — lo stesso falso positivo del 2026-09-17, spostato dalle regole built-in
# a quelle di progetto.
#
# `bash`/`sh`/`zsh` restano fuori: lì il corpo è shell per davvero, e le regex di
# progetto devono vederlo.
INTERPRETERS = re.compile(r"python[\d.]*|node|ruby|perl|php|Rscript")
INTERPRETERS_WITHOUT_SHELL = re.compile(r"python[\d.]*|node|Rscript")


# Chi legge un file e lo esegue come script. Il nome è quello del comando vero
# (`comando_effettivo`): `nohup bash x.sh`, `timeout 60 python3 x.py`, `/bin/bash x.sh`.
SCRIPT_INTERPRETER = re.compile(r"(?:ba|z|da|k)?sh|python3?|node|php|perl|ruby")
SHELL_INTERPRETER = re.compile(r"(?:ba|z|da|k)?sh")
SCRIPT_SORGENTI = frozenset({"source", "."})


def strip_data_heredocs(text: str) -> str:
    return riscrivi_heredoc(text, heredoc_di_dati)


def strip_interpreter_heredocs(text: str) -> str:
    """Il testo su cui si applicano le REGEX DI PROGETTO, e solo quelle.

    Toglie il corpo degli heredoc diretti a un interprete non-shell. La riga di
    testa resta: `python3 - <<PY` continua a essere un comando, e se la testa
    contiene il pattern cercato la regola scatta come prima.

    Per le regole built-in c'è `strip_inert_heredocs`, che taglia di meno.
    """
    return riscrivi_heredoc(text, lambda m, ricevente: INTERPRETERS.fullmatch(ricevente[0]) is not None)


def strip_inert_heredocs(text: str) -> str:
    """Il testo per le regole BUILT-IN: senza i corpi degli heredoc che non possono
    arrivare alla shell (vedi il commento su HEREDOC)."""

    def inerte(m: re.Match, ricevente: tuple[str, list[str], bool]) -> bool:
        corpo = m.group("body")
        return (
            INTERPRETERS_WITHOUT_SHELL.fullmatch(ricevente[0]) is not None
            and not SPAWNS_PROCESS.search(corpo)
            and (bool(m.group("q")) or ("$(" not in corpo and "`" not in corpo))
        )

    return riscrivi_heredoc(text, inerte)


def solo_sintassi(nome: str, flags: list[str]) -> bool:
    """`bash -n script.sh`: la shell legge lo script e ne controlla la sintassi,
    senza eseguirne niente. Scansionarlo come se partisse fermava proprio il
    controllo che si fa prima di lanciarlo (falso positivo del 2026-10-03/04).
    Con -i la shell è interattiva e -n non vale più."""
    if not SHELL_INTERPRETER.fullmatch(nome):
        return False
    lettere = "".join(f[1:] for f in flags if re.fullmatch(r"-[a-zA-Z]+", f))
    return "n" in lettere and "i" not in lettere


def script_nominato(e: Effettivo) -> str | None:
    """Il file che il comando vero esegue come script, o None.

    Tre forme: `./x.sh` (un path relativo alla cartella o alla home come comando),
    `bash x.sh` / `python3 x.py` (un interprete e il suo primo argomento che non è
    un'opzione), `source x.sh` / `. x.sh`."""
    if not e.nome:
        return None
    if e.nome in SCRIPT_SORGENTI:
        return e.args[0] if e.args else None
    if e.parole[0].startswith(("./", "../", "~/")):
        return e.parole[0]
    if not SCRIPT_INTERPRETER.fullmatch(e.nome):
        return None
    # Le opzioni prima del file; il file è il primo argomento che non lo è. Con
    # `bash -c "./x.sh"` quell'argomento è la stringa, che se è un path si legge.
    prima = list(itertools.takewhile(lambda a: a.startswith("-"), e.args))
    operandi = e.args[len(prima):]
    if not operandi or solo_sintassi(e.nome, prima):
        return None
    return operandi[0]


def invoked_scripts(text: str, cwd: str) -> list[Path]:
    found: list[Path] = []
    for e in effettivi(text):
        raw = script_nominato(e)
        if raw is None or "$" in raw:
            continue
        path = Path(os.path.expanduser(raw))
        if not path.is_absolute():
            path = Path(cwd or os.getcwd()) / path
        try:
            if path.is_file() and path.stat().st_size <= SCRIPT_MAX_BYTES and path not in found:
                found.append(path)
        except OSError:
            continue
    return found


def script_approvato(path: Path, content: str, config: dict) -> str:
    """Lo script è in `allow_scripts` di `.guardrail.json`?

    Quattro risposte: "si" (path e impronta corrispondono), "cambiato" (il path è
    stato approvato, ma il contenuto non è più quello), "senza-impronta" (la voce
    non dichiara un sha256, quindi non approva niente), "no".

    L'approvazione è legata al **contenuto**, non al nome: uno script approvato
    oggi e modificato domani torna a chiedere conferma. È la differenza fra
    «questo script l'ho letto» e «di questo file mi fido per sempre», e il
    2026-09-11 è nato da uno script di deploy che nessuno aveva riletto.
    """
    impronta = hashlib.sha256(content.encode("utf-8")).hexdigest()
    esito = "no"
    for voce in config["allow_scripts"]:
        if isinstance(voce, str):
            voce = {"path": voce}
        if not isinstance(voce, dict) or not voce.get("path"):
            continue
        if matches_any([str(voce["path"])], str(path)) is None:
            continue
        dichiarata = str(voce.get("sha256", "")).lower()
        # Senza impronta non si esenta niente: dichiararla è il modo di dire
        # "ho letto *questo* contenuto".
        if not dichiarata:
            esito = "senza-impronta"
            continue
        if dichiarata == impronta:
            return "si"
        esito = "cambiato"
    return esito


def check_scripts(text: str, config: dict, cwd: str) -> None:
    """Uno script lanciato è un comando che il hook altrimenti non vedrebbe."""
    for path in invoked_scripts(text, cwd):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        approvazione = script_approvato(path, content, config)
        try:
            check_bash(content, config, cwd, depth=1)
        except Decision as found:
            # `deny_commands` non si esenta: è la lista "questo non si lancia
            # mai", e vale anche dentro uno script approvato. Lo stesso per la
            # rimozione di .guardrail.json: uno script non spegne guardrail.
            if found.reason.startswith("comando vietato dalla configurazione") or SPEGNE_GUARDRAIL in found.reason:
                deny(f"lo script {path.name} contiene un comando vietato: {found.reason}")
            if approvazione == "si":
                continue
            avviso = ""
            if approvazione == "cambiato":
                avviso = (
                    f" ATTENZIONE: {path.name} è in allow_scripts, ma il suo contenuto non è più quello "
                    "approvato — l'impronta in .guardrail.json non corrisponde."
                )
            elif approvazione == "senza-impronta":
                avviso = (
                    f" Nota: la voce di allow_scripts per {path.name} non dichiara sha256, quindi non "
                    "esenta niente. Aggiungi l'impronta dello script che hai letto."
                )
            ask(
                f"lo script {path.name} contiene un comando che guardrail bloccherebbe se lanciato "
                f"direttamente — {found.reason} Leggilo, mostralo all'utente, e decida lui.{avviso}"
            )


# ---------------------------------------------------------------------------
# Bash: la funzione principale
# ---------------------------------------------------------------------------

# Interpreti di shell che accettano il codice come *stringa*. `python`, `node` e
# simili restano fuori: il loro argomento non è shell, e indovinarne il senso
# sarebbe peggio che dichiarare il limite.
SHELL_INTERPRETERS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash"})
# Opzioni di ssh che si portano dietro un valore: quel valore non è il comando.
SSH_VALUE_FLAGS = frozenset({"-o", "-p", "-i", "-l", "-F", "-b", "-c", "-D", "-E", "-e", "-I",
                             "-J", "-L", "-m", "-O", "-Q", "-R", "-S", "-W", "-w"})
MAX_DEPTH = 4


def inline_shell_payloads(text: str) -> list[str]:
    """Il codice passato a una shell come stringa: `bash -c "…"`, `sh -c '…'`,
    `eval …`, `ssh host "…"`.

    Il primo token di quella stringa **è** posizione di comando, ed è l'unico
    posto in cui le regole ancorate alla posizione (rm, find -delete, sudo, i CLI
    dei database) non guardavano. La ricorsione parte solo se l'interprete è
    davvero invocato: in `grep -n "bash -c \\"rm -rf\\""` il comando è `grep`, e
    non succede niente — la difesa dal falso positivo del 2026-09-17 resta.
    """
    payloads: list[str] = []
    for e in effettivi(text):
        args = list(e.args)
        # `bash -c "…"`, anche con flag composti (`-lc`, `-ec`).
        if e.nome in SHELL_INTERPRETERS:
            for indice, flag in enumerate(args):
                if flag.startswith("-") and not flag.startswith("--") and "c" in flag:
                    if indice + 1 < len(args):
                        payloads.append(args[indice + 1])
                    break
                if not flag.startswith("-"):
                    break  # è il path di uno script: se ne occupa check_scripts
        # `eval rm -rf "$X"`: tutto quello che segue è codice.
        elif e.nome == "eval":
            if args:
                payloads.append(" ".join(args))
        # `ssh [opzioni] host "…"`: il comando remoto è tutto ciò che segue l'host.
        elif e.nome == "ssh":
            indice = 0
            while indice < len(args) and args[indice].startswith("-"):
                indice += 2 if args[indice] in SSH_VALUE_FLAGS else 1
            resto = args[indice + 1:]
            if resto:
                payloads.append(" ".join(resto))
    return payloads


def check_inline_shell(text: str, config: dict, cwd: str, depth: int) -> None:
    """Analizza il codice passato a una shell come stringa, con le stesse regole.

    A differenza di uno script del repo, qui non si declassa il `deny` a `ask`:
    lo script lo ha scritto un umano e l'umano decide, questa stringa l'ha
    scritta chi ha scritto il comando, un istante fa.
    """
    if depth >= MAX_DEPTH:
        return
    for payload in inline_shell_payloads(text):
        try:
            check_bash(payload, config, cwd, depth + 1)
        except Decision as trovato:
            raise Decision(
                trovato.verdict,
                f"dentro una stringa passata a una shell ({payload[:70]!r}): {trovato.reason}",
            ) from None


def check_bash(cmd: str, config: dict, cwd: str = "", depth: int = 0) -> None:
    text = strip_data_heredocs(re.sub(r"\\\n", " ", cmd))
    # Le regex di progetto guardano il testo senza i corpi degli heredoc diretti a
    # un interprete: là dentro un path è citato, non eseguito. Le regole built-in
    # li perdono solo se quel codice non può arrivare alla shell.
    testo_progetto = strip_interpreter_heredocs(text)
    text = strip_inert_heredocs(text)

    if depth == 0 and matches_any(config["allow_commands"], testo_progetto):
        return

    if (pattern := matches_any(config["deny_commands"], testo_progetto)):
        deny(f"comando vietato dalla configurazione del progetto (.guardrail.json, regola {pattern!r}).")

    check_inline_shell(text, config, cwd, depth)
    check_rm(text)
    check_secret_reads(text)
    check_protected_writes(text, cwd)

    # Distruzione di sistema o supply chain
    if any(e.nome == "rm" and e.con_privilegi for e in effettivi(text)):
        deny("sudo/doas rm: cancellazioni con privilegi non passano dall'agente.")
    if re.search(r"\b(mkfs(\.\w+)?|dd\s+[^|;]*of=/dev/|wsl(\.exe)?\s+--unregister)\b", text):
        deny("comando che distrugge un filesystem o una distro.")
    if re.search(r"\bchmod\s+(-R\s+)?[0-7]*777\b", text):
        deny("chmod 777: permessi aperti a tutti, mai.")
    if re.search(r"\b(chmod|chown|chgrp)\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+|--recursive\s+)[^;|]*\s(?:~|\$HOME|/home/[\w.-]+|/)/?(?:\s|$)", text):
        deny("chmod/chown ricorsivo sulla home o sulla radice: rende inutilizzabile l'ambiente dell'utente.")
    if re.search(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", text):
        deny("curl|sh: esecuzione di codice scaricato al volo. Scarica il file, leggilo, poi esegui.")
    if re.search(r"\b(base64|openssl|echo|printf|xxd)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", text):
        deny("codice decodificato o costruito al volo e passato a sh: illeggibile per chi controlla. Scrivilo in un file, poi esegui.")

    # Le regole che seguono sono regex sul testo: valgono solo se il programma
    # compare come parola, non dentro il pattern di un grep. `mirror` è un comando
    # di lftp e vive dentro la stringa di `-e`: conta la parola lftp.
    words = shell_words(text)

    # Deploy con cancellazione sul bersaglio
    if "lftp" in words and re.search(r"\bmirror\b[^;|]*--delete\b", text) and not re.search(r"\bmirror\b[^;|]*--dry-run\b", text):
        deny("lftp mirror --delete senza --dry-run: cancella sul server remoto tutto ciò che manca in locale. (guardrail: deploy-infrastruttura.md)")
    if rsync_che_cancella(text):
        deny("rsync --delete senza --dry-run / -n: cancella sul bersaglio. Prima il dry-run, poi l'utente decide.")

    # Git
    if "git" in words:
        if re.search(r"\bgit\b[^;|]*\bpush\b[^;|]*(\s--force(?!-with-lease)\b|\s-f\b|\s\+\S+)", text):
            deny("git push --force: riscrive la storia condivisa. Mai. Se serve, --force-with-lease su un branch personale, con conferma.")
        if re.search(r"\bgit\b[^;|]*\bpush\b[^;|]*--force-with-lease", text):
            ask("git push --force-with-lease: accettabile solo su un branch personale. Conferma?")
        if re.search(r"\bgit\b[^;|]*\bpush\b[^;|]*(\s--delete\b|\s-d\b|\s:\S)", text):
            ask("git push --delete: cancella un branch o un tag sul remoto, per tutti. Conferma?")
        if re.search(r"\bgit\b[^;|]*\bclean\b[^;|]*\s-[a-zA-Z]*[xX]", text):
            deny("git clean -x/-X: cancella anche i file ignorati, cioè .env e le credenziali locali.")
        if re.search(r"\bgit\b[^;|]*\bclean\b[^;|]*\s-[a-zA-Z]*f", text):
            ask("git clean -f: cancella file non tracciati, non recuperabili. Conferma?")
        if re.search(r"\bgit\b[^;|]*\breset\s+--hard\b", text):
            ask("git reset --hard: scarta modifiche non committate. Conferma?")
        if re.search(r"\bgit\b[^;|]*\b(checkout|restore)\s+(--\s+)?\.(\s|$)", text):
            ask("git checkout/restore .: scarta tutte le modifiche locali. Conferma?")
        if re.search(r"\bgit\b[^;|]*\bbranch\b[^;|]*\s-D\b", text):
            ask("git branch -D: cancella un branch anche se non è stato mergiato. Conferma?")
        if re.search(r"\bgit\b[^;|]*\bstash\s+(drop|clear)\b", text):
            ask("git stash drop/clear: lavoro accantonato che sparisce. Conferma?")

    # Laravel: comandi che distruggono lo schema
    if re.search(r"\bartisan\s+(migrate:fresh|db:wipe|migrate:reset)\b", text):
        deny("artisan migrate:fresh / db:wipe / migrate:reset: droppano le tabelle, comprese quelle che le migration non ricreano. Solo a mano, su un DB usa e getta. (guardrail: database.md)")
    if re.search(r"\bartisan\s+migrate:rollback\b", text):
        ask("artisan migrate:rollback: annulla migration già applicate. Su quale DB? Conferma.")
    if re.search(r"\bartisan\s+db:seed\b[^;|]*RolePermissionSeeder", text):
        ask("RolePermissionSeeder sovrascrive le assegnazioni manuali di ruoli e permessi. Conferma che NON è un DB con dati reali.")

    # Docker: volumi = database; la home montata in un container = nessuna regola
    if re.search(r"\bdocker\s+(system\s+prune|volume\s+(rm|prune)|compose\s+down\b[^;|]*(-v\b|--volumes))", text):
        ask("Docker: questa operazione cancella volumi, cioè database locali. Conferma?")
    if re.search(r"\bdocker\b[^;|]*\s(?:-v|--volume)[\s=]+[\"']?(?:~|\$HOME|/home/[\w.-]+|/)/?:", text) or re.search(
        r"\bdocker\b[^;|]*--mount[^;|]*\bsource=[\"']?(?:~|\$HOME|/home/[\w.-]+|/)/?[,\"'\s]", text
    ):
        ask("docker con la home o la radice montate nel container: da dentro, nessuna regola vale più. Monta una directory del progetto. Conferma?")

    # SQL da riga di comando
    check_sql_cli(text, config)

    # Script invocati: si leggono e si scansionano con le stesse regole
    if depth == 0:
        check_scripts(text, config, cwd)

    # Privilegi: mai in silenzio
    if any(e.con_privilegi for e in effettivi(text)):
        ask("sudo/doas: un comando con privilegi. Cosa fa, e perché serve root? Conferma.")

    if (pattern := matches_any(config["ask_commands"], testo_progetto)):
        ask(f"comando che richiede conferma per la configurazione del progetto (regola {pattern!r}).")


RSYNC = re.compile(r"(?:[\w./~-]*/)?rsync")
DRY_RUN_SHORT = re.compile(r"-[a-zA-Z]*n[a-zA-Z]*")


def rsync_che_cancella(text: str) -> bool:
    """rsync *eseguito* con --delete e senza dry-run.

    `--delete` conta solo come opzione di un rsync dello stesso segmento, token per
    token: in `sed -i 's/rsync -a --delete-after /rsync -a /' x; grep rsync x`
    rsync è una parola del comando e --delete compare nel testo, ma tutti e due
    stanno dentro il pattern di sed, che il --delete lo stava togliendo. Falso
    positivo del 2026-10-03. `timeout 60 rsync …` e `find … -exec rsync …` restano
    presi: rsync è un token del segmento anche se non è il primo.
    """
    for comando in comandi(text):
        tokens = comando.parole
        for indice, token in enumerate(tokens):
            if not RSYNC.fullmatch(token):
                continue
            opzioni = tokens[indice + 1:]
            cancella = any(o.startswith("--delete") or o == "--del" for o in opzioni)
            prova = any(o == "--dry-run" or DRY_RUN_SHORT.fullmatch(o) for o in opzioni)
            if cancella and not prova:
                return True
    return False


SQL_CLI_NAMES = frozenset(
    {"psql", "mysql", "mariadb", "sqlcmd", "pg_restore", "dropdb", "createdb", "mongosh", "redis-cli"}
)


def invoked_commands(text: str) -> frozenset[str]:
    """I comandi che il testo *esegue*, non quelli che nomina.

    `grep -n "dropdb" hooks/guard.py` non cancella nessun database, e nemmeno una
    riga di codice che quella parola la contiene dentro una stringa: il nome sta
    in posizione di argomento, non di comando. Cercarlo come testo è il falso
    positivo del 2026-09-17, e blocca proprio chi sta diagnosticando il guard.
    Il nome è quello del comando vero (`comando_effettivo`): `PGPASSWORD=x psql`,
    `timeout -k 5 60 psql`, `then psql` sono psql.
    """
    return frozenset(e.nome for e in effettivi(text) if e.nome)


def shell_words(text: str) -> frozenset[str]:
    """Le parole che il testo contiene *come parole*, in qualunque posizione.

    Più largo di `invoked_commands`: `timeout 60 rsync …` e `find … -exec rsync …`
    eseguono rsync senza metterlo in testa al comando, e qui contano. Più stretto
    del testo grezzo: in `grep -rlE "rsync.*--delete" scripts/` la parola rsync non
    c'è, c'è il pattern `rsync.*--delete`, che non sincronizza niente. È il falso
    positivo del 2026-09-23, durante /guardrail:setup.

    Una sostituzione di comando (`$(…)`, backtick) esegue anche dentro le
    virgolette doppie, e le virgolette spaiate non si leggono: in quei casi si
    torna a tutte le parole del testo, che sbaglia per eccesso di prudenza.
    """
    if "$(" in text or "`" in text:
        return frozenset(re.findall(r"[\w.-]+", text))
    lexer = shlex.shlex(text.replace("\n", " ; "), punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return frozenset(os.path.basename(token) for token in lexer)
    except ValueError:
        return frozenset(re.findall(r"[\w.-]+", text))


# Il bersaglio di una connessione, e solo quello. Serve a distinguere
# `pg_dump -h prod | psql -h localhost` (un clone verso una sandbox: legittimo,
# vedi database.md) da `psql -h prod -f dump.sql` (un dump che rientra in
# produzione): cercando "prod" nell'intero comando i due sono identici.
CONN_FLAGS = frozenset({"-h", "--host", "-d", "--dbname", "--database", "-U", "--username", "--service"})
# Flag che portano un valore qualunque: quel valore non è un bersaglio.
OTHER_VALUE_FLAGS = frozenset(
    {"-c", "--command", "-f", "--file", "-o", "--output", "-p", "--port", "-P", "-v", "--set",
     "--variable", "-e", "--execute", "-L", "--log-file", "-j", "-T", "-F", "-n"}
)
CONN_ENV = re.compile(
    r"(?:PG(?:HOST|HOSTADDR|DATABASE|SERVICE)|MYSQL_(?:HOST|DATABASE)|DATABASE_URL|DB_(?:HOST|NAME|DATABASE))"
    r"=(?P<value>.*)",
    re.I | re.S,
)
CONN_URI = re.compile(r"(?:postgres(?:ql)?|mysql|mariadb)://", re.I)
LOOKS_LIKE_FILE = re.compile(r"[/\\]|\.\w+$")
# Comandi che possono comparire nella stessa catena senza essere un bersaglio.
DUMP_COMMANDS = frozenset({"pg_dump", "pg_dumpall", "mysqldump", "cat", "zcat", "gunzip", "gzip", *LANCIATORI})


def connection_targets(segment: str) -> str:
    """Le parti di un comando che dicono *a quale database* punta: host, nome del
    database, URI di connessione, variabili d'ambiente.

    I nomi di file restano fuori di proposito: un dump si chiama spesso
    `dump_produzione.sql`, e il nome di un file non è un bersaglio.
    """
    targets: list[str] = []
    pending_conn = False
    skip_value = False
    for token in shell_tokens(segment):
        if pending_conn:
            targets.append(token)
            pending_conn = False
            continue
        if skip_value:
            skip_value = False
            continue
        flag, separator, inline = token.partition("=")
        if flag in CONN_FLAGS:
            if separator:
                targets.append(inline)
            else:
                pending_conn = True
        elif flag in OTHER_VALUE_FLAGS:
            skip_value = not separator
        elif (match := CONN_ENV.fullmatch(token)):
            targets.append(match.group("value"))
        elif CONN_URI.match(token):
            targets.append(token)
        elif token.startswith("-"):
            continue
        elif not LOOKS_LIKE_FILE.search(token) and os.path.basename(token) not in SQL_CLI_NAMES | DUMP_COMMANDS:
            targets.append(token)  # il nome del database, posizionale
    return " ".join(targets)


RESTORE_CLI = re.compile(r"\b(?:psql|mysql|mariadb)\b")
# Un file o una pipe in ingresso: il SQL lo porta il file, non il comando.
FILE_INPUT = re.compile(r"(?:^|\s)(?:-f|--file)[=\s]|(?<!<)<(?![<(])")
PG_RESTORE_TARGET = re.compile(r"(?:^|\s)(?:-d|--dbname)[=\s]")


def pipeline_segments(text: str) -> list[tuple[str, bool]]:
    """Ogni comando della riga, e se riceve stdin da una pipe."""
    parts = re.split(r"(\|\||&&|[;\n|])", text)
    segments: list[tuple[str, bool]] = []
    from_pipe = False
    for index in range(0, len(parts), 2):
        if parts[index].strip():
            segments.append((parts[index], from_pipe))
        separator = parts[index + 1] if index + 1 < len(parts) else ""
        from_pipe = separator == "|"
    return segments


def check_restore_into_prod(text: str, config: dict) -> None:
    """Un dump che rientra in produzione non contiene verbi SQL: li porta il file.

    È la direzione inversa del clone produzione → sandbox locale, ed è l'unico
    modo in cui quel clone può fare danno: `psql -h prod -f dump.sql` riscrive il
    database senza che una sola parola di SQL compaia nel comando.
    """
    for segment, from_pipe in pipeline_segments(text):
        if RESTORE_CLI.search(segment):
            fed = from_pipe or FILE_INPUT.search(segment) is not None
        elif re.search(r"\bpg_restore\b", segment):
            fed = PG_RESTORE_TARGET.search(segment) is not None
        else:
            continue
        if not fed:
            continue
        if (pattern := matches_any(config["prod_patterns"], connection_targets(segment))):
            deny(
                "un dump che rientra in PRODUZIONE: il file (o la pipe) in ingresso esegue SQL che nel "
                f"comando non si vede, e il bersaglio è di produzione (regola {pattern!r}). Il clone va in "
                "una direzione sola, produzione → locale. (guardrail: database.md)"
            )


def check_sql_cli(text: str, config: dict) -> None:
    invoked = invoked_commands(text)
    if not invoked & SQL_CLI_NAMES:
        return
    is_prod = matches_any(config["prod_patterns"], text) is not None

    check_restore_into_prod(text, config)

    if "dropdb" in invoked:
        deny("dropdb: cancella un database intero.") if is_prod else ask("dropdb su un DB non di produzione: conferma?")
    if "pg_restore" in invoked and re.search(r"\bpg_restore\b[^;|]*(--clean|-c\b)", text) and is_prod:
        deny("pg_restore --clean verso produzione: droppa gli oggetti prima di ricrearli.")
    if "redis-cli" in invoked and re.search(r"\bredis-cli\b[^;|]*\b(FLUSHALL|FLUSHDB)\b", text, re.I):
        deny("FLUSHALL/FLUSHDB: svuota Redis, quindi cache, code e sessioni.")

    if WRITE_SQL.search(text):
        if is_prod:
            deny("SQL di scrittura verso un database di PRODUZIONE. In produzione si legge soltanto; ogni modifica passa da una migration nel repo o da un operatore umano. (guardrail: database.md)")
        check_unbounded_writes(text)


def check_unbounded_writes(sql: str) -> None:
    if re.search(r"\bDROP\s+(DATABASE|SCHEMA)\b", sql, re.I):
        deny("DROP DATABASE/SCHEMA: mai dall'agente, su nessun ambiente.")
    if re.search(r"\bTRUNCATE\b", sql, re.I):
        deny("TRUNCATE: svuota una tabella senza possibilità di rollback logico. Se serve, lo fa un umano.")
    for statement in re.split(r";", sql):
        if re.search(r"\bDELETE\s+FROM\s+[\w\".]+", statement, re.I) and not re.search(r"\bWHERE\b", statement, re.I):
            deny("DELETE senza WHERE: cancella l'intera tabella. Aggiungi un predicato stretto.")
        if re.search(r"\bUPDATE\s+[\w\".]+\s+SET\b", statement, re.I) and not re.search(r"\bWHERE\b", statement, re.I):
            deny("UPDATE senza WHERE: riscrive l'intera tabella. Aggiungi un predicato stretto.")


# ---------------------------------------------------------------------------
# MCP: server SQL, e tutti gli altri
# ---------------------------------------------------------------------------

MCP_TOOL = re.compile(r"^mcp__(?P<server>[^_].*?)__(?P<tool>[^_].*)$")
MCP_READ_TOOL = re.compile(r"^(get|list|read|show|describe|search|find|fetch|lookup|check|view|status|info|explain|count|export|browse|preview|query|resolve)(?=$|[_\-\s])", re.I)
# Chiavi di tool_input che descrivono l'operazione (Azure MCP: "command",
# GitHub MCP: "method"/"state"). Il resto dell'input sono parametri, non intenzioni.
MCP_OP_KEYS = ("command", "operation", "action", "method", "op", "intent", "state", "mode", "verb")
MCP_DESTRUCTIVE = re.compile(
    r"\b(delete|remove|purge|destroy|drop|wipe|truncate|prune|reset|unregister|deallocate|revoke|force|closed?|dismiss|archive)\b",
    re.I,
)
MCP_MUTATING = re.compile(
    r"\b(create|update|set|write|put|patch|push|deploy|scale|restart|start|stop|merge|upload|import|restore|rotate"
    r"|assign|grant|enable|disable|apply|edit|rename|move|tag|publish|submit|send|post|add|invite|approve|reopen)\b",
    re.I,
)


# Tool di documentazione (context7: query-docs, resolve-library-id): il loro
# `query` è una domanda in linguaggio naturale, e "with line and column" non è
# una CTE. Classificarla come SQL dava "non classificabile" (2026-10-01/04).
# Restano soggetti alle regole generiche dei tool MCP qui sotto.
MCP_DOCS_TOOL = re.compile(r"(?:^|[_-])(?:docs?|documentation|librar(?:y|ies))(?:$|[_-])", re.I)
# Chiudere il browser di prova o una sua scheda non cancella niente: Playwright
# (browser_close, browser_tabs con action=close), Chrome DevTools (close_page).
MCP_BROWSER_CLOSE = re.compile(r"\b(?:browser|page|tabs?)\s+close\b|\bclose\s+(?:browser|page|tabs?)\b", re.I)


def extract_sql(tool_input: dict) -> str:
    for key in ("sql", "query", "statement", "command", "text"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def mcp_operation_text(tool: str, tool_input: dict) -> str:
    parts = [tool.replace("_", " ").replace("-", " ")]
    for key in MCP_OP_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


# Campi in cui un server di `prose_mcp_servers` riceve il testo da scrivere.
MCP_CONTENT_KEYS = frozenset(
    ("content", "body", "text", "markdown", "message", "description", "comment", "title", "intent", "summary", "notes")
)


def mcp_target_text(tool_input: dict, prose: bool = False) -> str:
    """I parametri MCP come testo, per riconoscere un bersaglio di produzione.

    Di default conta tutto: un `body` può portare il bersaglio in qualunque forma
    (JSON, JSON5, form-encoded, testo), e provare a leggerla apre la porta alle
    differenze fra il nostro parser e quello del server. Solo per un server che
    scrive testo, dichiarato in `prose_mcp_servers`, le stringhe dei campi di
    contenuto non contano: il 2026-10-05 un documento che parlava di produzione
    veniva bloccato come modifica alla produzione. Gli identificativi restano.
    Niente ricorsione: un input annidato a fondo farebbe fallire il controllo, e un
    errore interno lascia passare il tool.
    """
    parts: list[str] = []
    stack: list[tuple[str, object]] = [("", tool_input)]
    while stack:
        key, value = stack.pop()
        if isinstance(value, dict):
            for k, v in value.items():
                parts.append(str(k))
                stack.append((str(k), v))
        elif isinstance(value, list):
            stack.extend((key, v) for v in value)
        elif prose and isinstance(value, str) and key.lower() in MCP_CONTENT_KEYS:
            continue
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts)


def check_mcp(tool_name: str, tool_input: dict, config: dict) -> None:
    match = MCP_TOOL.match(tool_name)
    if not match:
        return
    server, tool = match.group("server"), match.group("tool")
    is_prod = server in config["prod_mcp_servers"] or matches_any(config["prod_patterns"], server) is not None
    is_shared = server in config["ask_mcp_servers"]

    sql = extract_sql(tool_input)
    # La classificazione distingue le tre risposte possibili, e la sola che
    # autorizza è "lettura": una query di sola lettura resta permessa ovunque,
    # produzione compresa, anche quando un valore confrontato contiene un verbo
    # di scrittura. Tutto il resto si mostra a chi deve decidere.
    if (
        sql
        and re.search(r"(query|sql|execute|run|statement)", tool, re.I)
        and not MCP_DOCS_TOOL.search(tool)
        and SQL_KEYWORD.search(sql)
    ):
        verdetto = classifica_sql(sql)
        if verdetto == "lettura":
            return
        testo = query_esposta(sql)
        if verdetto == "incerta":
            perche = (
                "non riesco a dire se legge o scrive: contiene un commento, un dollar-quote, un literal "
                "non chiuso o un'istruzione che non si classifica (CALL, DO, COPY…), e lì il confine fra "
                "codice e dati non è leggibile con certezza"
            )
            if is_prod:
                deny(
                    f"query non classificabile sul server MCP {server!r}, che è PRODUZIONE — {perche}.\n"
                    f"Sarebbe stato eseguito questo:\n    {testo}\n"
                    "Riscrivila senza commenti né dollar-quote e con i literal chiusi, così posso "
                    "riconoscerla come lettura; se deve davvero scrivere, la esegue un operatore. "
                    "(guardrail: database.md)"
                )
            ask(
                f"query non classificabile sul server MCP {server!r} — {perche}.\n"
                f"Sta per essere eseguito questo:\n    {testo}\nConfermi?"
            )
        if is_prod:
            deny(
                f"scrittura SQL sul server MCP {server!r}, che è PRODUZIONE. In produzione l'agente legge "
                f"soltanto; le modifiche passano da una migration nel repo o da un operatore.\n"
                f"Sarebbe stato eseguito questo:\n    {testo}\n(guardrail: database.md)"
            )
        check_unbounded_writes(sql_normalizzato(sql)[0])
        if is_shared:
            ask(
                f"scrittura SQL sul server MCP {server!r}, condiviso con altre persone.\n"
                f"Sta per essere eseguito questo:\n    {testo}\nConfermi?"
            )
        return

    # Ogni altro server: Azure, GitHub, filesystem, ... L'intenzione sta nel nome
    # del tool e nei campi che descrivono l'operazione; i parametri dicono se il
    # bersaglio è produzione.
    if MCP_READ_TOOL.match(tool):
        return
    operation = MCP_BROWSER_CLOSE.sub(" ", mcp_operation_text(tool, tool_input))
    prose = server in config["prose_mcp_servers"]
    targets_prod = is_prod or matches_any(config["prod_patterns"], mcp_target_text(tool_input, prose)) is not None

    if MCP_DESTRUCTIVE.search(operation):
        if targets_prod:
            deny(f"operazione distruttiva via MCP {server!r} ({operation.strip()}) su un bersaglio di PRODUZIONE. Mai dall'agente.")
        ask(f"operazione distruttiva via MCP {server!r}: {operation.strip()}. Cosa sparisce, e si può ricreare? Conferma.")
    if MCP_MUTATING.search(operation):
        if targets_prod:
            deny(f"modifica via MCP {server!r} ({operation.strip()}) su un bersaglio di PRODUZIONE. In produzione si legge soltanto; le modifiche passano da un deploy o da un operatore umano.")
        if is_shared:
            ask(f"modifica via MCP {server!r} ({operation.strip()}) su un servizio condiviso. Conferma?")


# ---------------------------------------------------------------------------
# Read / Write / Edit
# ---------------------------------------------------------------------------

SECRET_NAME = re.compile(
    r"^(\.env(\..+)?|\.secrets|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_(rsa|ed25519|ecdsa|dsa)(\.pub)?|\.netrc|\.pgpass|\.my\.cnf"
    r"|\.htpasswd|\.claude\.json|\.credentials\.json|credentials\.json|\.git-credentials|\.npmrc|\.pypirc)$"
)
SECRET_TEMPLATE = re.compile(r"\.(example|sample|template|dist)$")
SECRET_DIRS = {".ssh", ".aws", ".azure", ".kube", ".gnupg"}
SECRET_TAILS = ((".docker", "config.json"), ("gh", "hosts.yml"))

# Sotto ~/.claude: ciò che governa il comportamento dell'agente. Il resto
# (projects/, todos/, debug/...) è stato interno di Claude Code e non si tocca qui.
CLAUDE_HOME_GOVERNANCE = {"settings.json", "settings.local.json", "CLAUDE.md", "keybindings.json"}
CLAUDE_HOME_GOVERNANCE_DIRS = {"commands", "skills", "agents", "rules", "output-styles"}
CLAUDE_HOME_CODE_DIRS = {"plugins", "hooks"}


def target_path(tool_input: dict) -> Path | None:
    raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path")
    if not isinstance(raw, str) or not raw:
        return None
    return Path(os.path.expanduser(raw))


def is_secret_file(name: str) -> bool:
    return bool(SECRET_NAME.match(name)) and not SECRET_TEMPLATE.search(name)


def is_secret_path(path: Path) -> bool:
    parts = path.parts
    if any(part in SECRET_DIRS for part in parts):
        return True
    for parent, name in SECRET_TAILS:
        if len(parts) >= 2 and parts[-1] == name and parts[-2] == parent:
            return True
    return is_secret_file(path.name)


def relative_to_home(path: Path) -> Path | None:
    try:
        return path.resolve().relative_to(Path.home())
    except (ValueError, OSError):
        return None


def check_read(tool_input: dict) -> None:
    """Le letture di segreti non dipendono più da permissions.deny nelle settings."""
    path = target_path(tool_input)
    if path is None:
        return
    if any(part == ".ssh" for part in path.parts):
        deny(f"lettura dentro ~/.ssh ({path}): chiavi e configurazione SSH non passano dall'agente.")
    if is_secret_path(path):
        deny(
            f"lettura di un file di segreti ({path}): il contenuto finirebbe nella trascrizione, "
            "che resta su disco. Per il nome di una variabile leggi .env.example; per il valore, "
            "chiedilo all'utente. (guardrail: filesystem-shell-segreti.md)"
        )


def is_inside(path: Path, root: Path | None) -> bool:
    if root is None:
        return False
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def check_write_guardrail(path: Path) -> None:
    """Scritture su guardrail stesso: il suo codice, la sua configurazione, le
    impostazioni di Claude Code. Valgono anche dove guardrail è spento (vedi `decide`).
    Si guarda anche dove porta il percorso: `note.json` può essere un link."""
    try:
        reale = path.resolve()
    except (OSError, RuntimeError):
        reale = path
    for candidato in dict.fromkeys([path, reale]):
        _check_write_guardrail(candidato)


def _check_write_guardrail(path: Path) -> None:
    raw = str(path)
    name = path.name
    in_home = relative_to_home(path)
    if in_home is not None and in_home.parts[:1] == (".claude",) and len(in_home.parts) > 2 and in_home.parts[1] in CLAUDE_HOME_CODE_DIRS:
        deny(
            f"scrittura in ~/.claude/{in_home.parts[1]} ({raw}): è il codice dei hook e dei plugin, cioè di "
            "guardrail stesso. Si aggiorna con /plugin, mai a mano dall'agente. (guardrail: RULES-CORE.md 8)"
        )

    # Conferme: la configurazione di guardrail e di Claude Code non si modifica da
    # soli, sarebbe il modo elegante di aggirare un blocco (RULES-CORE.md, regola 8).
    if name.lower() == ".guardrail.json":
        ask(
            "modifica di .guardrail.json: cambia le regole di guardrail che ti vincolano. "
            "Decide l'utente, e il file va committato con la motivazione. (guardrail: RULES-CORE.md 8)"
        )
    if in_home is not None and in_home.parts[:1] == (".claude",) and (
        (len(in_home.parts) == 2 and name in CLAUDE_HOME_GOVERNANCE)
        or (len(in_home.parts) > 2 and in_home.parts[1] in CLAUDE_HOME_GOVERNANCE_DIRS)
    ):
        ask(
            f"modifica della configurazione di Claude Code ({raw}): tocca permessi, hook, comandi o "
            "istruzioni dell'utente. Mostra il cambiamento e fallo approvare."
        )
    # Lo stesso nel .claude/ di un progetto: con `enabledPlugins` o `env` le sue
    # settings spengono guardrail lì. Da shell PROTECTED_PATH lo copre già.
    parti = path.parts[:-1]
    if in_home is None or in_home.parts[:1] != (".claude",):
        if ".claude" in parti:
            resto = path.parts[len(parti) - parti[::-1].index(".claude"):]
            if resto in (("settings.json",), ("settings.local.json",), ("CLAUDE.md",)) or (
                len(resto) > 1 and resto[0] in CLAUDE_HOME_CODE_DIRS | CLAUDE_HOME_GOVERNANCE_DIRS
            ):
                ask(
                    f"modifica della configurazione di Claude Code del progetto ({raw}): settings, hook e "
                    "istruzioni possono spegnere o aggirare guardrail. Mostra il cambiamento e fallo approvare."
                )


def check_bash_guardrail(cmd: str, cwd: str = "", depth: int = 0) -> None:
    """Da shell, le stesse scritture di `check_write_guardrail`, e la rimozione di
    .guardrail.json; anche dentro `bash -c "…"` e negli script lanciati."""
    text = strip_inert_heredocs(strip_data_heredocs(re.sub(r"\\\n", " ", cmd)))
    check_protected_writes(text, cwd)
    if depth >= MAX_DEPTH:
        return
    for payload in inline_shell_payloads(text):
        check_bash_guardrail(payload, cwd, depth + 1)
    # Ogni livello, non solo il primo: uno script può lanciarne un altro.
    for path in invoked_scripts(text, cwd):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            check_bash_guardrail(content, cwd, depth + 1)
        except Decision as found:
            if found.verdict == "deny":
                deny(f"lo script {path.name} contiene un comando vietato: {found.reason}")
            ask(f"lo script {path.name} tocca la configurazione di guardrail o di Claude Code — {found.reason}")


def check_write(tool_input: dict, cwd: str) -> None:
    path = target_path(tool_input)
    if path is None:
        return
    raw = str(path)
    name = path.name
    in_home = relative_to_home(path)

    # Blocchi secchi
    if any(part == ".ssh" for part in path.parts) or (SECRET_NAME.match(name) and re.search(r"id_|\.pem$|\.key$|\.p12$|\.pfx$", name)):
        deny(f"scrittura su una chiave privata o in ~/.ssh ({raw}). Mai dall'agente.")
    if str(path).startswith("/etc/") or str(path).startswith("/usr/"):
        deny(f"scrittura su un file di sistema ({raw}).")
    check_write_guardrail(path)
    if is_secret_path(path):
        ask(f"scrittura su un file di segreti ({raw}). Conferma che è voluto e che il file è gitignorato.")
    if in_home is not None and len(in_home.parts) == 1 and in_home.parts[0].startswith("."):
        ask(f"scrittura su un dotfile della home ({raw}): cambia l'ambiente dell'utente. Conferma?")

    # Regola 5: nulla fuori dal progetto senza chiederlo. Lo scratchpad e lo
    # stato interno di Claude Code (memoria, todo) sono aree di lavoro legittime.
    root = project_root(cwd)
    if root is None:
        return
    allowed = [root, Path("/tmp"), Path.home() / ".claude" / "projects"]
    for env_key in ("TMPDIR", "TMP", "TEMP"):
        if os.environ.get(env_key):
            allowed.append(Path(os.environ[env_key]))
    if not any(is_inside(path, base) for base in allowed):
        ask(
            f"scrittura fuori dal progetto ({raw}; progetto: {root}). La home, altri repo e le "
            "directory di sistema si toccano solo su richiesta esplicita. Conferma? (guardrail: RULES-CORE.md 5)"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def decide(payload: dict) -> None:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    cwd = str(payload.get("cwd") or "")

    # Dove guardrail è spento valgono solo le regole che proteggono guardrail stesso.
    # Senza, una sessione aperta in una cartella qualunque potrebbe spegnerlo o
    # allentarlo nei progetti dove è acceso: togliendo il loro .guardrail.json,
    # scrivendo allow_commands in ~/.guardrail.json, toccando il codice del plugin.
    if not attivo(cwd):
        if tool == "Bash":
            check_bash_guardrail(str(tool_input.get("command", "")), cwd)
        elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            path = target_path(tool_input)
            if path is not None:
                check_write_guardrail(path)
        return

    config = load_config(cwd)

    if tool == "Bash":
        command = str(tool_input.get("command", ""))
        try:
            check_bash_guardrail(command, cwd)
            sospesa = None
        except Decision as found:
            if found.verdict == "deny":
                raise
            sospesa = found
        check_bash(command, config, cwd)
        if sospesa:
            raise sospesa
    elif tool == "Read":
        check_read(tool_input)
    elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        check_write(tool_input, cwd)
    elif tool.startswith("mcp__"):
        check_mcp(tool, tool_input, config)


def log_decision(payload: dict, verdict: str, reason: str) -> None:
    try:
        log = Path.home() / ".claude" / "guardrail.log.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "verdict": verdict,
            "tool": payload.get("tool_name"),
            "cwd": payload.get("cwd"),
            "session": payload.get("session_id"),
            "reason": reason,
            "input": json.dumps(payload.get("tool_input"), ensure_ascii=False)[:400],
        }
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except RecursionError:
        # Un input annidato oltre quanto il parser regge non si può giudicare. Lasciarlo
        # passare vorrebbe dire che basta annidare un comando per saltare ogni controllo.
        emit("deny", "input del tool annidato troppo a fondo per essere controllato.")
        return 0
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0

    # Il mascheramento non segue GUARDRAIL_DISABLE: spegnere i controlli non deve
    # rimettere in chiaro i termini riservati. Lo si spegne togliendo la mappa.
    tool = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input") or {}
    cwd = str(payload.get("cwd") or "")
    try:
        pairs = mask.load_pairs()
    except mask.MappaNonValida as exc:
        # Fail-closed: con una mappa rotta nessun risultato di tool si può mascherare.
        log_decision(payload, "deny", str(exc))
        emit("deny", f"{exc}. Correggi la mappa o toglila per disattivare il mascheramento.")
        return 0

    # Cosa esegue davvero la macchina (i controlli si fanno su questo, con i termini
    # reali) e cosa riceve il tool al posto dell'input del modello.
    effettivo, riscritto = tool_input, None
    if pairs and tool == "Bash" and str(tool_input.get("command", "")).strip():
        command = str(tool_input["command"])
        effettivo = {**tool_input, "command": mask.unmask(command, pairs)}
        riscritto = {**tool_input, "command": mask.wrap_command(command)}
    elif pairs:
        riscritto = mask.unmask_tool_input(tool, tool_input, cwd, pairs)
        effettivo = riscritto or tool_input

    bloccato = mask.blocking_reason(tool, effettivo, pairs)
    if bloccato:
        log_decision(payload, "deny", bloccato)
        emit("deny", bloccato)
        return 0

    if os.environ.get("GUARDRAIL_DISABLE") == "1":
        log_decision(payload, "disabled", "GUARDRAIL_DISABLE=1")
        emit(updated_input=riscritto)
        return 0

    try:
        decide({**payload, "tool_input": effettivo})
    except Decision as decision:
        reason = mask.mask(decision.reason, pairs)
        log_decision(payload, decision.verdict, reason)
        emit(decision.verdict, reason, None if decision.verdict == "deny" else riscritto)
        return 0
    except Exception as exc:  # noqa: BLE001 — un bug del guard non deve mai bloccare il lavoro
        print(f"[guardrail] errore interno, tool lasciato passare: {mask.mask(str(exc), pairs)}", file=sys.stderr)
    emit(updated_input=riscritto)
    return 0


def emit(verdict: str = "", reason: str = "", updated_input: dict | None = None) -> None:
    """Stampa la risposta del hook: la decisione, se c'è, e l'input riscritto per il
    mascheramento, se c'è. Nessuna delle due: nessun output, il tool procede."""
    out: dict = {"hookEventName": "PreToolUse"}
    if verdict:
        out["permissionDecision"] = verdict
        out["permissionDecisionReason"] = f"[guardrail] {reason}"
    if updated_input is not None:
        out["updatedInput"] = updated_input
    if len(out) > 1:
        print(json.dumps({"hookSpecificOutput": out}, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
