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

La configurazione per repo sta in `.guardrail.json` (cercato dalla cwd verso l'alto)
e in `~/.guardrail.json`; le liste si sommano. Vedi README.md.

Solo libreria standard. Nessuna dipendenza, nessuna rete.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

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


def load_config(cwd: str) -> dict:
    """Unisce default, ~/.guardrail.json e il primo .guardrail.json trovato risalendo da cwd."""
    config = {key: list(value) for key, value in DEFAULT_CONFIG.items()}

    sources: list[Path] = []
    override = os.environ.get("GUARDRAIL_CONFIG")
    if override:
        sources.append(Path(override))
    else:
        sources.append(Path.home() / ".guardrail.json")
        current = Path(cwd or os.getcwd()).resolve()
        for candidate in [current, *current.parents]:
            probe = candidate / ".guardrail.json"
            if probe.is_file():
                sources.append(probe)
                break

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
# Bash: cancellazioni
# ---------------------------------------------------------------------------

RM_ANY = re.compile(
    r"(?:^|[;&|(\n]\s*|\bsudo\s+|\bxargs\s+(?:-[a-zA-Z0-9]+\s+)*)rm\s+(?P<args>[^;&|)\n]*)",
    re.M,
)
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
FIND_DELETE = re.compile(
    r"(?:^|[;&|(]\s*)(?:sudo\s+)?find\s+(?P<root>[^-\s;&|][^\s;&|]*)?[^;&|]*?(?:-delete\b|-exec\s+(?:sudo\s+)?rm\b)"
)


def check_rm(cmd: str) -> None:
    for match in RM_ANY.finditer(cmd):
        args = match.group("args")
        recursive = RM_RECURSIVE_FLAG.search(" " + args) is not None
        variable_only: str | None = None
        for arg in args.split():
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
    for match in FIND_DELETE.finditer(cmd):
        root = match.group("root") or "."
        if root != "." and DANGEROUS_RM_TARGET.match(root):
            deny(f"find … -delete / -exec rm a partire da {root!r}: cancellazione ricorsiva su un bersaglio non sicuro.")
        ask(
            f"find … -delete / -exec rm a partire da {root!r}: cancella tutto ciò che il predicato seleziona. "
            "Prima lo stesso find senza -delete, mostrato all'utente. Conferma?"
        )


# ---------------------------------------------------------------------------
# Bash: segreti e configurazione
# ---------------------------------------------------------------------------

# `\.env(?:\.[\w-]+)*` prende la catena *intera* dei suffissi: con un solo
# segmento `.env.azure.example` si fermerebbe a `.env.azure`, e l'esenzione
# template (ancorata in fondo) non vedrebbe mai `.example`.
SECRET_FILE = re.compile(
    r"(?:[\w./~-]*/)?(?:\.env(?:\.[\w-]+)*|\.secrets|\.netrc|\.pgpass|\.my\.cnf|\.htpasswd"
    r"|\.claude\.json|\.credentials\.json|credentials\.json|\.git-credentials|\.npmrc|\.pypirc"
    r"|\.aws/credentials|\.docker/config\.json|\.kube/config|gh/hosts\.yml|\.gnupg/[^\s\"']+"
    r"|[\w.-]+\.(?:pem|key|p12|pfx)|id_(?:rsa|ed25519|ecdsa|dsa))"
)
# Comandi che stampano o trasformano il contenuto di un file: il segreto finisce
# nella trascrizione della sessione, che resta su disco.
SECRET_READERS = re.compile(
    r"\b(cat|bat|tac|less|more|head|tail|nl|od|xxd|strings|grep|egrep|fgrep|rg|ag|awk|sed|cut|base64|jq|tee)\b"
)
SECRET_SOURCERS = re.compile(r"(?:^|[;&|]\s*)(?:source|\.)\s+\S")
# Comandi il cui primo operando è un'espressione, non un file: in
# `grep "\.env" casi.jsonl` quel `.env` è una regex e non si legge nessun segreto.
PATTERN_COMMANDS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "perl"}
# ...a meno che il pattern arrivi da un flag: allora ogni operando è un file.
PATTERN_FLAGS = {"-e", "--regexp", "-f", "--file", "--expression"}

# File che governano guardrail e Claude Code: modificarli da shell è il modo di
# aggirare un blocco senza passare da Write/Edit.
PROTECTED_PATH = re.compile(
    r"(?:^|[\s/\"'=])(?P<path>\.guardrail\.json|\.claude/settings(?:\.local)?\.json|\.claude/CLAUDE\.md"
    r"|\.claude/(?P<plugin>plugins|hooks)(?:/[^\s\"']*)?|\.claude/(?:commands|skills|agents|rules)(?:/[^\s\"']*)?)"
)
SHELL_WRITER_CMDS = re.compile(
    r"(?:^|[;&|(])\s*(?:sudo\s+)?(?:tee|cp|mv|rm|sed|perl|truncate|ln|install|chmod|chattr|dd|rsync|python3?|node)\b"
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
# Quel che sta *prima* del vero comando: `sudo -u deploy rm x`, `FOO=1 tee y`.
COMMAND_PREFIX = re.compile(r"^(?:sudo|command|env|nohup|time|xargs|\w+=.*)$")
PREFIX_VALUE_FLAGS = {"-u", "-g", "-U", "-C", "-p", "-r", "-t", "-n", "-I"}
IN_PLACE_FLAG = re.compile(r"^--in-place|^-[a-zA-Z]*i")
# Il bersaglio di una redirezione è il token che la segue, non il comando che la
# contiene: `ls .claude/hooks 2>/dev/null` scrive su /dev/null, non sui hook.
REDIRECT = re.compile(r"(?:^|\s)\d*>>?\s*(?P<target>[^\s;&|<>()]+)")


def shell_segments(text: str) -> list[str]:
    return [s for s in re.split(r"[;&|\n]+|\$\(|\)", text) if s.strip()]


def redirect_targets(segment: str) -> list[str]:
    return [m.group("target") for m in REDIRECT.finditer(segment)]


def shell_tokens(segment: str) -> list[str]:
    """Token del comando, tolte le redirezioni. Virgolette sbilanciate: best effort."""
    cleaned = REDIRECT.sub(" ", segment)
    try:
        return shlex.split(cleaned)
    except ValueError:
        return cleaned.split()


def write_targets(segment: str) -> list[str]:
    """Gli operandi su cui il comando *scrive*. Un comando di lettura non ne ha."""
    targets = redirect_targets(segment)
    tokens = shell_tokens(segment)
    seen_prefix = False
    while tokens:
        if COMMAND_PREFIX.match(tokens[0]):
            tokens.pop(0)
            seen_prefix = True
            continue
        # I flag di sudo/env/xargs, non quelli del comando vero.
        if seen_prefix and tokens[0].startswith("-"):
            flag = tokens.pop(0)
            if flag in PREFIX_VALUE_FLAGS and tokens:
                tokens.pop(0)
            continue
        break
    if not tokens:
        return targets
    mode = WRITER_TARGETS.get(os.path.basename(tokens[0]))
    if mode is None:
        return targets
    args = tokens[1:]
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


def file_operands(segment: str) -> list[str]:
    """Gli operandi che il comando tratta come file, senza il pattern di grep/sed/awk."""
    tokens = shell_tokens(segment)
    while tokens and COMMAND_PREFIX.match(tokens[0]):
        tokens.pop(0)
    if not tokens:
        return []
    args = tokens[1:]
    operands = [a for a in args if not a.startswith("-")]
    if os.path.basename(tokens[0]) in PATTERN_COMMANDS and not any(
        a in PATTERN_FLAGS or a.split("=", 1)[0] in PATTERN_FLAGS for a in args
    ):
        operands = operands[1:]
    return operands


def check_secret_reads(text: str) -> None:
    """Blocca `cat .env` e affini: permissions.deny copre il tool Read, non la shell."""
    for segment in shell_segments(text):
        found = secret_names(file_operands(segment))
        written = secret_names(redirect_targets(segment))
        if not found and not written:
            continue
        if found and SECRET_READERS.search(segment):
            deny(
                f"lettura di un file di segreti da shell ({found[0]}): il contenuto finirebbe "
                "nella trascrizione, che resta su disco. Per il nome di una variabile leggi "
                ".env.example; per il valore, chiedilo all'utente. (guardrail: filesystem-shell-segreti.md)"
            )
        if found and SECRET_SOURCERS.search(segment):
            ask(
                f"source di un file di segreti ({found[0]}): carica credenziali nell'ambiente "
                "del comando. Conferma che è voluto?"
            )
        # cp/mv/ln restano presi in *entrambe* le direzioni: `cp .env x && cat x`
        # ricicla il nome. Le redirezioni no: contano solo se scrivono sul segreto.
        if written or (found and SHELL_WRITER_CMDS.search(segment)):
            name = (written + found)[0]
            ask(f"scrittura da shell su un file di segreti ({name}). Conferma che è voluto e che il file è gitignorato.")


def check_protected_writes(text: str) -> None:
    for segment in shell_segments(text):
        for target in write_targets(segment):
            match = PROTECTED_PATH.search(target)
            if not match:
                continue
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
HEREDOC_DATA_HEAD = (
    r"(?:>>?\s*\S+|\btee\b"
    r"|\b(?:git|gh)\b[^\n]*?(?:--body-file|--notes-file|--file|-F)[=\s]+-(?=\s))"
)
HEREDOC = re.compile(
    r"(?P<head>^[^\n]*?" + HEREDOC_DATA_HEAD + r"[^\n]*<<-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)[^\n]*\n)"
    r"(?P<body>.*?)(?P<end>^\s*(?P=tag)\s*$)",
    re.M | re.S,
)

# Heredoc che alimenta un interprete NON-shell: `python3 - <<PY`, `node <<JS`.
# Il corpo sono comandi — per quell'interprete, non per la shell — e resta
# analizzato da tutte le regole built-in: un `os.system("rm -rf ...")` dentro un
# heredoc Python va visto, ed è la ragione per cui la riga 395 dice che questi
# heredoc non si toccano.
#
# Le regex di PROGETTO sono un caso diverso, e solo loro usano questo taglio.
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
HEREDOC_INTERPRETER = re.compile(
    r"(?P<head>^[^\n]*?\b(?:python[\d.]*|node|ruby|perl|php|Rscript)\b"
    r"[^\n]*<<-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)[^\n]*\n)"
    r"(?P<body>.*?)(?P<end>^\s*(?P=tag)\s*$)",
    re.M | re.S,
)

SCRIPT_BY_INTERPRETER = re.compile(
    r"(?:^|[;&|(]\s*)(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python3?|node|php|perl|ruby)\s+(?:-[\w=-]+\s+)*(?P<path>[^\s;&|()-][^\s;&|()]*)"
)
SCRIPT_DIRECT = re.compile(r"(?:^|[;&|(]\s*)(?:sudo\s+)?(?P<path>(?:\./|\.\./|~/)[^\s;&|()]+)")
SCRIPT_SOURCED = re.compile(r"(?:^|[;&|(]\s*)(?:source|\.)\s+(?P<path>[^\s;&|()]+)")


def strip_data_heredocs(text: str) -> str:
    return HEREDOC.sub(lambda m: m.group("head") + m.group("end"), text)


def strip_interpreter_heredocs(text: str) -> str:
    """Il testo su cui si applicano le REGEX DI PROGETTO, e solo quelle.

    Toglie il corpo degli heredoc diretti a un interprete non-shell. La riga di
    testa resta: `python3 - <<PY` continua a essere un comando, e se la testa
    contiene il pattern cercato la regola scatta come prima.

    Non usarlo per le regole built-in: quelle devono continuare a vedere tutto.
    """
    return HEREDOC_INTERPRETER.sub(lambda m: m.group("head") + m.group("end"), text)


def invoked_scripts(text: str, cwd: str) -> list[Path]:
    found: list[Path] = []
    for regex in (SCRIPT_BY_INTERPRETER, SCRIPT_DIRECT, SCRIPT_SOURCED):
        for match in regex.finditer(text):
            raw = match.group("path").strip("\"'")
            if "$" in raw:
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
            # mai", e vale anche dentro uno script approvato.
            if found.reason.startswith("comando vietato dalla configurazione"):
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
    lexer = shlex.shlex(text.replace("\n", " ; "), punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    payloads: list[str] = []
    try:
        tokens = list(lexer)
    except ValueError:
        return payloads

    at_start = True
    indice = 0
    while indice < len(tokens):
        token = tokens[indice]
        indice += 1
        if token in SHELL_SEPARATORS:
            at_start = True
            continue
        if not at_start:
            continue
        if ENV_ASSIGNMENT.fullmatch(token) or token in COMMAND_WRAPPERS:
            continue
        at_start = False
        nome = os.path.basename(token)

        # `bash -c "…"`, anche con flag composti (`-lc`, `-ec`).
        if nome in SHELL_INTERPRETERS:
            while indice < len(tokens) and tokens[indice] not in SHELL_SEPARATORS:
                flag = tokens[indice]
                indice += 1
                if flag.startswith("-") and not flag.startswith("--") and "c" in flag:
                    if indice < len(tokens) and tokens[indice] not in SHELL_SEPARATORS:
                        payloads.append(tokens[indice])
                        indice += 1
                    break
                if not flag.startswith("-"):
                    break  # è il path di uno script: se ne occupa check_scripts
        # `eval rm -rf "$X"`: tutto quello che segue è codice.
        elif nome == "eval":
            resto = []
            while indice < len(tokens) and tokens[indice] not in SHELL_SEPARATORS:
                resto.append(tokens[indice])
                indice += 1
            if resto:
                payloads.append(" ".join(resto))
        # `ssh [opzioni] host "…"`: il comando remoto è tutto ciò che segue l'host.
        elif nome == "ssh":
            host_visto = False
            resto = []
            while indice < len(tokens) and tokens[indice] not in SHELL_SEPARATORS:
                pezzo = tokens[indice]
                indice += 1
                if not host_visto:
                    if pezzo in SSH_VALUE_FLAGS:
                        indice += 1
                        continue
                    if pezzo.startswith("-"):
                        continue
                    host_visto = True
                    continue
                resto.append(pezzo)
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
    # continuano a usare `text`, che quei corpi li contiene ancora.
    testo_progetto = strip_interpreter_heredocs(text)

    if depth == 0 and matches_any(config["allow_commands"], testo_progetto):
        return

    if (pattern := matches_any(config["deny_commands"], testo_progetto)):
        deny(f"comando vietato dalla configurazione del progetto (.guardrail.json, regola {pattern!r}).")

    check_inline_shell(text, config, cwd, depth)
    check_rm(text)
    check_secret_reads(text)
    check_protected_writes(text)

    # Distruzione di sistema o supply chain
    if re.search(r"\bsudo\s+rm\b", text):
        deny("sudo rm: cancellazioni con privilegi non passano dall'agente.")
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

    # Deploy con cancellazione sul bersaglio
    if re.search(r"\bmirror\b[^;|]*--delete\b", text) and not re.search(r"\bmirror\b[^;|]*--dry-run\b", text):
        deny("lftp mirror --delete senza --dry-run: cancella sul server remoto tutto ciò che manca in locale. (guardrail: deploy-infrastruttura.md)")
    if re.search(r"\brsync\b[^;|]*--delete", text) and not re.search(r"\brsync\b[^;|]*(\s--dry-run\b|\s-[a-zA-Z]*n[a-zA-Z]*\b)", text):
        deny("rsync --delete senza --dry-run / -n: cancella sul bersaglio. Prima il dry-run, poi l'utente decide.")

    # Git
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
    if re.search(r"(?:^|[;&|(]\s*)sudo\b", text):
        ask("sudo: un comando con privilegi. Cosa fa, e perché serve root? Conferma.")

    if (pattern := matches_any(config["ask_commands"], testo_progetto)):
        ask(f"comando che richiede conferma per la configurazione del progetto (regola {pattern!r}).")


SQL_CLI_NAMES = frozenset(
    {"psql", "mysql", "mariadb", "sqlcmd", "pg_restore", "dropdb", "createdb", "mongosh", "redis-cli"}
)
# Token che stanno davanti al comando vero senza esserlo.
COMMAND_WRAPPERS = frozenset({"sudo", "env", "command", "exec", "time", "nohup", "xargs", "then", "do", "else", "!"})
# Separatori dopo i quali ricomincia un comando.
SHELL_SEPARATORS = frozenset({";", "|", "||", "&", "&&", "(", ")", "{", "}", "&|"})
ENV_ASSIGNMENT = re.compile(r"\w+=.*", re.S)


def invoked_commands(text: str) -> frozenset[str]:
    """I comandi che il testo *esegue*, non quelli che nomina.

    `grep -n "dropdb" hooks/guard.py` non cancella nessun database, e nemmeno una
    riga di codice che quella parola la contiene dentro una stringa: il nome sta
    in posizione di argomento, non di comando. Cercarlo come testo è il falso
    positivo del 2026-09-17, e blocca proprio chi sta diagnosticando il guard.

    Un ritorno a capo vale come `;`, perché ogni riga ricomincia con un comando;
    va sostituito prima, però, non riga per riga: una stringa che si estende su
    più righe lascerebbe ogni riga con le virgolette scompagnate.

    posix=True: `\\"` è un escape, come nella shell vera. Senza, una virgoletta
    escapata dentro un argomento fa ripartire la lettura a metà stringa, e un
    nome citato lì in mezzo sembra un comando.

    Se le virgolette non tornano si ripiega sul comportamento testuale di prima
    — tutte le parole — che sbaglia per eccesso di prudenza.
    """
    lexer = shlex.shlex(text.replace("\n", " ; "), punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    names: set[str] = set()
    at_start = True
    skip_next = False
    try:
        for token in lexer:
            if skip_next:  # il bersaglio di una redirezione non è un comando
                skip_next = False
                continue
            if token and set(token) <= {"<", ">"}:
                skip_next = True
                continue
            if token in SHELL_SEPARATORS:
                at_start = True
                continue
            if not at_start:
                continue
            if ENV_ASSIGNMENT.fullmatch(token):  # PGPASSWORD=x psql ...
                continue
            if token in COMMAND_WRAPPERS or token.startswith("-"):
                continue
            names.add(os.path.basename(token))
            at_start = False
    except ValueError:
        return frozenset(re.findall(r"[\w.-]+", text))
    return frozenset(names)


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
DUMP_COMMANDS = frozenset({"pg_dump", "pg_dumpall", "mysqldump", "cat", "zcat", "gunzip", "gzip", "sudo", "env"})


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
    if sql and re.search(r"(query|sql|execute|run|statement)", tool, re.I) and SQL_KEYWORD.search(sql):
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
    operation = mcp_operation_text(tool, tool_input)
    parameters = json.dumps(tool_input, ensure_ascii=False)
    targets_prod = is_prod or matches_any(config["prod_patterns"], parameters) is not None

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
    if in_home is not None and in_home.parts[:1] == (".claude",) and len(in_home.parts) > 2 and in_home.parts[1] in CLAUDE_HOME_CODE_DIRS:
        deny(
            f"scrittura in ~/.claude/{in_home.parts[1]} ({raw}): è il codice dei hook e dei plugin, cioè di "
            "guardrail stesso. Si aggiorna con /plugin, mai a mano dall'agente. (guardrail: RULES-CORE.md 8)"
        )

    # Conferme: la configurazione di guardrail e di Claude Code non si modifica da
    # soli, sarebbe il modo elegante di aggirare un blocco (RULES-CORE.md, regola 8).
    if name == ".guardrail.json":
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
    config = load_config(cwd)

    if tool == "Bash":
        check_bash(str(tool_input.get("command", "")), config, cwd)
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
