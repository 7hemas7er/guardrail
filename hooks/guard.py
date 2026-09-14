#!/usr/bin/env python3
"""Guardrail — hook PreToolUse per Claude Code.

Legge da stdin il JSON che Claude Code passa ai hook:
    {"tool_name": "...", "tool_input": {...}, "cwd": "...", "session_id": "..."}
e risponde su stdout con una decisione:
    allow  -> nessun output (il tool procede)
    ask    -> chiede conferma all'utente, anche in modalità auto
    deny   -> blocca il tool e spiega a Claude il motivo

Quattro famiglie di regole, tutte nella funzione `decide`:
    Bash        comandi distruttivi, deploy con cancellazione, SQL da CLI su prod,
                letture di segreti da shell (cat .env)
    mcp__*__*   query SQL via server MCP: scritture su prod, DELETE/UPDATE senza WHERE
    Write/Edit  file di segreti, dotfile della home, e la configurazione di
                guardrail stessa (.guardrail.json, ~/.claude/settings.json)
    Read        file di segreti e ~/.ssh

La configurazione per repo sta in `.guardrail.json` (cercato dalla cwd verso l'alto)
e in `~/.guardrail.json`; le liste si sommano. Vedi README.md.

Solo libreria standard. Nessuna dipendenza, nessuna rete.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

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
}

WRITE_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|REPLACE|MERGE|RENAME|VACUUM\s+FULL)\b",
    re.I,
)
READ_ONLY_START = re.compile(r"^\s*(SELECT|WITH|EXPLAIN|SHOW|DESCRIBE|DESC|TABLE|VALUES|\\d)", re.I)


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
                config[key].extend(str(item) for item in value)
    return config


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
# Bash
# ---------------------------------------------------------------------------

RM_RECURSIVE = re.compile(
    r"(?:^|[;&|(\n]\s*|\bsudo\s+|\bxargs\s+(?:-[a-zA-Z0-9]+\s+)*)rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*|--recursive)(?:\s+-[a-zA-Z-]+)*\s+([^;&|)\n]*)",
    re.M,
)
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


def check_rm(cmd: str) -> None:
    for match in RM_RECURSIVE.finditer(cmd):
        args = match.group(1).split()
        for arg in args:
            if arg.startswith("-"):
                continue
            if DANGEROUS_RM_TARGET.match(arg):
                deny(
                    f"rm ricorsivo su un bersaglio non sicuro: {arg!r}. "
                    "Vietati: variabili ($HOME, $DIR...), ~, radici di sistema, '.', '..', glob nascosti (.*, .[!.]*) e '*'. "
                    "Usa un path letterale e relativo al progetto, oppure chiedi all'utente di cancellare a mano. "
                    "(guardrail: filesystem-shell-segreti.md)"
                )


SECRET_FILE = re.compile(
    r"(?:[\w./~-]*/)?(?:\.env(?:\.[\w-]+)?|\.secrets|\.netrc|\.pgpass|\.my\.cnf"
    r"|[\w.-]+\.(?:pem|key|p12|pfx)|id_(?:rsa|ed25519|ecdsa|dsa))"
)
# Comandi che stampano o trasformano il contenuto di un file: il segreto finisce
# nella trascrizione della sessione, che resta su disco.
SECRET_READERS = re.compile(
    r"\b(cat|bat|tac|less|more|head|tail|nl|od|xxd|strings|grep|egrep|fgrep|rg|ag|awk|sed|cut|base64|jq|tee)\b"
)
SECRET_SOURCERS = re.compile(r"(?:^|[;&|]\s*)(?:source|\.)\s+\S")


def check_secret_reads(text: str) -> None:
    """Blocca `cat .env` e affini: permissions.deny copre il tool Read, non la shell."""
    for segment in re.split(r"[;&|\n]+|\$\(|\)", text):
        if not segment.strip():
            continue
        found = [
            m.group(0) for m in SECRET_FILE.finditer(segment)
            if not SECRET_TEMPLATE.search(m.group(0))
        ]
        if not found:
            continue
        if SECRET_READERS.search(segment):
            deny(
                f"lettura di un file di segreti da shell ({found[0]}): il contenuto finirebbe "
                "nella trascrizione, che resta su disco. Per il nome di una variabile leggi "
                ".env.example; per il valore, chiedilo all'utente. (guardrail: filesystem-shell-segreti.md)"
            )
        if SECRET_SOURCERS.search(segment):
            ask(
                f"source di un file di segreti ({found[0]}): carica credenziali nell'ambiente "
                "del comando. Conferma che è voluto?"
            )


def check_bash(cmd: str, config: dict) -> None:
    text = re.sub(r"\\\n", " ", cmd)

    if matches_any(config["allow_commands"], text):
        return

    check_secret_reads(text)

    if (pattern := matches_any(config["deny_commands"], text)):
        deny(f"comando vietato dalla configurazione del progetto (.guardrail.json, regola {pattern!r}).")

    check_rm(text)

    # Distruzione di sistema o supply chain
    if re.search(r"\bsudo\s+rm\b", text):
        deny("sudo rm: cancellazioni con privilegi non passano dall'agente.")
    if re.search(r"\b(mkfs(\.\w+)?|dd\s+[^|;]*of=/dev/|wsl(\.exe)?\s+--unregister)\b", text):
        deny("comando che distrugge un filesystem o una distro.")
    if re.search(r"\bchmod\s+(-R\s+)?[0-7]*777\b", text):
        deny("chmod 777: permessi aperti a tutti, mai.")
    if re.search(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", text):
        deny("curl|sh: esecuzione di codice scaricato al volo. Scarica il file, leggilo, poi esegui.")

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
    if re.search(r"\bgit\b[^;|]*\bclean\b[^;|]*\s-[a-zA-Z]*[xX]", text):
        deny("git clean -x/-X: cancella anche i file ignorati, cioè .env e le credenziali locali.")
    if re.search(r"\bgit\b[^;|]*\bclean\b[^;|]*\s-[a-zA-Z]*f", text):
        ask("git clean -f: cancella file non tracciati, non recuperabili. Conferma?")
    if re.search(r"\bgit\b[^;|]*\breset\s+--hard\b", text):
        ask("git reset --hard: scarta modifiche non committate. Conferma?")
    if re.search(r"\bgit\b[^;|]*\b(checkout|restore)\s+(--\s+)?\.(\s|$)", text):
        ask("git checkout/restore .: scarta tutte le modifiche locali. Conferma?")

    # Laravel: comandi che distruggono lo schema
    if re.search(r"\bartisan\s+(migrate:fresh|db:wipe|migrate:reset)\b", text):
        deny("artisan migrate:fresh / db:wipe / migrate:reset: droppano le tabelle, comprese quelle che le migration non ricreano. Solo a mano, su un DB usa e getta. (guardrail: database.md)")
    if re.search(r"\bartisan\s+migrate:rollback\b", text):
        ask("artisan migrate:rollback: annulla migration già applicate. Su quale DB? Conferma.")
    if re.search(r"\bartisan\s+db:seed\b[^;|]*RolePermissionSeeder", text):
        ask("RolePermissionSeeder sovrascrive le assegnazioni manuali di ruoli e permessi. Conferma che NON è un DB con dati reali.")

    # Docker: volumi = database
    if re.search(r"\bdocker\s+(system\s+prune|volume\s+(rm|prune)|compose\s+down\b[^;|]*(-v\b|--volumes))", text):
        ask("Docker: questa operazione cancella volumi, cioè database locali. Conferma?")

    # SQL da riga di comando
    check_sql_cli(text, config)

    if (pattern := matches_any(config["ask_commands"], text)):
        ask(f"comando che richiede conferma per la configurazione del progetto (regola {pattern!r}).")


SQL_CLI = re.compile(r"\b(psql|mysql|mariadb|sqlcmd|pg_restore|dropdb|createdb|mongosh|redis-cli)\b")


def check_sql_cli(text: str, config: dict) -> None:
    if not SQL_CLI.search(text):
        return
    is_prod = matches_any(config["prod_patterns"], text) is not None

    if re.search(r"\bdropdb\b", text):
        deny("dropdb: cancella un database intero.") if is_prod else ask("dropdb su un DB non di produzione: conferma?")
    if re.search(r"\bpg_restore\b[^;|]*(--clean|-c\b)", text) and is_prod:
        deny("pg_restore --clean verso produzione: droppa gli oggetti prima di ricrearli.")
    if re.search(r"\bredis-cli\b[^;|]*\b(FLUSHALL|FLUSHDB)\b", text, re.I):
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
# MCP (server SQL e affini)
# ---------------------------------------------------------------------------

MCP_TOOL = re.compile(r"^mcp__(?P<server>[^_].*?)__(?P<tool>[^_].*)$")


def extract_sql(tool_input: dict) -> str:
    for key in ("sql", "query", "statement", "command", "text"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def check_mcp(tool_name: str, tool_input: dict, config: dict) -> None:
    match = MCP_TOOL.match(tool_name)
    if not match:
        return
    server, tool = match.group("server"), match.group("tool")
    sql = extract_sql(tool_input)
    if not sql:
        return
    if not re.search(r"(query|sql|execute|run|statement)", tool, re.I):
        return

    is_prod = server in config["prod_mcp_servers"] or matches_any(config["prod_patterns"], server) is not None
    is_shared = server in config["ask_mcp_servers"]

    statements = [s for s in re.split(r";", re.sub(r"--[^\n]*", "", sql)) if s.strip()]
    writes = [s for s in statements if WRITE_SQL.search(s) or not READ_ONLY_START.match(s)]
    if not writes:
        return

    if is_prod:
        deny(f"scrittura SQL sul server MCP {server!r}, che è PRODUZIONE. In produzione l'agente legge soltanto. (guardrail: database.md)")
    check_unbounded_writes(sql)
    if is_shared:
        ask(f"scrittura SQL sul server MCP {server!r}, condiviso con altre persone. Conferma?")


# ---------------------------------------------------------------------------
# Write / Edit
# ---------------------------------------------------------------------------

SECRET_NAME = re.compile(r"^(\.env(\..+)?|\.secrets|.*\.pem|.*\.key|id_(rsa|ed25519|ecdsa|dsa)(\.pub)?|\.netrc|\.pgpass|\.my\.cnf)$")
SECRET_TEMPLATE = re.compile(r"\.(example|sample|template|dist)$")


def target_path(tool_input: dict) -> Path | None:
    raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path")
    if not isinstance(raw, str) or not raw:
        return None
    return Path(os.path.expanduser(raw))


def is_secret_file(name: str) -> bool:
    return bool(SECRET_NAME.match(name)) and not SECRET_TEMPLATE.search(name)


def check_read(tool_input: dict) -> None:
    """Le letture di segreti non dipendono più da permissions.deny nelle settings."""
    path = target_path(tool_input)
    if path is None:
        return
    if any(part == ".ssh" for part in path.parts):
        deny(f"lettura dentro ~/.ssh ({path}): chiavi e configurazione SSH non passano dall'agente.")
    if is_secret_file(path.name):
        deny(
            f"lettura di un file di segreti ({path}): il contenuto finirebbe nella trascrizione, "
            "che resta su disco. Per il nome di una variabile leggi .env.example; per il valore, "
            "chiedilo all'utente. (guardrail: filesystem-shell-segreti.md)"
        )


def check_write(tool_input: dict) -> None:
    path = target_path(tool_input)
    if path is None:
        return
    raw = str(path)
    name = path.name
    home = Path.home()

    # La configurazione di guardrail non si modifica da soli: sarebbe il modo
    # elegante di aggirare un blocco (RULES-CORE.md, regola 8).
    if name == ".guardrail.json":
        ask(
            "modifica di .guardrail.json: cambia le regole di guardrail che ti vincolano. "
            "Decide l'utente, e il file va committato con la motivazione. (guardrail: RULES-CORE.md 8)"
        )
    try:
        relative_home = path.resolve().relative_to(home)
    except (ValueError, OSError):
        relative_home = None
    if relative_home is not None and relative_home.parts[:1] == (".claude",) and name in (
        "settings.json",
        "settings.local.json",
    ):
        ask(
            "modifica delle impostazioni di Claude Code: tocca permessi, hook e sandbox "
            "dell'utente. Mostra il cambiamento e fallo approvare."
        )

    if any(part == ".ssh" for part in path.parts) or (SECRET_NAME.match(name) and re.search(r"id_|\.pem$|\.key$", name)):
        deny(f"scrittura su una chiave privata o in ~/.ssh ({raw}). Mai dall'agente.")
    if str(path).startswith("/etc/") or str(path).startswith("/usr/"):
        deny(f"scrittura su un file di sistema ({raw}).")
    if SECRET_NAME.match(name) and not SECRET_TEMPLATE.search(name):
        ask(f"scrittura su un file di segreti ({raw}). Conferma che è voluto e che il file è gitignorato.")
    if relative_home is not None and len(relative_home.parts) == 1 and relative_home.parts[0].startswith("."):
        ask(f"scrittura su un dotfile della home ({raw}): cambia l'ambiente dell'utente. Conferma?")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def decide(payload: dict) -> None:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    config = load_config(payload.get("cwd", ""))

    if tool == "Bash":
        check_bash(str(tool_input.get("command", "")), config)
    elif tool == "Read":
        check_read(tool_input)
    elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        check_write(tool_input)
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

    if os.environ.get("GUARDRAIL_DISABLE") == "1":
        log_decision(payload, "disabled", "GUARDRAIL_DISABLE=1")
        return 0

    try:
        decide(payload)
    except Decision as decision:
        log_decision(payload, decision.verdict, decision.reason)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.verdict,
                "permissionDecisionReason": f"[guardrail] {decision.reason}",
            }
        }))
        return 0
    except Exception as exc:  # noqa: BLE001 — un bug del guard non deve mai bloccare il lavoro
        print(f"[guardrail] errore interno, tool lasciato passare: {exc}", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
