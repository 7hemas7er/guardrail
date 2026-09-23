#!/usr/bin/env python3
"""Hook SessionStart: inietta nel contesto dell'agente le regole essenziali.

Stampa su stdout RULES-CORE.md (breve, ~30 righe): Claude Code aggiunge lo stdout
dei hook SessionStart al contesto della sessione. Le regole complete per servizio
stanno in services/ e si caricano con la skill `guardrail`.

In coda, una sola volta per progetto e per tipo di avviso, segnala quello che il
hook non può fare da solo: il sandbox spento, o un progetto con superficie di
produzione ma senza .guardrail.json. Lo stato sta in ~/.claude/guardrail.state.json,
così l'avviso non diventa rumore a ogni sessione.
"""
import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
core = root / "RULES-CORE.md"
try:
    text = core.read_text(encoding="utf-8").strip()
except OSError:
    sys.exit(0)

print("<!-- guardrail: regole essenziali, iniettate a ogni sessione -->")
print(text)
print(f"<!-- regole complete per servizio: {root / 'services'} (skill: guardrail) -->")

# Con la mappa attiva il modello deve sapere che i segnaposto sono nomi veri a tutti
# gli effetti, altrimenti prova a "correggerli". Si elencano solo i segnaposto.
try:
    import mask

    segnaposto = sorted({finto for _, finto in mask.load_pairs()})
except Exception:  # noqa: BLE001 — una mappa rotta la segnala guard.py al primo comando
    segnaposto = []
if segnaposto:
    print(
        "\n<!-- guardrail: mascheramento nomi di rete attivo -->\n"
        f"Alcuni nomi di rete sono mascherati: nell'output di Bash compaiono come {', '.join(segnaposto)}. "
        "Usali nei comandi come se fossero i nomi veri: guardrail li converte prima dell'esecuzione. "
        "Non cercare di ricostruire gli originali. Il tool Read è negato sui file che li contengono: "
        "leggili via Bash (cat, sed -n)."
    )

STATE = Path.home() / ".claude" / "guardrail.state.json"


def read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def cwd_from_stdin() -> Path:
    if sys.stdin.isatty():
        return Path(os.getcwd())
    try:
        payload = json.load(sys.stdin)
        return Path(payload.get("cwd") or os.getcwd())
    except (ValueError, OSError):
        return Path(os.getcwd())


def project_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return start


def avvisi(cwd: Path) -> list[tuple[str, str]]:
    """[(chiave di stato, testo)] — solo ciò che il hook non può fare da sé."""
    out: list[tuple[str, str]] = []

    settings = read_json(Path.home() / ".claude" / "settings.json")
    if not (settings.get("sandbox") or {}).get("enabled"):
        out.append((
            "sandbox",
            "il sandbox dei comandi Bash è spento in ~/.claude/settings.json "
            '(`"sandbox": {"enabled": true, "autoAllowBashIfSandboxed": true}`). '
            "È l'unica protezione che nessun hook può attivare al posto dell'utente.",
        ))

    progetto = project_root(cwd)
    ha_config = any((candidate / ".guardrail.json").is_file() for candidate in [progetto, *progetto.parents])
    indizi = [
        nome for nome in (".mcp.json", "docker-compose.yml", "docker-compose.yaml", "scripts/deploy")
        if (progetto / nome).exists()
    ]
    if not ha_config and indizi:
        out.append((
            f"config:{progetto}",
            f"questo progetto ha {', '.join(indizi)} ma nessun .guardrail.json: guardrail non sa "
            "quali server MCP e quali host sono produzione, quindi riconosce come tali solo quelli "
            "che contengono 'prod' o 'live' nel nome. Si configura con /guardrail:setup.",
        ))
    return out


try:
    stato = read_json(STATE)
    visti = stato.get("avvisi_mostrati") if isinstance(stato.get("avvisi_mostrati"), list) else []
    nuovi = [(chiave, testo) for chiave, testo in avvisi(cwd_from_stdin()) if chiave not in visti]
    if nuovi:
        print("\n<!-- guardrail: da segnalare all'utente nel primo messaggio, una riga per punto -->")
        for _, testo in nuovi:
            print(f"- {testo}")
        STATE.parent.mkdir(parents=True, exist_ok=True)
        stato["avvisi_mostrati"] = visti + [chiave for chiave, _ in nuovi]
        STATE.write_text(json.dumps(stato, ensure_ascii=False, indent=2), encoding="utf-8")
except Exception:  # noqa: BLE001 — un avviso non deve mai rompere l'avvio di sessione
    pass
