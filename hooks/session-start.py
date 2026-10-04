#!/usr/bin/env python3
"""Hook SessionStart: inietta nel contesto dell'agente le regole essenziali.

Guardrail vale solo nei progetti che l'hanno scelto, con un `.guardrail.json` (vedi
`guard.attivo`). Lì stampa su stdout RULES-CORE.md (breve, ~30 righe): Claude Code
aggiunge lo stdout dei hook SessionStart al contesto della sessione. Le regole
complete per servizio stanno in services/ e si caricano con la skill `guardrail`.

Altrove non inietta niente, e la prima volta che una sessione parte in quella
cartella lo dice: guardrail non è attivo, e come si accende. La scelta è
dell'utente; l'avviso non si ripete, così una cartella lasciata spenta di
proposito non diventa rumore.

In coda, una sola volta per tipo, segnala anche quello che il hook non può fare da
solo: il sandbox spento. Lo stato sta in ~/.claude/guardrail.state.json.
"""
import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
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
    except (ValueError, OSError, AttributeError):
        return Path(os.getcwd())


def project_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return start


def progetto_attivo(cwd: Path) -> bool:
    try:
        import guard

        return guard.attivo(str(cwd))
    except Exception:  # noqa: BLE001 — nel dubbio le regole entrano: costano poco
        return True


cwd = cwd_from_stdin()
attivo = progetto_attivo(cwd)

if attivo:
    try:
        text = (root / "RULES-CORE.md").read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    if text:
        print("<!-- guardrail: regole essenziali, iniettate a ogni sessione -->")
        print(text)
        print(f"<!-- regole complete per servizio: {root / 'services'} (skill: guardrail) -->")

# Con la mappa attiva il modello deve sapere che i segnaposto valgono come termini
# veri, altrimenti prova a "correggerli". Si elencano solo i segnaposto. Vale anche
# nei progetti dove guardrail è spento: il mascheramento segue la mappa.
try:
    import mask

    segnaposto = sorted({finto for _, finto in mask.load_pairs()})
except Exception:  # noqa: BLE001 — una mappa rotta la segnala guard.py al primo tool
    segnaposto = []
if segnaposto:
    print(
        "\n<!-- guardrail: mascheramento dei termini riservati attivo -->\n"
        f"Alcuni termini riservati sono mascherati: in ogni risultato di tool (comandi, file letti, "
        f"ricerche, MCP) compaiono come {', '.join(segnaposto)}. Trattali come i termini veri e usali "
        "così nei comandi Bash, nei percorsi, nei pattern di Grep/Glob e in Write: guardrail li "
        "converte prima dell'esecuzione. Non cercare di ricostruire gli originali, e non guardare i "
        "byte (od, xxd, base64) per capire perché un testo non corrisponde. Il tool Edit non "
        "riconosce i segnaposto: per modificare un testo che ne contiene usa sed via Bash. PDF, "
        "documenti Office e archivi non si leggono con Read: convertili via Bash (pdftotext file -, "
        "unzip -p). Per una risorsa privata usa curl via Bash, non WebFetch."
    )
    # Il git status e i commit recenti entrano nel contesto prima di qualunque hook.
    # Si ripete a ogni sessione finché resta così: è una fuga, non un consiglio.
    impostazioni = read_json(Path.home() / ".claude" / "settings.json")
    if (
        os.environ.get("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS") != "1"
        and impostazioni.get("includeGitInstructions") is not False
    ):
        print(
            "\n<!-- guardrail: da segnalare all'utente nel primo messaggio -->\n"
            "- il mascheramento è attivo, ma Claude Code mette nel contesto il git status e i commit "
            "recenti prima di qualunque hook: nomi di file e messaggi di commit arrivano al modello "
            'in chiaro. Si toglie con `"includeGitInstructions": false` in ~/.claude/settings.json.'
        )


def avvisi(cwd: Path) -> list[tuple[str, str]]:
    """[(chiave di stato, testo)] — solo ciò che il hook non può fare da sé."""
    progetto = project_root(cwd)
    if not attivo:
        indizi = [
            nome for nome in (".mcp.json", "docker-compose.yml", "docker-compose.yaml", "scripts/deploy")
            if (progetto / nome).exists()
        ]
        superficie = f" Qui c'è superficie di produzione: {', '.join(indizi)}." if indizi else ""
        return [(
            f"inattivo:{progetto}",
            f"guardrail non è attivo in questa cartella ({progetto}): manca un .guardrail.json, quindi "
            "comandi distruttivi, scritture in produzione e letture di segreti non vengono controllati."
            f"{superficie} Per attivarlo: /guardrail:setup, che propone la configurazione, oppure un "
            ".guardrail.json con `{}` nella root del progetto. Se lo lasci spento, l'avviso non si "
            "ripete per questa cartella.",
        )]

    settings = read_json(Path.home() / ".claude" / "settings.json")
    if not (settings.get("sandbox") or {}).get("enabled"):
        return [(
            "sandbox",
            "il sandbox dei comandi Bash è spento in ~/.claude/settings.json "
            '(`"sandbox": {"enabled": true, "autoAllowBashIfSandboxed": true}`). '
            "È l'unica protezione che nessun hook può attivare al posto dell'utente.",
        )]
    return []


try:
    stato = read_json(STATE)
    visti = stato.get("avvisi_mostrati") if isinstance(stato.get("avvisi_mostrati"), list) else []
    nuovi = [(chiave, testo) for chiave, testo in avvisi(cwd) if chiave not in visti]
    if nuovi:
        print("\n<!-- guardrail: da segnalare all'utente nel primo messaggio, una riga per punto -->")
        for _, testo in nuovi:
            print(f"- {testo}")
        STATE.parent.mkdir(parents=True, exist_ok=True)
        stato["avvisi_mostrati"] = visti + [chiave for chiave, _ in nuovi]
        STATE.write_text(json.dumps(stato, ensure_ascii=False, indent=2), encoding="utf-8")
except Exception:  # noqa: BLE001 — un avviso non deve mai rompere l'avvio di sessione
    pass
