# guardrail

Regole aziendali per gli agenti di sviluppo, in due forme: **prosa** che ogni
agente legge (`AGENTS.md`, `services/`) e **hook** che su Claude Code bloccano o
mettono in conferma i comandi pericolosi (`hooks/`). Nato dall'incidente del
2026-09-11, in cui un subagent in modalità auto ha cancellato la home di uno
sviluppatore mentre "studiava" uno script di deploy.

## Installazione su Claude Code (consigliata)

Il repo è insieme un plugin e il proprio marketplace:

```
/plugin marketplace add 7hemas7er/guardrail
/plugin install guardrail@7hemas7er-guardrail
```

Da un clone locale, per provarlo o svilupparlo:

```
/plugin marketplace add /percorso/di/guardrail
/plugin install guardrail@7hemas7er-guardrail
```

Cosa ottieni:

- a ogni sessione, le regole essenziali (`RULES-CORE.md`) entrano nel contesto;
- ogni comando Bash, scrittura di file e query MCP passa dal hook `guard.py`:
  esito `allow`, `ask` (conferma anche in modalità auto) o `deny` (blocco con
  spiegazione all'agente);
- la skill `guardrail`, che carica le regole del servizio interessato.

Aggiungi poi le impostazioni consigliate al tuo `~/.claude/settings.json`
(vedi `examples/settings.example.json`): negano la lettura di `.env*` e
accendono il sandbox. Il hook non può farlo al posto tuo.

## Configurazione per progetto

Metti `.guardrail.json` nella root del repo. Esempio completo in
`examples/esempio.guardrail.json`:

```json
{
  "prod_mcp_servers": ["postgres", "telemetria"],
  "ask_mcp_servers": ["postgres-test"],
  "prod_patterns": ["db-produzione\\.esempio\\.com", "\\bappdb\\b(?!_)"],
  "deny_commands": ["scripts/deploy/(promote-to-production|rollback-production)\\.sh"],
  "ask_commands": ["scripts/deploy/containerapp/(promote-to-production|rollback-production)\\.sh", "build-and-push(-fast)?\\.sh[^;|]*--skip-tests"]
}
```

| Chiave | Significato |
|---|---|
| `prod_mcp_servers` | nomi esatti di server MCP che sono produzione: scritture bloccate |
| `ask_mcp_servers` | server condivisi: scritture in conferma |
| `prod_patterns` | regex che marcano come produzione un comando `psql`/`mysql`/`pg_restore` |
| `deny_commands` | regex sul comando Bash: blocco secco |
| `ask_commands` | regex sul comando Bash: conferma |
| `allow_commands` | regex che esentano un comando da tutte le regole (usare con parsimonia, motivare nel commit) |

Le liste si sommano con `~/.guardrail.json`, se esiste. `GUARDRAIL_CONFIG=<file>`
sostituisce entrambi (usato dai test). `GUARDRAIL_DISABLE=1` spegne il hook: la
scelta viene registrata nel log.

## Log

Ogni `deny` e `ask` finisce in `~/.claude/guardrail.log.jsonl` con tool, cwd,
sessione e motivo. Serve a capire cosa gli agenti provano a fare, e a correggere
i falsi positivi con una regola migliore invece che con `GUARDRAIL_DISABLE`.

## Altri strumenti (Copilot, Cursor, Codex, Gemini)

Clona il repo accanto ai progetti e importa `AGENTS.md` nel file di istruzioni
dello strumento. Solo prosa: nessun blocco automatico.

## Sviluppo

```
python3 tests/run.py        # deve restare verde
```

I casi sono in `tests/cases.jsonl`: uno per riga, con l'esito atteso. Una regola
nuova arriva con il suo caso e con il motivo (l'incidente o il quasi-incidente)
nel file di servizio corrispondente.

## Struttura

```
AGENTS.md                 indice e regole per ogni agente
RULES-CORE.md             le 9 regole essenziali, iniettate a ogni sessione
CLAUDE.md                 importa i due file sopra per Claude Code
services/                 regole per tipologia di servizio
hooks/guard.py            hook PreToolUse: allow / ask / deny
hooks/session-start.py    hook SessionStart: inietta RULES-CORE.md
hooks/hooks.json          registrazione dei hook nel plugin
skills/guardrail/         skill che carica il file di servizio giusto
examples/                 .guardrail.json d'esempio, settings consigliati
tests/                    casi e runner
.claude-plugin/           manifest del plugin e del marketplace
```
