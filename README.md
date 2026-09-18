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
- ogni comando Bash, lettura e scrittura di file e query MCP passa dal hook
  `guard.py`: esito `allow`, `ask` (conferma anche in modalità auto) o `deny`
  (blocco con spiegazione all'agente);
- la skill `guardrail`, che carica le regole del servizio interessato;
- quattro comandi: `/guardrail:check` (il hook è davvero attivo?),
  `/guardrail:setup` (configura il repo corrente), `/guardrail:log` (cosa è stato
  bloccato, e perché), `/guardrail:approve` (approva uno script e ne registra
  l'impronta).

Subito dopo l'installazione, in una sessione nuova:

```
/guardrail:check
```

Lancia tre azioni innocue che il hook deve fermare e ti dice se lo ha fatto. Un
hook che non parte non fa rumore: senza questa verifica non sai di non essere
protetto.

Poi, nel primo progetto che lo richiede:

```
/guardrail:setup
```

L'agente guarda `.mcp.json`, gli script di deploy e la CI, deduce quali server e
host sono produzione, e ti propone il `.guardrail.json` da committare. Non scrive
niente senza mostrartelo, e la scrittura passa comunque da una conferma.

Resta una sola cosa da fare a mano, una volta per macchina: accendere il sandbox
in `~/.claude/settings.json` (vedi `examples/settings.example.json`). È l'unica
protezione che nessun hook può attivare al posto tuo. Se manca, guardrail te lo
segnala all'inizio della prima sessione.

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
| `prod_patterns` | regex che marcano come produzione un comando `psql`/`mysql`/`pg_restore`, un nome di server MCP, o i parametri di una chiamata MCP (es. il resource group di Azure) |
| `deny_commands` | regex sul comando Bash: blocco secco |
| `ask_commands` | regex sul comando Bash: conferma |
| `allow_commands` | regex che esentano un comando da tutte le regole (usare con parsimonia, motivare nel commit) |
| `allow_scripts` | script già letti e approvati: `{"path": regex, "sha256": impronta}`. Esentano **solo** la scansione del contenuto, e solo finché il contenuto resta quello |

### Script già letti: `allow_scripts`

Ogni script invocato viene letto dal hook, e se contiene un comando che sarebbe
bloccato l'esito è una conferma. Su uno script di build lanciato venti volte al
giorno quella conferma diventa rumore, e il rumore insegna ad approvare senza
leggere. `allow_scripts` la toglie, ma lega l'esenzione al **contenuto**:

```json
"allow_scripts": [
  {"path": "scripts/build\\.sh", "sha256": "625f88e4…"}
]
```

```
/guardrail:approve scripts/build.sh    # legge, mostra, registra l'impronta
sha256sum scripts/build.sh             # se preferisci farlo a mano
```

Senza argomenti, `/guardrail:approve` controlla le approvazioni esistenti e dice
quali impronte sono scadute, incomplete o orfane.

Se lo script cambia, l'impronta non corrisponde più: torna la conferma, con un
avviso che dice che il contenuto non è quello approvato. Una voce senza `sha256`
non esenta niente — «mi fido di questo file per sempre» non è una cosa che questo
repo sa dire. `deny_commands` vince comunque: un comando vietato resta vietato
anche dentro uno script approvato, e l'esenzione vale solo per la scansione del
contenuto, non per il comando che lo lancia (`rm -rf "$X" && bash build.sh`
resta bloccato).

Le liste si sommano con `~/.guardrail.json`, se esiste. `GUARDRAIL_CONFIG=<file>`
sostituisce entrambi (usato dai test). `GUARDRAIL_DISABLE=1` spegne il hook: la
scelta viene registrata nel log.

## Log

Ogni `deny` e `ask` finisce in `~/.claude/guardrail.log.jsonl` con tool, cwd,
sessione e motivo. Serve a capire cosa gli agenti provano a fare, e a correggere
i falsi positivi con una regola migliore invece che con `GUARDRAIL_DISABLE`.
`/guardrail:log` lo riassume per regola e segnala i tentativi di aggiramento
(stessa sessione, stessa azione riprovata in forma diversa).

## Altri strumenti (Copilot, Cursor, Codex, Gemini)

Clona il repo accanto ai progetti e importa `AGENTS.md` nel file di istruzioni
dello strumento. Solo prosa: nessun blocco automatico.

## Sviluppo

```
python3 tests/run.py                  # casi del hook guard.py, deve restare verde
python3 tests/test_session_start.py   # regole iniettate e avvisi una tantum
```

I casi sono in `tests/cases.jsonl`: uno per riga, con l'esito atteso. Una regola
nuova arriva con il suo caso e con il motivo (l'incidente o il quasi-incidente)
nel file di servizio corrispondente. Un caso può aggiungere
`"config": ".guardrail.json"` per essere valutato con la configurazione di questo
repo invece della fixture: è così che si verificano le proprie `deny_commands`,
che altrimenti bloccherebbero il comando stesso che prova a verificarle. Gli script in `tests/fixtures/` servono ai
casi che verificano la scansione degli script invocati: non vanno eseguiti.

Per scrivere file che *citano* comandi pericolosi (documentazione, casi di test)
usa gli strumenti di modifica file dell'agente: un heredoc che alimenta un
interprete (`bash <<EOF`) viene letto come comandi, uno che scrive su file
(`cat > x <<EOF`) come dati.

**Il hook che ti blocca mentre sviluppi è quello installato, non quello che stai
scrivendo.** Claude Code esegue la copia in
`~/.claude/plugins/cache/<marketplace>/guardrail/<versione>/hooks/guard.py`: una
correzione nel repo non ha effetto finché non aggiorni il plugin, e il codice del
plugin non si modifica a mano. Quindi si lavora sotto la versione precedente —
comodo per accorgersi dei falsi positivi, scomodo quando è proprio quello che
stai correggendo a bloccarti. In quel caso: usa `Edit`/`Write` sul repo, e
verifica con `python3 tests/run.py`, che gira sul `guard.py` locale.

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
commands/check.md         /guardrail:check — il hook è attivo?
commands/setup.md         /guardrail:setup — configura il repo corrente
commands/log.md           /guardrail:log — riassume i blocchi recenti
commands/approve.md       /guardrail:approve — approva uno script, registra l'impronta
examples/                 .guardrail.json d'esempio, settings consigliati,
                          clone-prod-to-local.sh di riferimento
tests/                    casi, runner, fixture di script, test di session-start
.claude-plugin/           manifest del plugin e del marketplace
```
