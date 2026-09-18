# Guardrail — regole per gli agenti di sviluppo

Questo repo contiene le regole che ogni agente (Claude Code, Copilot, Cursor,
Codex, Gemini CLI) deve rispettare quando lavora sui progetti dell'organizzazione.
Nasce da un incidente reale: l'11 settembre 2026 un subagent in modalità auto,
incaricato di *leggere* uno script di deploy con `--delete`, ha cancellato tutti i
file di configurazione della home dello sviluppatore. Le regole in prosa non lo
avrebbero fermato: per questo il repo distribuisce anche hook che bloccano.

## Come usarlo

- **Claude Code**: installa il plugin (vedi README). Le regole essenziali entrano
  nel contesto a ogni sessione; i comandi pericolosi vengono bloccati o messi in
  conferma; la skill `guardrail` carica le regole del servizio interessato;
  `/guardrail:check` verifica che il hook sia attivo, `/guardrail:setup`
  configura il `.guardrail.json` del repo corrente, `/guardrail:log` riassume
  cosa è stato bloccato, `/guardrail:approve` approva uno script che si lancia di
  continuo e ne registra l'impronta.
- **Altri strumenti**: clona il repo accanto ai progetti e importa `AGENTS.md`
  nel file di istruzioni del tuo strumento. Nessun blocco automatico: valgono
  solo le regole scritte.

## Le regole essenziali

Sono in [`RULES-CORE.md`](RULES-CORE.md). Valgono sempre, in ogni repo. Leggile
per prime.

## Regole per tipologia di servizio

Leggi il file del servizio che stai per toccare, **prima** di agire.

| Servizio | File | Quando leggerlo |
|---|---|---|
| Database | [`services/database.md`](services/database.md) | query, migration, seed, dump, MCP SQL |
| Deploy e infrastruttura | [`services/deploy-infrastruttura.md`](services/deploy-infrastruttura.md) | build, push immagini, promozioni, FTP, Azure, container |
| Filesystem, shell, segreti | [`services/filesystem-shell-segreti.md`](services/filesystem-shell-segreti.md) | rm, pulizie, script con variabili, `.env`, chiavi, home |
| Git, GitHub, dati personali | [`services/git-github-dati-personali.md`](services/git-github-dati-personali.md) | commit, push, PR, issue, anagrafiche, GPS, audit |

## Cosa viene bloccato automaticamente (solo Claude Code)

Ogni file di servizio distingue le **regole di condotta** (prosa) da ciò che il
hook `hooks/guard.py` fa rispettare: `BLOCCO` (il tool non parte) o `CONFERMA`
(qualcuno deve approvare). ⚠️ In modalità auto la `CONFERMA` la concede l'agente,
non l'utente: se una decisione deve essere di un umano, la regola va scritta come
`BLOCCO`, che è l'unico esito non scavalcabile. Il blocco non è un ostacolo
da aggirare: se scatta, ferma il lavoro e spiega all'utente.

## Configurazione per progetto

Un file `.guardrail.json` nella root del repo dice al hook quali server MCP sono
produzione, quali pattern identificano la produzione nei comandi e quali comandi
del progetto sono vietati. Esempio in [`examples/esempio.guardrail.json`](examples/esempio.guardrail.json).

## Contribuire

Una regola entra qui se ha impedito, o avrebbe impedito, un danno reale. Ogni
regola cita il caso che l'ha motivata. Le modifiche ai hook passano da
`tests/run.py`, che deve restare verde.
