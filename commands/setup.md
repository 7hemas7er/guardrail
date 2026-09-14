---
description: Configura guardrail per questo progetto — deduce cosa è produzione, propone .guardrail.json e verifica le impostazioni di Claude Code
---

# Configurare guardrail per questo progetto

Il tuo compito è produrre un `.guardrail.json` corretto per il repo corrente e
segnalare le impostazioni mancanti. **Non scrivi niente senza mostrarlo prima.**

## 1. Raccogli le prove

Guarda, se esistono:

- `.mcp.json` e `~/.claude.json` → nomi dei server MCP e host a cui puntano
- `docker-compose*.yml`, `*.tf`, `.github/workflows/`, `azure-pipelines.yml`
- `scripts/deploy/`, `Makefile`, `package.json` (script di deploy, promote, rollback)
- `config/database.php`, `config/*.yml`, `.env.example` → **nomi** delle connessioni
- `git remote -v`, `README.md` → di che progetto si tratta

**Regola assoluta durante la raccolta:** non stampare mai il contenuto di
`.mcp.json`, `.env*` o di qualunque file che possa contenere credenziali. Estrai
solo le chiavi:

```
jq -r '.mcpServers | keys[]' .mcp.json
jq -r '.mcpServers | to_entries[] | "\(.key): \(.value.command // .value.url)"' .mcp.json | sed -E 's#(password|pwd|token|key)=[^ &"]*#\1=***#gi'
```

Se un comando ti viene bloccato dal hook, è il comportamento atteso: non cercare
una via alternativa, riporta il blocco e vai avanti con le altre prove.

## 2. Classifica

Per ogni server MCP e per ogni host trovato, decidi: produzione, condiviso
(test/staging usato da altri), o usa e getta. Il criterio non è il nome: un
server che si chiama `postgres` può benissimo essere la produzione. Usa l'host,
il database, il contesto degli script di deploy.

Nel dubbio, classifica come produzione: un falso positivo costa una conferma in
più, un falso negativo costa un incidente.

## 3. Proponi

Mostra all'utente una tabella — voce, valore, perché l'hai classificata così —
e poi il `.guardrail.json` completo:

```json
{
  "prod_mcp_servers": [],
  "ask_mcp_servers": [],
  "prod_patterns": [],
  "deny_commands": [],
  "ask_commands": []
}
```

Chiedi conferma esplicita prima di scrivere. La scrittura farà scattare una
richiesta di conferma del hook: è voluto, è la garanzia che questo file non
cambi senza che l'utente lo veda.

**Non proporre mai `allow_commands`.** È l'eccezione che disattiva le regole: la
aggiunge un umano, motivandola nel messaggio di commit.

## 4. Verifica le impostazioni di Claude Code

Leggi `~/.claude/settings.json` e controlla che ci sia:

```json
"sandbox": { "enabled": true, "autoAllowBashIfSandboxed": true }
```

Il sandbox è l'unica protezione che nessun hook può attivare al posto
dell'utente. Se manca, mostra la riga da aggiungere e spiega cosa cambia: i
comandi Bash girano isolati dal resto del filesystem. Non modificare il file
senza che l'utente te lo chieda.

Le letture di `.env` e delle chiavi sono già bloccate dal hook, sia via `Read`
che via shell: non servono più voci in `permissions.deny`.

## 5. Chiudi

Ricorda all'utente di committare `.guardrail.json`: è parte del repo, va rivisto
come si rivede il codice, e vale per chiunque ci lavori — persone e agenti.
