---
description: Verifica che guardrail sia davvero attivo — lancia comandi innocui che il hook deve bloccare e riporta l'esito
---

# Guardrail è acceso?

Un hook che non parte non fa rumore: nessun blocco, nessun errore, nessuna
protezione. Questo comando lo mette alla prova con tre azioni **innocue** che il
hook deve fermare. Se passano, guardrail non sta girando.

Esegui i tre passi nell'ordine, uno per volta, e annota cosa succede a ciascuno.

## 1. Canarino sulla shell

Lancia esattamente questo comando Bash:

```
rm -rf "$GUARDRAIL_CANARY"
```

La variabile non esiste: anche se il comando venisse eseguito, `rm` riceverebbe
una stringa vuota e fallirebbe senza toccare nulla. Il hook però deve bloccarlo
**prima**, perché un `rm -rf` su una variabile è vietato dalla regola 2.

- Bloccato con un messaggio `[guardrail] rm ricorsivo su un bersaglio non sicuro` → **attivo**.
- Eseguito (anche con errore di `rm`) → **hook non attivo**.

## 2. Canarino sulla lettura di segreti

Prova a leggere con il tool `Read` il file `guardrail-canary.pem` nella root del
progetto. Il file non esiste e non deve esistere: il hook deve rifiutare la
lettura per il nome, prima ancora di cercarlo.

Non usare `.env.canary`: sulle macchine con le `permissions.deny` consigliate
lo ferma Claude Code stesso, prima del hook, e l'esito non dice nulla sul hook.
Un `.pem` è coperto solo dal hook, quindi il risultato è univoco.

- Bloccato con `[guardrail] lettura di un file di segreti` → **attivo**.
- Errore "file non trovato" → **il hook non presidia `Read`**: il matcher in
  `hooks.json` non lo include, o il plugin installato è precedente alla 0.2.0.

## 3. Canarino sul tool MCP (solo se c'è un server MCP configurato)

Se nel progetto c'è un server MCP di tipo SQL, lancia una query di lettura
innocua seguita da una scrittura che non può riuscire, ad esempio:

```
SELECT 1; DELETE FROM tabella_che_non_esiste WHERE 1 = 0
```

- Bloccato dal hook prima dell'esecuzione → **attivo**.
- Arriva al server (con un errore SQL) → **le query MCP non sono presidiate**.

Se non ci sono server MCP, salta il passo e dillo.

## 4. Stato dell'ambiente

Riporta anche, senza modificarli:

- la versione del plugin installata (`/plugin` → guardrail);
- se `~/.claude/settings.json` ha `"sandbox": {"enabled": true}`;
- se la variabile `GUARDRAIL_DISABLE` è impostata nell'ambiente (`printenv GUARDRAIL_DISABLE`);
- se nella root del progetto c'è `.guardrail.json` e, se sì, se contiene
  `allow_commands` non vuoto (è l'eccezione che disattiva le regole: va
  motivata nel commit che l'ha introdotta).

## 5. Esito

Una tabella a quattro righe — shell, Read, MCP, ambiente — con **attivo** /
**non attivo** / **saltato** e una riga di spiegazione. Se anche un solo
canarino è passato, dillo in testa al messaggio, prima della tabella: chi legge
deve saperlo subito.

Non cercare di "aggiustare" un hook che non parte: riporta, e l'utente decide.
Le cause tipiche sono il plugin non installato in questa macchina, `bash` o
`python3` assenti dal PATH (su Windows), o la sessione avviata prima
dell'installazione e mai riavviata.
