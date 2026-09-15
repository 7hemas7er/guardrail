---
description: Riassume i blocchi e le conferme recenti di guardrail, per correggere i falsi positivi con una regola migliore
---

# Cosa ha fermato guardrail

Ogni `deny` e `ask` finisce in `~/.claude/guardrail.log.jsonl`, una riga JSON
per evento con `ts`, `verdict`, `tool`, `cwd`, `session`, `reason` e i primi 400
caratteri di `input`. Questo comando lo legge e lo riassume.

## 1. Leggi il log

```
tail -n 200 ~/.claude/guardrail.log.jsonl
```

Se il file non esiste, guardrail non ha mai bloccato nulla su questa macchina:
dillo e fermati. Se l'utente ha passato un argomento (`$ARGUMENTS`), usalo come
filtro: un numero è quante righe leggere, una parola è un filtro sul `reason` o
sulla `cwd`.

## 2. Raggruppa

Per ogni evento, prendi la regola che ha deciso (la prima frase di `reason`) e
raggruppa. Per ogni gruppo:

- quante volte, in quante sessioni, in quali progetti (`cwd`);
- un esempio di `input`, **con i valori sensibili oscurati**: se un input contiene
  connection string, token o password, sostituiscili con `***` prima di
  riportarli. Il log li ha già troncati, ma non li ha redatti.

## 3. Classifica

Per ogni gruppo, dì se secondo te è:

- **un blocco giusto**: l'azione era davvero da fermare;
- **un falso positivo**: l'azione era legittima e la regola è troppo larga.
  Proponi la correzione precisa — la regex da restringere in `hooks/guard.py`,
  o la voce `ask_commands`/`prod_patterns` da sistemare in `.guardrail.json` —
  e il caso da aggiungere a `tests/cases.jsonl` perché non si ripeta;
- **un tentativo di aggiramento**: lo stesso agente ha riprovato l'azione
  bloccata con un comando equivalente (stesso `session`, `reason` diversi a
  pochi secondi di distanza). Questo va segnalato per primo: è esattamente ciò
  che la regola 8 vieta.

## 4. Riporta

Un elenco per gruppo, dal più frequente al più raro, con la classificazione e la
proposta. Non modificare né il log né `guard.py` né `.guardrail.json`: le
correzioni le decide l'utente, e un `allow_commands` non è mai una proposta
accettabile per un falso positivo — si restringe la regola, non si spegne.
