---
description: Approva uno script per allow_scripts — lo legge, mostra cosa fa di pericoloso, e registra la sua impronta in .guardrail.json
---

# Approvare uno script

Ogni script invocato viene letto dal hook: se contiene un comando che guardrail
fermerebbe, l'esito è una conferma, **ogni volta**. Su uno script di build
lanciato venti volte al giorno quella conferma diventa rumore, e il rumore
insegna ad approvare senza leggere.

`allow_scripts` la toglie, ma lega l'esenzione all'impronta sha256 del contenuto:
se lo script cambia, la conferma torna. Questo comando è il modo corretto di
mettere e rinnovare quell'impronta.

**L'approvazione la dà l'utente, non tu.** Il tuo compito è leggere, mostrare e
registrare. Se lo script lo hai scritto tu in questa sessione, dillo prima di
ogni altra cosa: l'utente starebbe approvando codice appena generato.

## 0. Senza argomenti: controlla le approvazioni esistenti

Se `$ARGUMENTS` è vuoto, leggi `allow_scripts` da `.guardrail.json` e per ogni
voce confronta `sha256sum` con l'impronta dichiarata. Riporta in una tabella:

| Stato | Significato |
|---|---|
| valida | il file c'è e l'impronta corrisponde |
| scaduta | il contenuto è cambiato: l'esenzione non vale più |
| incompleta | la voce non dichiara `sha256`, quindi non esenta niente |
| orfana | il path non esiste più |

Non aggiornare niente in questa modalità: un'impronta scaduta si rinnova
rileggendo lo script, cioè rilanciando questo comando su quel path.

## 1. Con un path: leggi lo script per intero

Usa `Read`, non `head`. Se supera le 200 righe leggilo comunque, e riassumilo per
blocchi. Fermati subito, spiegando perché, se:

- il path non esiste, o sta fuori dal progetto corrente;
- il file non è tracciato da git. Un file non versionato può cambiare senza
  lasciare traccia in nessuna revisione: l'impronta lo intercetterebbe, ma non
  c'è niente da rileggere per capire *cosa* è cambiato. Dillo, e lascia decidere.

## 2. Mostra cosa contiene di rilevante

Elenca, con il numero di riga, ogni comando che il hook fermerebbe: `rm`
ricorsivi, `--delete`, `prune`, SQL di scrittura, letture di segreti, `sudo`,
`curl | sh`. Poi:

- **Nessun comando del genere**: lo script non ha bisogno di approvazione, perché
  non produce nessuna conferma. Dillo e fermati senza scrivere niente.
- **Un comando presente in `deny_commands`**: non si approva. `deny_commands`
  vince anche dentro uno script approvato, quindi la voce sarebbe inutile e
  bugiarda. Spiega e fermati.

## 3. Se era già approvato con un'impronta diversa

Mostra cosa è cambiato dall'ultima approvazione. La revisione approvata si trova
confrontando le impronte delle versioni in git:

```
for c in $(git log --format=%H -- PERCORSO); do
  echo "$c $(git show "$c:PERCORSO" | sha256sum | cut -d' ' -f1)"
done
```

La riga con l'impronta dichiarata in `.guardrail.json` è la revisione che
l'utente aveva letto: mostra `git diff <quel commit> -- PERCORSO`. Se nessuna
revisione corrisponde, dillo: lo script è stato modificato senza passare da git,
ed è un'informazione che conta più del diff.

## 4. Chiedi conferma

Mostra la voce esatta che stai per scrivere:

```json
{"path": "scripts/build\\.sh", "sha256": "625f88e4…"}
```

Il `path` è una regex: punti escapati, ancorata al progetto quanto basta a non
prendere omonimi in altre directory. Chiedi conferma esplicita. Se l'utente non
conferma, non scrivere niente.

## 5. Scrivi

Aggiorna `allow_scripts` in `.guardrail.json` (crea il file se manca, con le
altre chiavi vuote). Sostituisci la voce esistente per quel path invece di
aggiungerne una seconda. L'impronta è quella di `sha256sum PERCORSO`, presa
**dopo** la lettura, non prima.

La scrittura farà scattare una conferma del hook: è voluto, è la garanzia che
questo file non cambi senza che l'utente lo veda.

## 6. Chiudi

Ricorda due cose:

- `.guardrail.json` va committato: l'approvazione vale per chiunque lavori nel
  repo, persone e agenti, e come il codice si rivede in una PR;
- a ogni modifica volontaria dello script l'impronta va rinnovata, rilanciando
  questo comando. Se qualcuno la rinnova senza rileggere, l'esenzione torna a
  essere quello che non deve essere: fiducia in un nome.
