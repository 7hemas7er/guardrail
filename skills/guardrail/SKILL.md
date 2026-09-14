---
name: guardrail
description: Regole aziendali per servizio (database, deploy e infrastruttura, filesystem/shell/segreti, git/GitHub/dati personali). Caricare PRIMA di eseguire SQL, migration, seed, deploy, sincronizzazioni con --delete, rm ricorsivi, pulizie di file temporanei, push, chiusura di issue, o di toccare dati di persone. Triggers on: prod, produzione, database, migrate, seed, deploy, promote, rollback, lftp, rsync, rm -rf, pulizia, cleanup, .env, segreti, credenziali, force push, GDPR, GPS, dati personali.
---

# Guardrail — regole per servizio

Le regole essenziali sono già nel contesto (iniettate a inizio sessione). Qui
carichi quelle del servizio che stai per toccare. I file stanno nella cartella
`services/` due livelli sopra questa skill.

1. Individua il servizio: database, deploy e infrastruttura, filesystem/shell/
   segreti, git/GitHub/dati personali. Se il compito ne tocca più d'uno, leggili
   tutti.
2. Leggi il file corrispondente:
   - `../../services/database.md`
   - `../../services/deploy-infrastruttura.md`
   - `../../services/filesystem-shell-segreti.md`
   - `../../services/git-github-dati-personali.md`
3. Se il repo ha `.guardrail.json`, leggilo: dice quali server e host sono
   produzione per questo progetto.
4. Prima dell'azione irreversibile, scrivi all'utente in una riga: cosa stai per
   fare, su quale ambiente, e come lo hai verificato (dry-run, conteggio, ls).
   Poi agisci, o fermati se la regola lo richiede.
5. Se un hook ti blocca: non cercare un comando equivalente. Riporta il motivo
   del blocco all'utente e lascia a lui la decisione.
