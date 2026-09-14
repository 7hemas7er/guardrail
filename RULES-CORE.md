# Guardrail — regole essenziali (valide per ogni agente, in ogni repo)

1. **Produzione si legge, non si scrive.** Nessun INSERT/UPDATE/DELETE/DDL su un
   database, storage o servizio di produzione. Le modifiche passano da una
   migration nel repo o da un operatore umano.
2. **Mai variabili in un comando distruttivo.** `rm -rf "$X"`, `rm -rf ~/.*`,
   `rsync --delete $DIR`: vietati. Un bersaglio da cancellare è un path letterale,
   relativo al progetto, e prima si mostra all'utente cosa contiene.
3. **Cancellare non è mai un effetto collaterale.** `--delete`, `prune`, `clean -x`,
   `migrate:fresh`, `TRUNCATE`, `DROP`: solo con dry-run mostrato e conferma
   esplicita dell'utente. Se in dubbio, elenca e fermati.
4. **Segreti.** Non leggere `.env*`, chiavi, token; non stamparli mai in chat; non
   scriverli in file tracciati da git. Se serve un valore, chiedilo all'utente.
5. **Nulla fuori dal progetto senza chiederlo.** La home, `~/.config`, `~/.claude`,
   altri repo: si toccano solo su richiesta esplicita.
6. **Git:** mai `push --force` su branch condivisi, mai riscrivere la storia di
   `main`, commit atomici con messaggio in italiano.
7. **Dati personali** (anagrafiche, posizioni GPS, sanitari): si trattano solo
   per lo scopo richiesto, non si copiano in log, test, esempi o chat.
8. **Un hook ti ha bloccato?** Non aggirarlo con un comando equivalente. Spiega
   all'utente cosa volevi fare e perché; decide lui.
9. **Modalità auto non è licenza.** Prima di un'azione irreversibile ragiona come
   se l'utente stesse guardando: mostra il piano, poi agisci.
