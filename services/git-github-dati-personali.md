# Git, GitHub e dati personali

## Git e GitHub

- **Commit**: Conventional Commits con scope, descrizione in italiano; un commit
  per unità logica; mai `git add -A` o `git add .`, sempre file espliciti. Il
  prefisso finisce nel changelog letto dagli utenti.
- **Mai riscrivere la storia condivisa**: niente `push --force` su `main` o su
  branch di altri. `--force-with-lease` solo su un branch personale, con
  conferma. `main` senza branch protection è un motivo in più, non in meno.
- **Non scartare lavoro altrui**: `git reset --hard`, `git checkout -- .`,
  `git clean -f` cancellano modifiche non committate che potrebbero non essere
  tue (worktree condivisi, sessioni parallele). Prima `git status`, poi chiedi.
- **`git clean -x` mai**: rimuove anche i file ignorati, cioè `.env` e le
  credenziali locali.
- **Segreti in git**: nessun `.env` non-`.example`, nessun dump SQL, nessun
  token in file tracciati. Se ne trovi uno già committato, non basta cancellarlo:
  segnala che va ruotato.
- **GitHub**: il repo giusto è quello dell'organizzazione, non fork personali
  obsoleti. Verifica l'esistenza di issue e PR prima di commentare o chiudere.
  Chiudere un'issue è un'azione verso persone: solo con verifica fatta e
  descritta nel commento.
- **Attribuzione**: i commit dell'agente portano le righe di attribuzione che la
  sessione prescrive, senza inventarle né hardcodarle in skill e script.

## Dati personali (GDPR)

Molti progetti trattano anagrafiche, posizioni GPS, dati sanitari, dati di
minori. Valgono queste regole a prescindere dal repo.

- **Minimizzazione**: usa solo i campi che il compito richiede. Un `SELECT *` su
  una tabella di persone in chat è già una fuga.
- **Mai dati reali in test, fixture, esempi, log, issue, commenti di PR.** Per
  gli esempi si usano dati inventati, o un seeder di anonimizzazione e uno script
  di clone da produzione a dev che anonimizza in transito.
- **GPS e tracciamento**: la posizione di una persona si legge solo con il suo
  consenso valido e ogni lettura è auditata. Un amministratore non accende il
  tracciamento di una persona. Se una feature lo permetterebbe, è un bug da
  segnalare, non da usare.
- **Audit**: sui modelli sensibili ogni campo nuovo va classificato: escluso dal
  log (rumore) o redatto (riservato). Nel 2026-07 un trait di audit ha finito per
  scrivere nel log campi riservati, perché nessuno lo aveva fatto.
- **Retention**: i dati hanno una scadenza. Non copiarli fuori dal sistema che
  la applica (export, fogli, chat).
- **Nelle trascrizioni**: ciò che stampi in chat resta su disco. Nomi, codici
  fiscali, telefoni, coordinate: non stamparli se non serve alla persona che ti
  legge, e se serve, il minimo.

## Cosa fa rispettare il hook

| Azione | Esito |
|---|---|
| `git push --force`, `-f`, refspec `+ref` | BLOCCO |
| `git push --force-with-lease` | CONFERMA |
| `git clean -x` / `-X` | BLOCCO |
| `git clean -f`, `git reset --hard`, `git checkout -- .`, `git restore .` | CONFERMA |

Le regole sui dati personali sono di condotta: nessun hook può riconoscere un
codice fiscale in una query. Le fa rispettare l'agente, e chi lo controlla.
