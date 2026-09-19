# Database

Vale per PostgreSQL, MySQL/MariaDB, Redis, Mongo, e per ogni via d'accesso:
`psql`/`mysql` da shell, server MCP, `artisan tinker`, script.

## Ambienti

| Ambiente | Cosa può fare l'agente | Note |
|---|---|---|
| **Produzione** | solo `SELECT`, `EXPLAIN`, letture di schema | **una query di sola lettura è sempre autorizzata**, anche in produzione; a essere vietata è la scrittura, senza eccezioni, nemmeno "una riga sola" |
| **Test condiviso** | letture; scritture solo con conferma | altri lo usano: uno schema rotto blocca la suite di tutti |
| **Dev locale / usa e getta** | tutto, tranne DROP DATABASE e TRUNCATE | è il posto per provare |

Un DB è "produzione" se il nome del server MCP è nella lista `prod_mcp_servers`
di `.guardrail.json` o se host/nome corrispondono a `prod_patterns`. **Il nome
del server MCP non basta a riconoscerlo**: capita che il server di produzione si
chiami semplicemente `postgres`, senza "prod". Ogni repo dichiara i suoi.

## Regole di condotta

- Le modifiche allo schema e ai dati di produzione passano **solo** da migration
  versionate nel repo, applicate dalla pipeline di deploy o da un operatore.
- Prima di una query pesante in produzione: `EXPLAIN`. Un seq scan su una tabella
  grande in orario di lavoro è un incidente.
- Mai `migrate:fresh` o `db:wipe` fuori da un DB usa e getta: droppano anche le
  tabelle che le migration non ricreano (tipicamente uno schema legacy creato
  fuori dalle migration). Il 2026-07-06 un run ha distrutto un DB di test
  condiviso.
- I seeder che riscrivono permessi o ruoli (`RolePermissionSeeder`) si lanciano
  solo al setup iniziale: in produzione cancellano le assegnazioni manuali.
- `DELETE` e `UPDATE` hanno sempre un `WHERE` stretto e prima si conta con un
  `SELECT COUNT(*)` con lo stesso predicato. Mostra il conteggio all'utente.
- Dump e restore: `pg_dump` di produzione va solo verso un DB locale anonimizzato
  (vedi «Ambiente di prova clonato da produzione»); mai `pg_restore --clean`
  verso produzione.
- Connection string con password non si scrivono in file tracciati, né in chat.
  Se un `.mcp.json` tracciato contiene credenziali, segnalalo: è un bug.
- Timestamp: confronta sempre nello stesso fuso. Un `timestamp` senza timezone
  riletto come ora locale ha già prodotto tre volte lo stesso bug.
- Identificatori SQL dinamici (nomi colonna, chiavi JSONB in `orderBy`) non sono
  bindabili: whitelist esplicita, sempre.

## Ambiente di prova clonato da produzione

Provare sul serio richiede dati veri per forma e volume. Un clone di produzione
dentro un container locale **è consentito**, ed è preferibile all'alternativa che
di solito prende il suo posto: provare in produzione. Le regole della tabella qui
sopra non si allentano di un millimetro mentre il clone gira — il consenso vale
per l'ambiente, non per la produzione.

Vale a queste condizioni, tutte necessarie.

- **Una direzione sola.** Produzione è solo sorgente: `pg_dump`/`mysqldump` con
  l'utente read-only. Nessun comando della catena ha produzione come bersaglio.
  È l'unico modo in cui un clone fa danno, ed è quello che il hook blocca.
- **Bersaglio usa e getta e dichiarato**: un container con nome progetto, volume
  e porta propri (`docker compose -p appdb-sandbox`). Mai il DB di test
  condiviso, mai la home montata dentro il container.
- **Anonimizzazione in transito**, non "poi la faccio": il dump grezzo di una
  tabella di persone non deve restare a riposo su disco. Lo fa lo script, fra
  dump e restore. Vale la regola 7 di `RULES-CORE.md` anche in locale.
- **Il dump vive nello scratchpad**, mai in un path tracciato da git, e a fine
  lavoro si cancella per nome letterale.
- **Il clone è uno script del repo, scritto da un umano**
  (`scripts/clone-prod-to-local.sh`): l'agente lo invoca, non lo improvvisa. Lo
  script legge le credenziali dall'ambiente e fallisce se mancano; l'agente non
  le vede e non le stampa. Uno di riferimento, da copiare e adattare, è in
  [`examples/clone-prod-to-local.sh`](../examples/clone-prod-to-local.sh).
- **Dichiaralo in `ask_commands`** dentro `.guardrail.json`: ogni clone chiede
  conferma, senza che nessuno debba toccare le regole sul database di produzione.
  ⚠️ In modalità auto quella conferma la concede l'agente: se il clone deve
  passare per forza da un umano, la voce va in `deny_commands` e lo lancia una
  persona fuori dalla sessione.

## Cosa fa rispettare il hook

| Azione | Esito |
|---|---|
| SQL di scrittura (INSERT/UPDATE/DELETE/DDL) verso un server MCP o host di produzione | BLOCCO, con la query mostrata |
| SQL di scrittura verso un server MCP in `ask_mcp_servers` | CONFERMA, con la query mostrata |
| Payload SQL che il hook non riesce a classificare, verso un server MCP di produzione | BLOCCO, con la query mostrata |
| Stesso payload verso un server MCP condiviso | CONFERMA, con la query mostrata |
| `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`, su qualunque ambiente | BLOCCO |
| `DELETE FROM` o `UPDATE … SET` senza `WHERE` | BLOCCO |
| `dropdb`, `pg_restore --clean` verso produzione | BLOCCO |
| `psql`/`mysql` con `-f`, `<` o una pipe in ingresso, e un bersaglio di produzione | BLOCCO |
| `pg_restore -d` verso un bersaglio di produzione, anche senza `--clean` | BLOCCO |
| `pg_dump` di produzione verso un bersaglio locale (il clone) | permesso |
| `redis-cli FLUSHALL` / `FLUSHDB` | BLOCCO |
| `artisan migrate:fresh`, `db:wipe`, `migrate:reset` | BLOCCO |
| `artisan migrate:rollback`, `db:seed --class=RolePermissionSeeder` | CONFERMA |
| Tool MCP non SQL con operazione distruttiva (`delete`, `drop`, `purge`, `reset`…) su un server di produzione, o con parametri che corrispondono a `prod_patterns` | BLOCCO |
| Stessa operazione su qualunque altro server | CONFERMA |
| Tool MCP non SQL con operazione di modifica (`create`, `update`, `restart`, `scale`…) su produzione | BLOCCO |
| Stessa operazione su un server in `ask_mcp_servers` | CONFERMA |

Per le ultime tre righe il bersaglio non è "la parola produzione da qualche parte
nel comando", ma host, nome del database, URI di connessione e variabili
d'ambiente di connessione. Un file di nome `dump_produzione.sql` ripristinato in
locale non è un bersaglio di produzione, e non viene bloccato.

Per i server MCP non SQL (Azure, GitHub, filesystem…) l'intenzione si legge dal
nome del tool e dai campi che descrivono l'operazione (`command`, `action`,
`method`, `state`); i tool di sola lettura (`get_*`, `list_*`, `search_*`) non
vengono toccati.

### Come viene classificato un payload SQL via MCP

Il testo viene attraversato una volta sola tenendo lo stato — literal fra apici
(con `''` raddoppiato), dollar-quote con tag, commento di riga, commento a
blocco annidato — e di literal e commenti resta il guscio vuoto. Serve perché
letterali e commenti si intrecciano: un apice dentro `/* … */` non è un apice
per il database, ma per una ricerca testuale sì, e in quel finto literal ci si
nasconde una `DELETE`. Vale **solo** per il SQL puro: in una riga di shell gli
apici delimitano il payload di `psql -c '...'`, quindi lì il testo si valuta per
intero.

Sullo scheletro la risposta è una di tre:

| | Cosa vuol dire | Produzione | Condiviso |
|---|---|---|---|
| **lettura** | ogni istruzione comincia per `SELECT`/`WITH`/`EXPLAIN`… o delimita una transazione, e nessuna scrive | permessa, senza attrito | permessa |
| **scrittura** | c'è un verbo di scrittura, un `SELECT … INTO`, un `INTO OUTFILE` | BLOCCO | CONFERMA |
| **incerta** | un literal o un commento resta aperto; oppure l'istruzione non si classifica (`CALL`, `DO $$ … $$`, `COPY … FROM`); oppure compare una funzione che legge solo all'apparenza (`dblink`, `pg_read_file`, `pg_terminate_backend`, `setval`…) | BLOCCO | CONFERMA |

`incerta` non è un ripiego: è la risposta onesta quando il confine fra codice e
dati non si legge. Un `SELECT dblink('…', 'DELETE FROM utenti')` è una `SELECT`
solo di facciata — il SQL che esegue sta dentro un literal, cioè esattamente
dove lo scheletro non guarda.

**La query viene mostrata** nel messaggio di blocco o di conferma, troncata e con
le credenziali redatte: chi decide deve vedere cosa girerebbe. I valori restano
in chiaro, perché sono ciò che rende la query giudicabile — e quindi finiscono
nella trascrizione e nel log: se sono dati personali vale la regola 7, e la
query si guarda, non si copia altrove.

Su produzione l'esito è **BLOCCO**, non conferma, anche quando la query
sembrerebbe innocua. In modalità auto la conferma la concede l'agente: se la
decisione deve essere di un umano, l'unico esito che non si scavalca è il blocco.
Per ripartire: riscrivi la query senza commenti e con i literal chiusi, così
viene riconosciuta come lettura; se deve davvero scrivere, la esegue un
operatore.
