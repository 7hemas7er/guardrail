# Database

Vale per PostgreSQL, MySQL/MariaDB, Redis, Mongo, e per ogni via d'accesso:
`psql`/`mysql` da shell, server MCP, `artisan tinker`, script.

## Ambienti

| Ambiente | Cosa può fare l'agente | Note |
|---|---|---|
| **Produzione** | solo `SELECT`, `EXPLAIN`, letture di schema | utente DB **read-only**; nessuna eccezione, nemmeno "una riga sola" |
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
  le vede e non le stampa.
- **Dichiaralo in `ask_commands`** dentro `.guardrail.json`: ogni clone chiede
  conferma, anche in modalità auto, senza che nessuno debba toccare le regole
  sul database di produzione.

## Cosa fa rispettare il hook

| Azione | Esito |
|---|---|
| SQL di scrittura (INSERT/UPDATE/DELETE/DDL) verso un server MCP o host di produzione | BLOCCO |
| SQL di scrittura verso un server MCP in `ask_mcp_servers` | CONFERMA |
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
