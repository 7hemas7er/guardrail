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
- Dump e restore: `pg_dump` di produzione va solo verso un DB locale anonimizzato;
  mai `pg_restore --clean` verso produzione.
- Connection string con password non si scrivono in file tracciati, né in chat.
  Se un `.mcp.json` tracciato contiene credenziali, segnalalo: è un bug.
- Timestamp: confronta sempre nello stesso fuso. Un `timestamp` senza timezone
  riletto come ora locale ha già prodotto tre volte lo stesso bug.
- Identificatori SQL dinamici (nomi colonna, chiavi JSONB in `orderBy`) non sono
  bindabili: whitelist esplicita, sempre.

## Cosa fa rispettare il hook

| Azione | Esito |
|---|---|
| SQL di scrittura (INSERT/UPDATE/DELETE/DDL) verso un server MCP o host di produzione | BLOCCO |
| SQL di scrittura verso un server MCP in `ask_mcp_servers` | CONFERMA |
| `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`, su qualunque ambiente | BLOCCO |
| `DELETE FROM` o `UPDATE … SET` senza `WHERE` | BLOCCO |
| `dropdb`, `pg_restore --clean` verso produzione | BLOCCO |
| `redis-cli FLUSHALL` / `FLUSHDB` | BLOCCO |
| `artisan migrate:fresh`, `db:wipe`, `migrate:reset` | BLOCCO |
| `artisan migrate:rollback`, `db:seed --class=RolePermissionSeeder` | CONFERMA |
