# Database

Applies to PostgreSQL, MySQL/MariaDB, Redis, Mongo, and to every access path:
`psql`/`mysql` from the shell, MCP servers, `artisan tinker`, scripts.

## Environments

| Environment | What the agent may do | Notes |
|---|---|---|
| **Production** | only `SELECT`, `EXPLAIN`, schema reads | **a read-only query is always authorized**, even in production; what is forbidden is writing, with no exceptions, not even "just one row" |
| **Shared test** | reads; writes only with confirmation | others use it: a broken schema blocks everyone's suite |
| **Local dev / throwaway** | everything, except DROP DATABASE and TRUNCATE | it is the place to experiment |

A DB is "production" if the MCP server name is in the `prod_mcp_servers` list
of `.guardrail.json` or if host/name match `prod_patterns`. **The MCP server
name is not enough to recognize it**: it happens that the production server is
simply called `postgres`, with no "prod". Each repo declares its own.

## Rules of conduct

- Changes to production schema and data go **only** through migrations
  versioned in the repo, applied by the deploy pipeline or by an operator.
- Before a heavy query in production: `EXPLAIN`. A seq scan on a large table
  during working hours is an incident.
- Never `migrate:fresh` or `db:wipe` outside a throwaway DB: they also drop the
  tables the migrations do not recreate (typically a legacy schema created
  outside the migrations). On 2026-07-06 one run destroyed a shared test DB.
- Seeders that rewrite permissions or roles (`RolePermissionSeeder`) run only
  at initial setup: in production they wipe out manual assignments.
- `DELETE` and `UPDATE` always have a tight `WHERE`, and first you count with a
  `SELECT COUNT(*)` on the same predicate. Show the count to the user.
- Dump and restore: a production `pg_dump` goes only to an anonymized local DB
  (see "Test environment cloned from production"); never `pg_restore --clean`
  towards production.
- Connection strings with passwords are not written to tracked files, nor in
  chat. If a tracked `.mcp.json` contains credentials, report it: it is a bug.
- Timestamps: always compare in the same time zone. A `timestamp` without a
  timezone read back as local time has already produced the same bug three
  times.
- Dynamic SQL identifiers (column names, JSONB keys in `orderBy`) cannot be
  bound: explicit whitelist, always.

## Test environment cloned from production

Testing for real requires real data in shape and volume. A clone of production
inside a local container **is allowed**, and is preferable to the alternative
that usually takes its place: testing in production. The rules of the table
above do not loosen by a millimetre while the clone is running — the consent
covers the environment, not production.

It holds under these conditions, all of them necessary.

- **One direction only.** Production is only the source: `pg_dump`/`mysqldump`
  with the read-only user. No command in the chain has production as its
  target. That is the only way a clone does damage, and it is what the hook
  blocks.
- **A throwaway, declared target**: a container with its own project name,
  volume and port (`docker compose -p appdb-sandbox`). Never the shared test DB,
  never the home directory mounted inside the container.
- **Anonymization in transit**, not "I'll do it later": the raw dump of a
  table of people must not stay at rest on disk. The script does it, between
  dump and restore. Rule 7 of `RULES-CORE.md` holds locally too.
- **The dump lives in the scratchpad**, never in a git-tracked path, and at the
  end of the work it is deleted by literal name.
- **The clone is a script in the repo, written by a human**
  (`scripts/clone-prod-to-local.sh`): the agent invokes it, it does not
  improvise one. The script reads the credentials from the environment and
  fails if they are missing; the agent does not see them and does not print
  them. A reference one, to copy and adapt, is in
  [`examples/clone-prod-to-local.sh`](../examples/clone-prod-to-local.sh).
- **Declare it in `ask_commands`** inside `.guardrail.json`: every clone asks
  for confirmation, without anyone having to touch the rules on the production
  database. ⚠️ In auto mode that confirmation is granted by the agent: if the
  clone must go through a human no matter what, the entry goes in
  `deny_commands` and a person launches it outside the session.

## What the hook enforces

| Action | Outcome |
|---|---|
| Write SQL (INSERT/UPDATE/DELETE/DDL) towards a production MCP server or host | BLOCK, with the query shown |
| Write SQL towards an MCP server in `ask_mcp_servers` | CONFIRM, with the query shown |
| SQL payload the hook cannot classify, towards a production MCP server | BLOCK, with the query shown |
| Same payload towards a shared MCP server | CONFIRM, with the query shown |
| `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`, on any environment | BLOCK |
| `DELETE FROM` or `UPDATE … SET` without `WHERE` | BLOCK |
| `dropdb`, `pg_restore --clean` towards production | BLOCK |
| `psql`/`mysql` with `-f`, `<` or a pipe on input, and a production target | BLOCK |
| `pg_restore -d` towards a production target, even without `--clean` | BLOCK |
| Production `pg_dump` towards a local target (the clone) | allowed |
| `redis-cli FLUSHALL` / `FLUSHDB` | BLOCK |
| `artisan migrate:fresh`, `db:wipe`, `migrate:reset` | BLOCK |
| `artisan migrate:rollback`, `db:seed --class=RolePermissionSeeder` | CONFIRM |
| Non-SQL MCP tool with a destructive operation (`delete`, `drop`, `purge`, `reset`…) on a production server, or with parameters matching `prod_patterns` | BLOCK |
| Same operation on any other server | CONFIRM |
| Non-SQL MCP tool with a modifying operation (`create`, `update`, `restart`, `scale`…) on production | BLOCK |
| Same operation on a server in `ask_mcp_servers` | CONFIRM |

For the last three rows the target is not "the word production somewhere in
the command", but host, database name, connection URI and connection
environment variables. A file named `dump_production.sql` restored locally is
not a production target, and is not blocked.

For non-SQL MCP servers (Azure, GitHub, filesystem…) the intent is read from
the tool name and from the fields that describe the operation (`command`,
`action`, `method`, `state`); read-only tools (`get_*`, `list_*`, `search_*`)
are left alone. Closing the test browser or one of its tabs (Playwright,
Chrome DevTools) is not a destructive operation. The `query` field of a
documentation tool (context7: `query-docs`, `resolve-library-id`) is a
question, not SQL, and is not classified as such.

### How an SQL payload via MCP is classified

The text is walked once, keeping state — quoted literal (with doubled `''`),
dollar-quote with tag, line comment, nested block comment — and of literals
and comments only the empty shell remains. This is needed because literals
and comments intertwine: a quote inside `/* … */` is not a quote for the
database, but it is for a text search, and a `DELETE` hides in that fake
literal. It holds **only** for pure SQL: on a shell line the quotes delimit
the payload of `psql -c '...'`, so there the text is evaluated whole.

On the skeleton the answer is one of three:

| | What it means | Production | Shared |
|---|---|---|---|
| **read** | every statement begins with `SELECT`/`WITH`/`EXPLAIN`… or delimits a transaction, and none writes | allowed, no friction | allowed |
| **write** | there is a write verb, a `SELECT … INTO`, an `INTO OUTFILE` | BLOCK | CONFIRM |
| **uncertain** | a literal or a comment is left open; or the statement cannot be classified (`CALL`, `DO $$ … $$`, `COPY … FROM`); or a function appears that only looks like a read (`dblink`, `pg_read_file`, `pg_terminate_backend`, `setval`…) | BLOCK | CONFIRM |

`uncertain` is not a fallback: it is the honest answer when the boundary
between code and data cannot be read. A `SELECT dblink('…', 'DELETE FROM users')`
is a `SELECT` only on the surface — the SQL it executes sits inside a literal,
which is exactly where the skeleton does not look.

**The query is shown** in the block or confirmation message, truncated and
with credentials redacted: whoever decides must see what would run. The values
stay in clear, because they are what makes the query judgeable — and so they
end up in the transcript and in the log: if they are personal data, rule 7
applies, and the query is looked at, not copied elsewhere.

On production the outcome is **BLOCK**, not confirmation, even when the query
would seem harmless. In auto mode the confirmation is granted by the agent: if
the decision must be a human's, the only outcome that cannot be overridden is
the block. To get going again: rewrite the query without comments and with the
literals closed, so it is recognized as a read; if it really must write, an
operator runs it.
