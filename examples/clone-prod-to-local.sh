#!/usr/bin/env bash
#
# Clone of production into the local sandbox — reference script.
#
# Copy it to `scripts/clone-prod-to-local.sh` in your project, adapt the tables
# and the anonymisation query, and declare it in `.guardrail.json`:
#
#     "ask_commands": ["scripts/clone-prod-to-local\\.sh"]
#
# so every run asks for confirmation, even in auto mode.
#
# The conditions that make this clone legitimate are in
# `services/database.md`, section "Test environment cloned from production".
# Here they are implemented like this:
#
#   one direction only    production appears only in `pg_dump`, never as a target;
#                         the script refuses to write to a non-local host
#   no dump at rest       the dump does not touch the disk: it goes through a pipe in the sandbox
#   anonymisation         right after the restore, in the same run, and if it
#                         fails the sandbox is left unusable on purpose
#   secrets               credentials come from the environment and are not printed
#   throwaway target      a sandbox database, declared by name
#
set -euo pipefail

# --- Parameters: from the environment, never on the command line (they would end up in `ps`).
# Source (production): READ-ONLY user, always.
: "${PROD_HOST:?PROD_HOST missing}"
: "${PROD_DB:?PROD_DB missing}"
# PROD_USER must be the production read-only user.
: "${PROD_USER:?PROD_USER missing}"
# PGPASSWORD is exported from the environment or from the gitignored .env, not written here.
: "${PGPASSWORD:?PGPASSWORD missing}"

# Target (local sandbox): throwaway container, dedicated port.
SANDBOX_HOST="${SANDBOX_HOST:-127.0.0.1}"
SANDBOX_PORT="${SANDBOX_PORT:-55432}"
SANDBOX_DB="${SANDBOX_DB:-appdb_sandbox}"
SANDBOX_USER="${SANDBOX_USER:-postgres}"
ANONIMIZZA="${ANONIMIZZA:-scripts/anonimizza.sql}"

# --- The target must be local. This check is the heart of the script:
# if someone passes a remote host, the clone becomes a write to production.
case "$SANDBOX_HOST" in
  127.0.0.1|localhost|::1|host.docker.internal) ;;
  *)
    echo "refused: the target ($SANDBOX_HOST) is not local. The clone goes in one" >&2
    echo "direction only: production -> sandbox. See services/database.md." >&2
    exit 1
    ;;
esac

if [ ! -f "$ANONIMIZZA" ]; then
  echo "refused: $ANONIMIZZA missing. Without anonymisation the clone does not start." >&2
  exit 1
fi

echo "source : $PROD_USER@$PROD_HOST/$PROD_DB (read-only)"
echo "target : $SANDBOX_USER@$SANDBOX_HOST:$SANDBOX_PORT/$SANDBOX_DB"
echo "anonymisation: $ANONIMIZZA"

if [ "${1:-}" = "--dry-run" ]; then
  echo
  echo "dry-run: nothing is executed. Rows that would be copied:"
  psql -h "$PROD_HOST" -U "$PROD_USER" -d "$PROD_DB" -At \
    -c "SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 15"
  exit 0
fi

echo
echo "1/3 copy (through a pipe: the dump is not written to disk)"
# --no-owner/--no-privileges: production roles do not exist in the sandbox.
# --exclude-table-data: minimisation — audit logs are not needed for testing.
pg_dump \
  --host="$PROD_HOST" --username="$PROD_USER" --dbname="$PROD_DB" \
  --no-owner --no-privileges --clean --if-exists \
  --exclude-table-data='audit_logs' \
  --exclude-table-data='sessioni' \
| psql --host="$SANDBOX_HOST" --port="$SANDBOX_PORT" --username="$SANDBOX_USER" \
       --dbname="$SANDBOX_DB" --quiet --set=ON_ERROR_STOP=1

echo "2/3 anonymisation"
# Fail-closed: if the anonymisation does not pass, the sandbox is left with real data.
# Better to know right away and loudly than to find out in a screenshot.
if ! psql --host="$SANDBOX_HOST" --port="$SANDBOX_PORT" --username="$SANDBOX_USER" \
          --dbname="$SANDBOX_DB" --quiet --set=ON_ERROR_STOP=1 --file="$ANONIMIZZA"; then
  echo >&2
  echo "ANONYMISATION FAILED: the sandbox contains real personal data." >&2
  echo "Do not use it and do not take screenshots of it. Recreate it before continuing." >&2
  exit 2
fi

echo "3/3 check"
# One question only, but the right one: is anything recognisable left?
residui=$(psql --host="$SANDBOX_HOST" --port="$SANDBOX_PORT" --username="$SANDBOX_USER" \
               --dbname="$SANDBOX_DB" -At \
               -c "SELECT count(*) FROM utenti WHERE email NOT LIKE '%@esempio.invalid'")
if [ "$residui" != "0" ]; then
  echo "ANONYMISATION INCOMPLETE: $residui rows with a real email." >&2
  exit 2
fi

echo "done: $SANDBOX_DB ready, $residui real addresses left."
