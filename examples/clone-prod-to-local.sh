#!/usr/bin/env bash
#
# Clone di produzione dentro la sandbox locale — script di riferimento.
#
# Copialo in `scripts/clone-prod-to-local.sh` nel tuo progetto, adatta le tabelle
# e la query di anonimizzazione, e dichiaralo in `.guardrail.json`:
#
#     "ask_commands": ["scripts/clone-prod-to-local\\.sh"]
#
# così ogni esecuzione chiede conferma, anche in modalità auto.
#
# Le condizioni che rendono questo clone legittimo stanno in
# `services/database.md`, sezione «Ambiente di prova clonato da produzione».
# Qui sono implementate così:
#
#   una direzione sola   produzione compare solo in `pg_dump`, mai come bersaglio;
#                        lo script si rifiuta di scrivere su un host non locale
#   niente dump a riposo il dump non tocca il disco: passa in pipe nella sandbox
#   anonimizzazione      subito dopo il restore, nella stessa esecuzione, e se
#                        fallisce la sandbox viene lasciata inutilizzabile apposta
#   segreti              le credenziali arrivano dall'ambiente e non si stampano
#   bersaglio usa e getta  un database della sandbox, dichiarato per nome
#
set -euo pipefail

# --- Parametri: dall'ambiente, mai sulla riga di comando (finirebbero in `ps`).
# Sorgente (produzione): utente READ-ONLY, sempre.
: "${PROD_HOST:?manca PROD_HOST}"
: "${PROD_DB:?manca PROD_DB}"
# PROD_USER deve essere l'utente read-only di produzione.
: "${PROD_USER:?manca PROD_USER}"
# PGPASSWORD si esporta dall'ambiente o dal .env gitignorato, non si scrive qui.
: "${PGPASSWORD:?manca PGPASSWORD}"

# Bersaglio (sandbox locale): container usa e getta, porta dedicata.
SANDBOX_HOST="${SANDBOX_HOST:-127.0.0.1}"
SANDBOX_PORT="${SANDBOX_PORT:-55432}"
SANDBOX_DB="${SANDBOX_DB:-appdb_sandbox}"
SANDBOX_USER="${SANDBOX_USER:-postgres}"
ANONIMIZZA="${ANONIMIZZA:-scripts/anonimizza.sql}"

# --- Il bersaglio deve essere locale. Questo controllo è il cuore dello script:
# se qualcuno passa un host remoto, il clone diventa una scrittura in produzione.
case "$SANDBOX_HOST" in
  127.0.0.1|localhost|::1|host.docker.internal) ;;
  *)
    echo "rifiuto: il bersaglio ($SANDBOX_HOST) non è locale. Il clone va in una" >&2
    echo "direzione sola: produzione -> sandbox. Vedi services/database.md." >&2
    exit 1
    ;;
esac

if [ ! -f "$ANONIMIZZA" ]; then
  echo "rifiuto: manca $ANONIMIZZA. Senza anonimizzazione il clone non parte." >&2
  exit 1
fi

echo "sorgente : $PROD_USER@$PROD_HOST/$PROD_DB (sola lettura)"
echo "bersaglio: $SANDBOX_USER@$SANDBOX_HOST:$SANDBOX_PORT/$SANDBOX_DB"
echo "anonimizzazione: $ANONIMIZZA"

if [ "${1:-}" = "--dry-run" ]; then
  echo
  echo "dry-run: non viene eseguito niente. Righe che verrebbero copiate:"
  psql -h "$PROD_HOST" -U "$PROD_USER" -d "$PROD_DB" -At \
    -c "SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 15"
  exit 0
fi

echo
echo "1/3 copia (in pipe: il dump non viene scritto su disco)"
# --no-owner/--no-privileges: i ruoli di produzione non esistono nella sandbox.
# --exclude-table-data: minimizzazione — i log di audit non servono per provare.
pg_dump \
  --host="$PROD_HOST" --username="$PROD_USER" --dbname="$PROD_DB" \
  --no-owner --no-privileges --clean --if-exists \
  --exclude-table-data='audit_logs' \
  --exclude-table-data='sessioni' \
| psql --host="$SANDBOX_HOST" --port="$SANDBOX_PORT" --username="$SANDBOX_USER" \
       --dbname="$SANDBOX_DB" --quiet --set=ON_ERROR_STOP=1

echo "2/3 anonimizzazione"
# Fail-closed: se l'anonimizzazione non passa, la sandbox resta con dati veri.
# Meglio saperlo subito e rumorosamente che scoprirlo in uno screenshot.
if ! psql --host="$SANDBOX_HOST" --port="$SANDBOX_PORT" --username="$SANDBOX_USER" \
          --dbname="$SANDBOX_DB" --quiet --set=ON_ERROR_STOP=1 --file="$ANONIMIZZA"; then
  echo >&2
  echo "ANONIMIZZAZIONE FALLITA: la sandbox contiene dati personali veri." >&2
  echo "Non usarla e non farne screenshot. Ricreala prima di continuare." >&2
  exit 2
fi

echo "3/3 verifica"
# Una sola domanda, ma quella giusta: è rimasto qualcosa di riconoscibile?
residui=$(psql --host="$SANDBOX_HOST" --port="$SANDBOX_PORT" --username="$SANDBOX_USER" \
               --dbname="$SANDBOX_DB" -At \
               -c "SELECT count(*) FROM utenti WHERE email NOT LIKE '%@esempio.invalid'")
if [ "$residui" != "0" ]; then
  echo "ANONIMIZZAZIONE INCOMPLETA: $residui righe con email reale." >&2
  exit 2
fi

echo "fatto: $SANDBOX_DB pronta, $residui indirizzi reali rimasti."
