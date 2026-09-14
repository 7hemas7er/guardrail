#!/usr/bin/env bash
# Trova un Python 3 funzionante ed esegue lo script passato come primo argomento.
# Stesso schema del plugin ufficiale security-guidance: su Windows + Git Bash
# `python3` può essere lo stub dello Store, che esce in silenzio; si prova ogni
# candidato con `-c ""` e si usa il primo che risponde.
set -e
export PYTHONUTF8=1
script="$1"; shift || true
for candidate in python3 python "py -3"; do
  # shellcheck disable=SC2086
  if $candidate -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    exec $candidate "$script" "$@"
  fi
done
echo "[guardrail] nessun Python 3 trovato: hook non eseguito" >&2
exit 0
