#!/usr/bin/env bash
# Finds a working Python 3 and runs the script passed as the first argument.
# Same scheme as the official security-guidance plugin: on Windows + Git Bash
# `python3` may be the Store stub, which exits silently; every candidate is tried
# with `-c ""` and the first one that answers is used.
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
echo "[guardrail] no Python 3 found: hook not run" >&2
exit 0
