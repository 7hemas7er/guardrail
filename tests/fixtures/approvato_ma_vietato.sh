#!/usr/bin/env bash
# Fixture di test: uno script approvato in allow_scripts che però invoca un
# comando presente in deny_commands. L'approvazione non deve salvarlo: la lista
# dei comandi vietati vale anche dentro uno script letto e approvato.
# Non eseguirlo.
set -e
scripts/deploy/promote-to-production.sh
