#!/usr/bin/env bash
# Fixture di test: uno script elencato in allow_scripts senza sha256. L'esenzione
# non deve valere: la voce incompleta non approva niente. Non eseguirlo.
set -e
rsync -a --delete dist/ user@host:/srv/www/
