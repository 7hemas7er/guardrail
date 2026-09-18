#!/usr/bin/env bash
# Fixture di test: uno script che il hook fermerebbe, ma che è dichiarato in
# allow_scripts con la sua impronta. Serve a verificare l'esenzione. Non eseguirlo.
set -e
BUILD_DIR=build
rsync -a --delete "$BUILD_DIR/" user@host:/srv/www/
