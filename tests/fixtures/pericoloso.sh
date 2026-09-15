#!/usr/bin/env bash
# Fixture di test: uno script di deploy "vero" che il hook deve scansionare quando
# viene lanciato. Non eseguirlo.
set -e
BUILD_DIR=build
rsync -a --delete "$BUILD_DIR/" user@host:/srv/www/
