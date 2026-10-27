#!/usr/bin/env bash
# Test fixture: a script the hook would stop, but which is declared in
# allow_scripts with its fingerprint. It verifies the exemption. Do not run it.
set -e
BUILD_DIR=build
rsync -a --delete "$BUILD_DIR/" user@host:/srv/www/
