#!/usr/bin/env bash
# Test fixture: a "real" deploy script that the hook must scan when it is
# launched. Do not run it.
set -e
BUILD_DIR=build
rsync -a --delete "$BUILD_DIR/" user@host:/srv/www/
