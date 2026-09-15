#!/usr/bin/env bash
# Fixture di test: uno script qualunque, senza comandi che il hook debba fermare.
set -e
echo "build in corso"
mkdir -p build
cp -r src/. build/
