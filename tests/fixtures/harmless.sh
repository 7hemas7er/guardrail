#!/usr/bin/env bash
# Test fixture: an ordinary script, with no command the hook has to stop.
set -e
echo "build in progress"
mkdir -p build
cp -r src/. build/
