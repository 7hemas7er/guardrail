#!/usr/bin/env bash
# Test fixture: a shell script with a .py suffix. Run with `bash` or directly,
# it is shell whatever its name, and the project rules apply. Do not run it.
set -e
scripts/deploy/promote-to-production.sh
