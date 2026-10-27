#!/usr/bin/env bash
# Test fixture: a script approved in allow_scripts that nevertheless invokes a
# command listed in deny_commands. The approval must not save it: the list of
# forbidden commands applies even inside a script that was read and approved.
# Do not run it.
set -e
scripts/deploy/promote-to-production.sh
