#!/usr/bin/env bash
# Test fixture: a shell script whose comments quote commands the hook would
# object to. A full-line comment never runs. On 2026-11-08 iro's deploy-ovh.sh
# was denied for a comment like the next one. Do not run it.
#
#   python3 tools/deploy-ftp.py --remove tests/README.md   # unpublish
#   scripts/deploy/promote-to-production.sh                # the forbidden one
#   rm -rf "$HOME"/.[!.]*                                  # the 2026-09-11 form
set -e
echo "nothing dangerous here"
