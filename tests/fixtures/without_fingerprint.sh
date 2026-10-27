#!/usr/bin/env bash
# Test fixture: a script listed in allow_scripts without a sha256. The exemption
# must not apply: an incomplete entry approves nothing. Do not run it.
set -e
rsync -a --delete dist/ user@host:/srv/www/
