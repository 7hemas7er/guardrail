#!/usr/bin/env bash
# Test fixture: two forms from ~/.nvm/nvm.sh that confused the hook. The second,
# split on `$(`, left an orphan `"` that as a path meant the working directory:
# `source ~/.nvm/nvm.sh` was denied as if it removed the project's
# .guardrail.json. Do not run it.
nvm_clear_cache() {
  command rm -rf \
    "${CACHE_DIR}/bin/files" \
    "${CACHE_DIR}/src/files"
}
nvm_uninstall() {
  command rm -f "${NVM_DIR}/v*" "$(nvm_version_dir)/x"
}
