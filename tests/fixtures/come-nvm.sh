#!/usr/bin/env bash
# Fixture di test: due forme di ~/.nvm/nvm.sh che confondevano il hook. La
# seconda, divisa su `$(`, lasciava un `"` orfano che come path valeva la
# directory di lavoro: `source ~/.nvm/nvm.sh` era negato come se togliesse il
# .guardrail.json del progetto. Non eseguirlo.
nvm_svuota_cache() {
  command rm -rf \
    "${CACHE_DIR}/bin/files" \
    "${CACHE_DIR}/src/files"
}
nvm_disinstalla() {
  command rm -f "${NVM_DIR}/v*" "$(nvm_version_dir)/x"
}
