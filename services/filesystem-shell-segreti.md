# Filesystem, shell e segreti

Il servizio più pericoloso, perché non sembra un servizio: è la shell che ogni
agente usa per tutto il resto.

## Il caso che ha generato questo file

2026-09-11, 14:38. Un subagent di un workflow in modalità auto doveva verificare
cosa avrebbe fatto uno script di deploy. Ha costruito una simulazione nello
scratchpad, con una finta `HOME`, e alla fine ha ripulito. La pulizia, con ogni
probabilità nella forma `rm -rf "$HOME"/.[!.]* "$S"`, è stata eseguita in una
shell dove `HOME` era di nuovo quella vera. Risultato: tutti i dotfile della home
cancellati, credenziali comprese. Il classificatore di sicurezza aveva approvato
il comando: non risolve le variabili.

## Regole di condotta

- **Mai variabili in un comando distruttivo.** Non `rm -rf "$DIR"`, non
  `rm -rf "$HOME/..."`, non `rsync --delete "$SRC" "$DST"`. Il bersaglio è un path
  letterale, relativo al progetto. Se il path lo hai calcolato, stampalo, fallo
  vedere, e usa quello stampato.
- **Mai glob nascosti.** `.*`, `.[!.]*`, `..?*` prendono tutto ciò che inizia
  con il punto, e in una home quello è tutto. Se devi togliere `.cache`, scrivi
  `.cache`.
- **Prima di cancellare, elenca.** `ls -la <bersaglio>` o `find <bersaglio>
  -maxdepth 1` mostrati all'utente; poi il comando di cancellazione, con lo
  stesso path identico.
- **`set -e` non è una protezione.** Ferma lo script dopo un errore, non prima
  di un `rm` che riesce. Non contare su di esso per la sicurezza.
- **Pulizie di fine lavoro**: cancella solo ciò che hai creato, per nome, uno per
  uno. Non "tutto quello che c'è nella cartella temporanea".
- **La home non è un'area di lavoro.** `~/.config`, `~/.claude`, `~/.ssh`,
  `~/.bashrc` si toccano solo su richiesta esplicita, e mai con comandi
  ricorsivi.
- **Segreti**: non leggere `.env*`, `*.pem`, chiavi, token; non stamparli in chat
  (finiscono nella trascrizione su disco); non copiarli in file tracciati.
  Serve un valore? Chiedilo all'utente. Serve solo il nome della variabile?
  Leggi `.env.example`.
- **Isolare un test non significa cambiare `HOME`.** Usa directory dedicate e
  opzioni esplicite dello strumento (`--config`, `--credentials <file>`); se
  proprio serve `HOME`, esportala per l'intero script in una subshell
  `( export HOME=…; … )`, così anche la pulizia la vede.
- **`sudo`**: mai per cancellare. Se serve, l'utente lo lancia.
- **Backup prima di cambiare l'ambiente**: prima di riscrivere un dotfile,
  copialo accanto con suffisso `.bak-<data>`.

## Cosa fa rispettare il hook

| Azione | Esito |
|---|---|
| `rm -r` con bersaglio variabile (`$X`, `${X}`), e `rm` (ricorsivo o no) su `~`, `/home/<utente>`, radice di sistema, `.`, `..`, glob nascosti, `*` | BLOCCO |
| `rm` non ricorsivo con bersaglio variabile (`rm -f "$FILE"`) | CONFERMA |
| `find … -delete`, `find … -exec rm` | CONFERMA; BLOCCO se la radice del find è uno dei bersagli sopra |
| `sudo rm` | BLOCCO |
| `sudo <qualunque altra cosa>` | CONFERMA |
| `chmod`/`chown` ricorsivi sulla home o sulla radice | BLOCCO |
| `mkfs`, `dd of=/dev/`, `chmod 777`, `curl \| sh`, `base64 -d \| sh` | BLOCCO |
| `git clean -x` | BLOCCO |
| Lettura (`Read`) di `.env*`, `.secrets`, chiavi, `.netrc`, `.pgpass`, `.npmrc`, `.git-credentials`, `~/.claude.json`, o dentro `~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.gnupg`, `~/.docker/config.json` | BLOCCO |
| `cat`, `grep`, `head`, `sed`… sugli stessi file da shell | BLOCCO |
| `source .env` | CONFERMA |
| Scrittura da shell (`>`, `tee`, `cp`, `sed -i`…) sugli stessi file | CONFERMA |
| Scrittura (Write/Edit) su `~/.ssh/*`, chiavi private, `/etc`, `/usr` | BLOCCO |
| Scrittura su `.env*` (tranne `.example`/`.sample`/`.template`/`.dist`) e sugli altri file di segreti | CONFERMA |
| Scrittura su un dotfile di primo livello della home (`~/.bashrc`, `~/.gitconfig`…) | CONFERMA |
| Scrittura, da tool o da shell, su `.guardrail.json`, `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.claude/commands|skills|agents|rules` | CONFERMA |
| Scrittura, da tool o da shell, in `~/.claude/plugins` o `~/.claude/hooks` (il codice di guardrail stesso) | BLOCCO |
| Scrittura (Write/Edit) fuori dal progetto corrente, dallo scratchpad e dalla memoria di Claude Code | CONFERMA |

Le letture di segreti sono presidiate sia sul tool `Read` sia sulla shell: le
`permissions.deny` delle impostazioni valgono solo per `Read`, e un `cat .env`
passerebbe. Tenerle resta utile come difesa in profondità.

Le conferme e i blocchi sulla configurazione di guardrail e di Claude Code — dal
tool e dalla shell, perché `echo '{}' > .guardrail.json` è una scrittura quanto
una `Write` — servono a una cosa sola: un agente che ha ricevuto un blocco non
può allentare da solo le regole che lo vincolano (regola 8).

L'ultima riga è la regola 5 resa esecutiva: il progetto è la root git della
directory di lavoro; tutto ciò che sta fuori (home, altri repo, `/opt`) richiede
una conferma. Lo scratchpad della sessione e la memoria di Claude Code
(`~/.claude/projects`) sono aree di lavoro legittime e non la richiedono.

Sugli heredoc: uno che scrive su file (`cat > README.md <<EOF`) contiene dati, e
il hook non lo legge come comandi — citare `rm -rf ~` in una guida non è
eseguirlo. Uno che alimenta un interprete (`bash <<EOF`, `python - <<PY`) resta
comandi a tutti gli effetti. Uno script scritto su file e poi lanciato viene
scansionato al momento del lancio (vedi deploy-infrastruttura.md).
