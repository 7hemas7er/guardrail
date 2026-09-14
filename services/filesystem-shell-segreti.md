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
| `rm -r` con bersaglio variabile (`$X`, `${X}`), `~`, `/home/<utente>`, radice di sistema, `.`, `..`, glob nascosti, `*` | BLOCCO |
| `sudo rm` | BLOCCO |
| `mkfs`, `dd of=/dev/`, `chmod 777`, `curl \| sh` | BLOCCO |
| Scrittura (Write/Edit) su `~/.ssh/*`, chiavi private, `/etc`, `/usr` | BLOCCO |
| Scrittura su `.env*` (tranne `.example`/`.sample`/`.template`/`.dist`), `.secrets`, `.netrc`, `.pgpass` | CONFERMA |
| Scrittura su un dotfile di primo livello della home (`~/.bashrc`, `~/.gitconfig`…) | CONFERMA |
| `git clean -x` | BLOCCO |

Le letture di `.env*` e `.secrets` sono negate dalle impostazioni consigliate
(`examples/settings.example.json`, chiave `permissions.deny`), non dal hook.
