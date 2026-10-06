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
| Rimozione da shell di `.guardrail.json` (`rm`, `unlink`, `mv` come sorgente, `git rm`, `git mv`, `find … -delete`), anche con un glob (`.guardrail*`), con maiuscole diverse, insieme alla cartella che lo contiene (`rm -rf progetto`, `git rm -r .`) o dentro uno script lanciato | BLOCCO |
| Un secondo nome per `.guardrail.json` (`ln`, `cp -l`, `cp -s`) | BLOCCO |
| Scrittura (Write/Edit) su `.claude/settings.json`, `.claude/settings.local.json`, `.claude/CLAUDE.md` e su `.claude/hooks|commands|skills|agents|rules` di un progetto | CONFERMA |
| Scrittura, da tool o da shell, in `~/.claude/plugins` o `~/.claude/hooks` (il codice di guardrail stesso) | BLOCCO |
| Scrittura (Write/Edit) fuori dal progetto corrente, dallo scratchpad e dalla memoria di Claude Code | CONFERMA |
| Codice passato a una shell come stringa (`bash -c "…"`, `sh -c '…'`, `eval …`, `ssh host "…"`): analizzato con le stesse regole, stesso esito | come il comando che contiene |

Su quest'ultima riga: il primo token di una stringa passata a una shell è
posizione di comando, quindi `bash -c "rm -rf $HOME"` vale esattamente
`rm -rf "$HOME"`, annidamenti compresi. La stringa l'ha scritta l'agente in quel
momento, non un umano in un file del repo: per questo il `BLOCCO` resta blocco e
non viene declassato a conferma, come invece accade per uno script invocato.
Citare non è eseguire: in `grep "bash -c 'rm -rf'"` il comando è `grep`, e non
succede niente.

**Limite dichiarato**: un interprete che *non* è una shell resta in gran parte
fuori. Del codice passato come stringa (`python3 -c`, `node -e`) il hook guarda
una cosa sola: se chiama API che scrivono o lanciano processi. Se no, le stringhe
che contiene sono dati, e un `node -e` che legge un file sotto
`.claude/plugins` non lo modifica. Se sì, un `python3 -c` che nomina
`.guardrail.json` o le settings chiede conferma. Negli heredoc diretti a Python
o Node (`python3 - <<'PY'`, `node <<'JS'`, e `node -e 'eval(…readFileSync(0…))'`
dove il corpo è il programma) il hook va più a fondo: ne legge il codice, salta
commenti e stringhe che nessuno passa, e le stringhe **letterali** date a
`os.system`, `os.popen`, `subprocess.*(…, shell=True)`, `subprocess.getoutput`,
`child_process.exec`/`execSync` (e `spawn`/`execFile` con `shell`) le giudica come
comandi Bash, con le stesse regole, quelle di progetto comprese e con lo stesso
tetto di profondità: `os.system('rm -rf ~')` vale `rm -rf ~`. Una stringa
costruita (`'rm -rf ' + d`, un f-string, `%s`, `${x}`) conta con un segnaposto di
variabile al posto di ciò che non si legge, e una variabile in un comando
distruttivo è vietata. Una lista di argomenti senza shell
(`subprocess.run(['git', 'status'])`) non lancia una shell e resta ammessa.
`eval`/`exec` di un letterale si leggono come codice a loro volta. Restano
fuori: un comando che il codice costruisce senza nessun letterale
(`os.system(cmd)`), la stessa lettura dentro `python3 -c "…"` o `node -e '…'`
(lì valgono solo i controlli sui path protetti), Ruby, Perl, PHP e R, e un
programma che confonde il lettore (una regex JavaScript con un apice dentro:
se le virgolette non tornano si rilegge tutto senza saltare niente, ma una
stringa bilanciata ad arte nasconde la chiamata). Un progetto può stringere con
una regola sua in `deny_commands` (es. `os\.system`), ma sappia che vale per
`python3 -c "…"` e **non** dentro un heredoc: là il corpo è escluso dalle regex
di progetto di proposito, perché un path citato in uno script non è un path
eseguito; le stringhe che quel codice passa alla shell, invece, le vedono.

Le letture di segreti sono presidiate sia sul tool `Read` sia sulla shell: le
`permissions.deny` delle impostazioni valgono solo per `Read`, e un `cat .env`
passerebbe. Tenerle resta utile come difesa in profondità.

Le conferme e i blocchi sulla configurazione di guardrail e di Claude Code — dal
tool e dalla shell, perché `echo '{}' > .guardrail.json` è una scrittura quanto
una `Write` — servono a una cosa sola: un agente che ha ricevuto un blocco non
può allentare da solo le regole che lo vincolano (regola 8).

Togliere `.guardrail.json` è un blocco e non una conferma perché, dalla 0.10,
è quel file ad accendere guardrail nel progetto: senza, il hook non controlla
più niente. Una conferma in modalità auto la concede l'agente, e spegnere le
regole che lo vincolano non può essere una sua decisione. Modificarlo resta una
conferma: qualunque contenuto, anche `{}`, lo lascia acceso.

Queste regole sulla configurazione e sul codice di guardrail valgono anche nelle
cartelle dove guardrail è spento, le sole a farlo: da lì si raggiungono i
`.guardrail.json` degli altri progetti, `~/.guardrail.json` (che si somma a ogni
progetto acceso), le settings dei progetti (`enabledPlugins` spegne il plugin) e
il codice del plugin. Per guardrail è acceso qualunque voce si chiami
`.guardrail.json`, non solo un file: un link a `/dev/null` al suo posto non lo
spegne.

Si guarda anche dove porta un percorso: scrivere su `note.json` che è un link a
`.guardrail.json` è scrivere su `.guardrail.json`. E dove guardrail è acceso
queste regole vengono prima di `allow_commands`, che non le esenta.

**Limite dichiarato**: sono espressioni regolari su un comando di shell, e una
variante che non prevedono si trova sempre. Un interprete che non è una shell
resta fuori, come per ogni altra regola, salvo il caso descritto sopra; un
`.guardrail.json` più profondo di due livelli sotto la cartella cancellata non
viene cercato. Proteggono da un agente che sbaglia, non da uno che cerca il buco.

Una copia del progetto in una cartella temporanea (`/tmp`, `$TMPDIR`) e fuori
dalla home — un `git checkout-index`, un `git archive`, un `cp -r` nello
scratchpad — si porta dietro `.guardrail.json` e `.claude/`, che lì non accendono
né configurano niente: toglierla o riscriverne le settings non chiede niente. Il
controllo torna se la sessione ci lavora dentro (directory di lavoro o progetto
della sessione). Il path deve essere letterale: `rm -rf "$T"` non si sa dove
porta, e resta bloccato.

L'ultima riga è la regola 5 resa esecutiva: il progetto è la root git della
directory di lavoro; tutto ciò che sta fuori (home, altri repo, `/opt`) richiede
una conferma. Lo scratchpad della sessione e la memoria di Claude Code
(`~/.claude/projects`) sono aree di lavoro legittime e non la richiedono.

Sugli heredoc: uno che scrive su file (`cat > README.md <<EOF`, `git commit -F -
<<EOF`) contiene dati, e il hook non lo legge come comandi — citare `rm -rf ~`
in una guida non è eseguirlo; a meno che ciò che scrive finisca in una shell
(`tee x <<EOF | bash`, `tee x <<'EOF' >(bash)`: tee scrive anche nella process
substitution). Con il tag **senza virgolette**, invece, la shell esegue `$(…)` e
i backtick del corpo *prima* di darlo a chiunque, `cat` e `git` compresi: di quel
corpo il hook toglie il testo e tiene le sostituzioni, che giudica come comandi
(e che le regole di progetto vedono), qualunque sia il ricevente, interpreti
compresi. Con il tag fra virgolette sono testo. I backtick fuori da un heredoc
valgono come `$(…)`, tranne fra apici singoli e nei commenti. Chi riceve
l'heredoc si legge come lo legge la shell, virgolette comprese: se la riga non si
capisce, il corpo resta analizzato. Uno che alimenta una shell (`bash <<EOF`)
resta comandi a tutti gli effetti. Uno che alimenta Python o Node (`python - <<PY`,
`node <<JS`) è un programma: se lancia processi il corpo resta analizzato anche
come testo di shell, e le stringhe date ai lanciatori si giudicano come sopra.
Se il codice è passato con `-c`/`-e` e legge lo stdin lanciando processi
(`python3 -c 'import os; os.system(input())' <<EOF`), il corpo è un comando di
shell e resta analizzato per intero. Ruby, Perl e PHP restano sempre analizzati.
Uno script scritto su file e poi lanciato viene
scansionato al momento del lancio (vedi deploy-infrastruttura.md).
