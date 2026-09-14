# Deploy e infrastruttura

Vale per build di immagini, registry, Azure (Container Apps, Static Web Apps,
Key Vault, Blob), FTP/SFTP verso hosting, script di promozione e rollback,
Docker locale.

## Regole di condotta

- **La produzione non parte mai da sola.** Un deploy in produzione è un'azione
  umana: l'agente prepara, verifica, mostra il comando, e si ferma. Vale anche
  quando "manca solo l'ultimo passo".
- **Prima il dry-run, poi l'utente.** Ogni strumento che sincronizza (lftp,
  rsync, `az storage blob sync`, `swa deploy`) si esegue prima in modalità
  dry-run e l'output si mostra per intero. L'esecuzione vera è una decisione
  dell'utente, non dell'agente.
- **Niente cancellazione implicita.** `--delete`, `--prune`, `--force`: un file
  rimosso in locale resta online finché un umano non lo toglie con una lista
  esplicita. Il 2026-09-11 un subagent che doveva solo *studiare* uno script con
  `mirror --delete` ha cancellato la home dello sviluppatore.
- **Gli script di deploy non contengono segreti.** Credenziali in `.env`
  gitignorato o nel Key Vault; lo script le legge dall'ambiente e fallisce se
  mancano. Una password su una riga di comando finisce in `ps` e nella history.
- **Usa gli script correnti, nella directory giusta.** Se esistono script omonimi
  in directory diverse — tipico quando una migrazione di infrastruttura lascia in
  piedi la versione vecchia — chiedi prima. Sbagliare directory = deploy nel
  vuoto.
- **Il gate di test non si salta.** `--skip-tests` esiste per le emergenze e va
  dichiarato nel messaggio all'utente e nel log di deploy. Un'immagine buildata
  senza test non si promuove.
- **Feature rischiose nascono spente**: dietro un flag fail-closed, e si accendono
  in un cambio separato, dopo misura sull'ambiente di test.
- **Scheduler e worker dentro il container**: alzare le repliche sopra 1 esegue
  N volte ogni task schedulato. Verifica prima di scalare.
- **Container e volumi locali**: `docker system prune`, `volume rm`, `compose
  down -v` cancellano database locali. Elenca cosa sparisce, poi conferma.
- **Simulare un deploy in locale** non significa usare la home come bersaglio:
  finto server e finta home vivono nello scratchpad, con path letterali, e la
  pulizia finale cancella solo quello che si è creato, per nome.

## Cosa fa rispettare il hook

| Azione | Esito |
|---|---|
| `lftp … mirror … --delete` senza `--dry-run` | BLOCCO |
| `rsync … --delete` senza `--dry-run`/`-n` | BLOCCO |
| `docker system prune`, `docker volume rm/prune`, `compose down -v` | CONFERMA |
| `curl … \| sh`, `wget … \| bash` | BLOCCO |
| `chmod 777`, `mkfs`, `dd of=/dev/…`, `wsl --unregister` | BLOCCO |
| Comandi elencati in `deny_commands` del repo (es. script di promozione dismessi) | BLOCCO |
| Comandi elencati in `ask_commands` del repo (es. `promote-to-production.sh`) | CONFERMA |
