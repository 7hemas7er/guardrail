# Deploy and infrastructure

Applies to image builds, registries, Azure (Container Apps, Static Web Apps,
Key Vault, Blob), FTP/SFTP towards hosting, promotion and rollback scripts,
local Docker.

## Rules of conduct

- **Production never starts on its own.** A production deploy is a human
  action: the agent prepares, verifies, shows the command, and stops. It holds
  even when "only the last step is missing".
- **Dry-run first, then the user.** Every tool that synchronizes (lftp, rsync,
  `az storage blob sync`, `swa deploy`) is run first in dry-run mode and the
  output is shown in full. The real run is the user's decision, not the
  agent's.
- **No implicit deletion.** `--delete`, `--prune`, `--force`: a file removed
  locally stays online until a human removes it with an explicit list. On
  2026-09-11 a subagent that was only supposed to *study* a script with
  `mirror --delete` deleted the developer's home directory.
- **Deploy scripts contain no secrets.** Credentials in a gitignored `.env` or
  in the Key Vault; the script reads them from the environment and fails if
  they are missing. A password on a command line ends up in `ps` and in the
  history.
- **Use the current scripts, in the right directory.** If scripts with the
  same name exist in different directories — typical when an infrastructure
  migration leaves the old version standing — ask first. Wrong directory =
  deploy into the void.
- **The test gate is not skipped.** `--skip-tests` exists for emergencies and
  must be declared in the message to the user and in the deploy log. An image
  built without tests is not promoted.
- **Risky features are born off**: behind a fail-closed flag, and are turned
  on in a separate change, after measuring on the test environment.
- **Scheduler and workers inside the container**: raising the replicas above 1
  runs every scheduled task N times. Check before scaling.
- **Local containers and volumes**: `docker system prune`, `volume rm`,
  `compose down -v` delete local databases. List what disappears, then
  confirm.
- **The test sandbox is declared, not improvised.** A stable environment for
  tests (app plus database in containers) has a dedicated compose, with its
  own project name, volumes and ports: no containers reused from another
  project, no default port taken at random, no volume from the home directory.
  The data comes from an anonymized clone of production, under the conditions
  in [`database.md`](database.md); production stays the source and never
  becomes the target.
- **Simulating a deploy locally** does not mean using the home directory as
  the target: fake server and fake home live in the scratchpad, with literal
  paths, and the final cleanup deletes only what was created, by name.

## What the hook enforces

| Action | Outcome |
|---|---|
| `lftp … mirror … --delete` without `--dry-run` | BLOCK |
| `rsync … --delete` without `--dry-run`/`-n` | BLOCK |
| `docker system prune`, `docker volume rm/prune`, `compose down -v` | CONFIRM |
| `curl … \| sh`, `wget … \| bash`, `base64 -d \| sh`, `echo … \| sh` | BLOCK |
| `chmod 777`, `mkfs`, `dd of=/dev/…`, `wsl --unregister` | BLOCK |
| `docker run -v ~:/…`, `-v /:/…`, `--mount source=/home/…`: the home directory or the root inside a container | CONFIRM |
| `sudo <anything>` (except `sudo rm`, which is a block) | CONFIRM |
| An invoked script (`bash x.sh`, `./x.sh`, `source x.sh`, `python x.py`) that contains a command the hook would block | CONFIRM |
| MCP call towards Azure and the like with `delete`/`purge`/`deallocate`… | CONFIRM; BLOCK if the server or the parameters are production |
| MCP call with `deploy`/`update`/`scale`/`restart` on production | BLOCK |
| Commands listed in the repo's `deny_commands` (e.g. retired promotion scripts) | BLOCK |
| Commands listed in the repo's `ask_commands` (e.g. `promote-to-production.sh`) | CONFIRM |

The invoked script is read by the hook and scanned with the same rules as the
direct command: an `rsync --delete` inside `deploy.sh` counts as much as an
`rsync --delete` typed by hand. The outcome is a confirmation, not a block,
because a human wrote the script and the human decides; the exception is a
command in `deny_commands`, which stays blocked even inside a script. The
syntax check (`bash -n deploy.sh`, `sh -n`, `dash -n`) executes nothing, and
is not scanned.

A script that is launched all the time can be approved once, in
`allow_scripts` of `.guardrail.json`, by declaring its sha256 fingerprint (see
README). The approval is tied to the content: if the script changes, the
confirmation comes back, with the notice that what is about to run is not what
was read. Approving by name, without a fingerprint, would be exactly the
2026-09-11 incident with a signature on top.
