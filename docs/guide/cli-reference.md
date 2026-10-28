# Command-line reference

This page lists every `backtide` command, its arguments and flags, what it prints and how it exits. It also lists the `make` targets you will use most.

> **Status: pre-alpha.** backtide is a working prototype. Everything here was checked against the code of this repository, but a command that works in the test setup may still be rough in yours. Read the [security model](security-model.md) before you rely on it.

Other guides: [getting started](getting-started.md), [configuration](configuration.md), [real run](real-run.md), [troubleshooting](troubleshooting.md).

## Read this first

**The command names are in Spanish, and so is most of the text they print.** backtide began as a Spanish-language project. The commands (`vigilar`, `verificar`, `rebobinar`…) and their messages are not translated yet. The web view and its Settings page do have an English version. The table below gives the English meaning of each command.

| Command | What it does, in English |
|---|---|
| `backtide vigilar` | Run the service: watch the agent ("vigilar" = to watch) |
| `backtide verificar` | Check that the black box has not been tampered with ("verify") |
| `backtide instantaneas` | List the snapshots ("snapshots") |
| `backtide rebobinar` | Rewind the agent's folder to a snapshot ("rewind") |
| `backtide seguir` | Resume an agent that was paused ("carry on") |
| `backtide retenidas` | List the requests held back, waiting for you ("held") |
| `backtide aprobar` | Approve one held request ("approve") |
| `backtide rechazar` | Reject one held request ("reject") |
| `backtide gasto` | Show today's and this month's model spending ("spending") |
| `backtide tope` | Show or change the spending cap ("cap") |
| `backtide web` | Open the web view on this computer |
| `backtide entrar` | Open the coding agent in your terminal ("enter") |
| `backtide tarea` | Give the coding agent one task ("task") |
| `backtide importar` | Copy a folder from your computer into the agent's workspace ("import") |
| `backtide exportar` | Copy the agent's work out to a new folder on your computer ("export") |
| `backtide comprobar` | Check whether this machine can run backtide ("check") |
| `backtide instalar` | Install backtide as a system service ("install"; `install.sh` calls it) |
| `backtide imagenes` | List the container images this version uses, pinned by digest ("images") |
| `backtide enlace` | Print the installed web's one-time link ("link") |

`backtide --version` prints the version (`backtide 0.1.0` today). `backtide` on its own, or `backtide --help`, prints the list of commands. Each command also answers to `--help`.

### Where you run them

backtide needs Linux with Docker and Btrfs. On a Mac that means the development VM described in the [README](../../README.md). Two ways to run a command:

- **Through `make`** (recommended). The demo and real-run targets call `backtide` for you inside the VM, with the right config file. See [the `make` table](#make-commands).
- **By hand, in the VM.** Open it with `make vm-shell`, go to the repository folder, and run:

  ```sh
  UV_PROJECT_ENVIRONMENT="$HOME/.venvs/vigia" uv run --locked backtide <command> --config "$HOME/backtide-demo-run/backtide.toml"
  ```

  `~/.venvs/vigia` and the VM name `vigia-dev` keep the project's old name on purpose: renaming them would force a rebuild.

Two commands, `verificar` and `web`, only read files, so you can also try them on the Mac with `uv run backtide …` (`make web-demo` is a variant of this, with invented data). The rest need Linux with Docker and Btrfs, and most need a running service.

### Four ideas used on this page

- **The service.** `backtide vigilar` is the one long-running program. It owns the agent's container, takes the snapshots, writes the black box and holds back dangerous requests. Most other commands do nothing by themselves: they ask the service.
- **The control socket.** A local file (`control.sock`, in the state folder) through which the other commands talk to the service. Only the service's own user can use it, and the agent's container cannot see it. That is why the agent cannot approve its own requests. So run these commands as the same user as the service. The installed web, which runs as its own unprivileged user, has a second, narrower socket (`web.sock`) for its group only, with a closed list of what it may ask (see `--grupo-web` and `--socket-web` below).
- **The config file.** `backtide.toml`, described in [configuration](configuration.md). Every command except `verificar` takes `--config` (see below).
- **The black box.** The append-only log of everything the agent did. Each event carries the hash of the one before, so any edit or deletion breaks the chain.

### Options every command shares

| Option | Default | Meaning |
|---|---|---|
| `--config FILE` | `/etc/backtide/backtide.toml` | The config file. Every command has it except `verificar`. In the development VM the file is `~/backtide-demo-run/backtide.toml`, written by `make demo` and `make probar`. |

### Exit codes

Scripts can rely on the exit code. The meaning is nearly the same for all commands:

| Code | Usual meaning |
|---|---|
| 0 | Done |
| 1 | Not done. Nothing changed, or the failure is the kind you should look at (no service running, you answered no, tampering found) |
| 2 | Usage or configuration error (a bad argument, an unreadable file, a config that does not validate). `argparse` also uses 2 for a mistyped flag |
| 3 | Unclear. The request went out, but backtide cannot say whether it was done, or it was done with a problem |

The exact meaning of each code for each command is given below.

## Record and watch

### `backtide vigilar`

Runs the service in the foreground. It starts the agent's container, the egress proxy, the process sensor and the file watcher. It takes a snapshot of the agent's folder whenever something changed, writes every event to the black box, and answers the other commands.

```sh
backtide vigilar [--config FILE] [--grupo-web GROUP]
```

- `--grupo-web GROUP` also opens the web's narrow socket, `web.sock` in the state folder (mode `660`, that group), for a web that does not run as the service's user. Through it the web can only list the snapshots, the held requests and what keys are set, and ask to rewind (to a snapshot in the list), approve or reject a held request, set or remove a key, and change the spending caps. Nothing else: no resume, no shell, no paths. The service checks the caller's group with the kernel (`SO_PEERCRED`), limits how many requests it takes, and records every change in the black box as coming from the web. The group cannot be root's, the agent's or the proxy's. The installed `backtide.service` passes `--grupo-web backtide-web`.

- Stop it with Ctrl-C or SIGTERM. **That also stops the agent**: backtide never leaves an agent running without a watcher.
- Only one service can run per state folder. A second `vigilar` stops with an error (exit 1).
- Prints `backtide arrancando. Ctrl-C o SIGTERM lo paran, y con él al agente.` and then log lines on stderr. On a clean stop: `backtide parado. El agente está parado.`
- If it cannot stop the agent, it says so in capital letters (`EL AGENTE SIGUE EN MARCHA`) and tells you the `docker` command to stop it.
- It refuses to start the agent if its container would see something of the host it must not see (the black box, the snapshots, the config, the Docker socket). That is exit 2 (exit 1 if an agent was left running), with an explanation.
- Exit codes: `0` stopped cleanly; `1` could not start, or could not stop the agent; `2` the configuration is not valid.

In practice you start it with `make demo` or `make probar`, which first prepare a throwaway Btrfs volume and a config file.

### `backtide web`

Serves the web view on `127.0.0.1` (this computer only): the live feed of what the agent does, the history with filters, the snapshots, the held requests and the Settings page. By default it only reads. The three flags below switch on the things that change state.

```sh
backtide web [--config FILE] [--puerto N] [--rebobinar] [--aprobar] [--ajustes] [--socket-web PATH]
```

| Flag | Default | Effect |
|---|---|---|
| `--puerto N` (alias `--port N`) | `8765` | Port on `127.0.0.1`. `0` picks a free one. Must be 0 to 65535 |
| `--rebobinar` | off | The Snapshots page can rewind (with the same notice as `rebobinar` and a confirmation) |
| `--aprobar` | off | The Requests page can approve and reject held requests (each behind a confirmation). Without it the buttons are shown switched off |
| `--ajustes` | off | The Settings page can set and remove API keys, the Telegram bot and the spending cap. Without it the page only explains how to switch it on |
| `--socket-web PATH` | off | Ask for all of the above, and for the snapshot list, through the service's narrow socket at `PATH` (the one `vigilar --grupo-web` opens) instead of the control socket. For a web that runs as an unprivileged user in that group. The socket and the process answering it must be root's, or nothing is sent. The installed `backtide-web.service` passes `--socket-web /var/lib/backtide/web.sock --rebobinar --aprobar --ajustes` |
| `--enlace-en FILE` | off | Write the one-time link (and the run name) to `FILE`, mode `600`, instead of printing it, and remove the file when the web stops. The installed `backtide-web.service` uses it so the link never lands in the system journal; `sudo backtide enlace` prints it |

How it behaves:

- It prints a one-time link and a **run name** of three words, for example `luna-pino-boya`. Open the link in your browser; backtide does not open anything itself. The run name must match the one in the page header: if it does not, the page is not from this run. The link works once; afterwards the page uses a cookie.
- It then prints three lines saying whether rewind, Settings and approval are on or off for this run, and why.
- `--rebobinar`, `--aprobar` and `--ajustes` ask the service through the control socket, so they only work when the web runs as the same user as the service and `backtide vigilar` is running. With `--socket-web` they ask through the narrow socket instead, which is how the installed web approves, rejects, rewinds and sets keys and caps without the service's privileges.
- **As root, the web refuses to start** unless at least one of the three flags is given. A viewer that only looks should run as an ordinary user with read permission on the black box. With a flag as root it starts, with a warning.
- The page language follows your browser's language (Spanish or English). Add `?lang=en` to the address to force English.
- It reads only the black box, the snapshot folder and the control socket path from the config. It never reads the black box's key.
- Exit codes: `0` stopped with Ctrl-C; `1` could not open the port; `2` bad config, a port out of range, or the root refusal.

Example, on the Mac with invented data (`make web-demo`) the output looks like this (the port and words change every run):

```text
Puesto de vigilancia listo, solo en este ordenador:

  http://127.0.0.1:53971/s/<random>/?t=<random>

Nombre de esta ejecución: luna-pino-boya
Debe ser el mismo que sale en la cabecera de la página: si no, no es esta.
El enlace vale una sola vez (después la página usa una cookie de este navegador). Ctrl-C la para.
Rebobinar desde la web: no; sin `--rebobinar` esta web solo mira. ...
Ajustes desde la web: no; sin `--ajustes` la página solo dice cómo encenderla.
Aprobar desde la web: no; sin `--aprobar` las peticiones retenidas se ven con los botones apagados. ...
```

## See and verify

### `backtide verificar`

Checks that the black box is intact. It re-computes the hash chain and compares it with the checkpoint (a small file, protected with the same key, that records where the chain ended; it is what detects deleted last events).

```sh
backtide verificar --db FILE --key FILE [--checkpoint FILE]
```

| Argument | Required | Meaning |
|---|---|---|
| `--db FILE` | yes | The black box database (`blackbox.db` in the state folder) |
| `--key FILE` | yes | The key file (`blackbox.key`). It must be a regular file, yours, mode `600`, 32 bytes |
| `--checkpoint FILE` | no | The checkpoint (`blackbox.checkpoint`). Without it, a warning says that deleted final events cannot be detected |

- It does not take `--config`: you point it at the files directly, so you can verify a copy somewhere else.
- It never writes anything and never creates a database: a missing file is an error, not an empty black box.
- Any exit code other than 0 should be treated as an alert.
- Exit codes: `0` intact; `1` tampering found; `2` a file is missing or unreadable (then it also prints `NO VERIFICADA: trátala como no íntegra`, "NOT VERIFIED: treat it as not intact").

Sample output, from a run on invented data:

```text
$ backtide verificar --db state/blackbox.db --key state/blackbox.key --checkpoint state/blackbox.checkpoint
OK: 891 eventos íntegros (último: 891)

$ backtide verificar --db state/blackbox.db --key state/blackbox.key
AVISO: no se ha indicado punto de control: no se puede comprobar si se han borrado los últimos eventos
OK: 891 eventos íntegros (último: 891)
```

When the chain is broken it prints one `MANIPULADO:` ("tampered") line per problem, up to 50 (then `… y N problemas más`), and a last line `La caja negra NO está íntegra: N problemas.` Typical lines, taken from the test suite: `MANIPULADO: evento 2: la huella no coincide`, `MANIPULADO: evento 3: se han borrado eventos del final`.

### `backtide instantaneas`

Lists the snapshots of the agent's workspace, newest first. It works without a running service.

```sh
backtide instantaneas [--config FILE] [--todas]
```

| Flag | Default | Effect |
|---|---|---|
| `--todas` | off | Show every snapshot. Without it, the 30 newest, then a line `… y N más (usa --todas para verlas todas)` |

Columns: the snapshot **id**, the local time, the reason and how long ago. Copy the id (first column) to `rebobinar`.

```text
INSTANTÁNEA                          HORA                 MOTIVO              HACE
20261023T115853.000000Z-pre_restore  2026-10-23 11:58:53  antes de rebobinar  hace 1 min
20261023T115553.000000Z-periodic     2026-10-23 11:55:53  periódica           hace 4 min
20261023T114753.000000Z-manual       2026-10-23 11:47:53  manual              hace 12 min
20261023T112953.000000Z-periodic     2026-10-23 11:29:53  periódica           hace 30 min
```

The id is the UTC time plus the reason. The reasons:

| Reason in the id | Printed as | Why the snapshot exists |
|---|---|---|
| `periodic` | periódica | Taken by the service when the folder changed. Only these are thinned out by retention |
| `manual` | manual | Taken on request |
| `pre_restore` | antes de rebobinar | The undo point saved just before a rewind |
| `recovered` | recuperada | Saved by crash recovery |
| `evidence` | de evidencia | Taken at once because an event had risk 3. Never deleted automatically |

With none: `No hay instantáneas todavía.` Exit codes: `0` listed; `2` the config or the snapshot folder cannot be read.

## Rewind

### `backtide rebobinar`

Sets the agent's workspace back to a snapshot. A rewind replaces the working folder and what the agent remembers in it. It cannot take back anything that already left the machine (an email sent, a payment).

```sh
backtide rebobinar ID [--config FILE] [--si]
```

| Argument | Meaning |
|---|---|
| `ID` | The snapshot id: copy it from the first column of `backtide instantaneas` |
| `--si` | Do not ask for confirmation. **Required when there is no terminal** (a script, a pipe) |

What happens:

1. The id is checked: it must have the shape of a snapshot id and exist.
2. backtide prints a notice: the time you will go back to, what is undone, what is not, and the agent-specific lines (for OpenClaw: Telegram, WhatsApp, Signal, IMAP). Read it. It is the same notice the web and Telegram show.
3. It asks `¿Rebobinar? [s/N]`. Only `s`, `si` or `sí` mean yes; anything else cancels with `No se ha hecho nada.` (exit 1).
4. If a service is running, backtide asks it through the control socket. The service stops the agent, swaps the folder and **starts the agent again**.
5. If no service is running, the rewind is done inside this process and **the agent is left stopped**: start it again with `backtide vigilar`. Ctrl-C is ignored during that rewind so it cannot be cut in half.
6. Afterwards it prints `Para deshacer: backtide rebobinar <id>`. Every rewind first saves an undo point (a `pre_restore` snapshot); that id undoes the rewind.

Exit codes: `0` rewound; `1` not done and the workspace did not change (you said no, or the service refused); `2` usage or read error (bad id, unknown snapshot, no terminal and no `--si`); `3` rewound with a problem afterwards, or backtide cannot tell.

Example (two terminals in the demo; `make demo-rebobinar` runs this for you):

```sh
backtide instantaneas --config ~/backtide-demo-run/backtide.toml
backtide rebobinar 20261023T115553.000000Z-periodic --config ~/backtide-demo-run/backtide.toml
```

## Pause and resume

### `backtide seguir`

Resumes an agent that backtide paused because it was running out of disk space (or could not record). The service refuses while the problem still stands. Pausing needs no command of its own on the terminal: the service pauses the agent automatically, and Telegram has `/pausar`.

```sh
backtide seguir [--config FILE]
```

- Needs a running service. Without one it says there is nothing to resume (exit 1). If a pause by space was open when the service stopped, the agent stays stopped on the next start until you run `seguir`.
- Exit codes: `0` resumed, or there was no pause; `1` not resumed (a condition still stands, another reason keeps it paused, or no service); `2` usage error; `3` cannot tell, or resumed with a problem.

## Approve what was held

The gate holds back requests that write or send something to the outside: a message, a delete, a push. Reads pass. A held request waits for you; if you do not answer in 5 minutes it is rejected. You can decide from Telegram, from the web (`--aprobar`) or from these commands. All three need a running service.

### `backtide retenidas`

Lists the held requests, oldest first.

```sh
backtide retenidas [--config FILE]
```

One block per request (the sample below is illustrative): the id (`h-` and 12 hex characters), the risk (0 to 3), the method and the target, the time left, and whether the agent is still waiting. A second line says what the request would do, when a translator understood it. The text of the target is cut to 160 characters, redacted, and escaped.

```text
h-3f9a1c0b7d2e  riesgo 2  POST gmail.googleapis.com/…  (caduca en 4 min 12 s; esperando conectada)
    <what the request would do, in the translator's words>

Apruébalas con `backtide aprobar <id>` o recházalas con `backtide rechazar <id>`. Sin respuesta, se rechazan solas a los 5 minutos.
```

With none: `No hay ninguna petición retenida esperando.` Exit codes: `0` listed; `1` no service; `2` error.

### `backtide aprobar` and `backtide rechazar`

```sh
backtide aprobar ID [--config FILE]
backtide rechazar ID [--config FILE]
```

- `ID` is the `h-…` id from `retenidas` or from the notice. Anything else is exit 2.
- **Approve lets that one request out, once.** If the agent was still waiting, it goes out now. If it had given up, the same request is let through once if it repeats it within 10 minutes.
- **Reject** stops the request. The same request is refused again without asking for 10 minutes.
- The decision is written to the black box (`gate/approved` or a rejection) with who made it.
- A hold only exists while the service runs: a restart of backtide or of the proxy closes every open hold.
- While the agent is paused or being rewound, nothing is approved.
- Exit codes: `0` decided; `1` there is no such open hold (already decided, expired, or lost in a restart), the agent is paused, or there is no service; `2` usage error (not an id, bad lock, refused); `3` cannot tell whether it was done.

## Coding agents: enter, task, import, export

These four commands exist for agents that run as a **shell program** inside the container instead of as a background service. Today that is the `claude-code` profile (Claude Code). With the default OpenClaw profile they stop with exit 2 and explain why. Choose the profile in `[agent] profile` ([configuration](configuration.md)). The design is in docs/34 (internal note) (in Spanish).

All four ask the running service first. The service records the request in the black box and checks that the agent is running, before anything happens.

### `backtide entrar`

Opens the agent's interactive program in your terminal, inside the agent's container, as the agent's user and in its working folder (`/workspace/work`). Everything it does is recorded and can be rewound.

```sh
backtide entrar [--config FILE] [--continue]
```

| Flag | Effect |
|---|---|
| `--continue` | Continue the last conversation (for example after a rewind, when the conversation is restored from the snapshot) |

Prints `Entrando en el agente (sal con /exit o Ctrl-D). Todo lo que haga queda grabado.` When the session ends, backtide puts your terminal back as it was and prints `Sesión de Claude Code cerrada. Estás otra vez en tu terminal.` Exit codes: `0` the session ended normally; `1` it could not open or ended with an error (code 137 means it was cut, for example by a rewind); `2` usage error (for example, not a shell-mode agent).

### `backtide tarea`

Gives the agent one task without opening an interactive session, and prints its answer.

```sh
backtide tarea "TASK TEXT" [--config FILE] [--continue] [--minutos N]
```

| Argument / flag | Default | Effect |
|---|---|---|
| `TASK TEXT` | required | What you ask, in quotes. It is passed as one single argument, never through a shell |
| `--continue` | off | Continue the last conversation. Refused if another task is still running inside the agent |
| `--minutos N` | `60` | Maximum wait, in minutes. Above 0 and up to 1440 (24 hours) |

When the time runs out, the task is stopped inside the container (`la tarea se ha cortado`). Exit codes: `0` done; `1` it ended with an error, or it was cut by the time limit or a rewind; `2` usage error; `3` unknown (for example the connection to Docker failed and the task may still be running).

```sh
backtide tarea "List the files in this folder and say what the project does" --config ~/backtide-demo-run/backtide.toml
```

### `backtide importar`

Copies a folder from your computer into the agent's workspace, at `/workspace/work/<name>`.

```sh
backtide importar FOLDER [--config FILE] [--nombre NAME] [--reemplazar] [--incluir-secretos]
```

| Argument / flag | Default | Effect |
|---|---|---|
| `FOLDER` | required | The folder on your computer. Must be a real folder (not a symbolic link). Never your home folder, a folder above it, `~/.ssh` or `~/.aws` and similar key folders |
| `--nombre NAME` | the folder's own name | Name in the agent. Letters, digits, `.`, `_`, `-`; up to 100 characters |
| `--reemplazar` | off | Write over the folder if it already exists. Without it, an existing folder is never touched |
| `--incluir-secretos` | off | Also copy what looks like a secret. By default these are left out and named |

What the import does and does not copy:

- It does not follow symbolic links. It skips them and lists up to 10 of them. It copies only files and folders.
- Limits: 1 GiB, 100,000 entries, 64 levels deep, 30 minutes. Over a limit, nothing is imported.
- It leaves out what looks like a secret: key folders (`.ssh`, `.aws`, `.gnupg`…), `.env*`, `.npmrc`, `.netrc`, private keys and certificates (`*.pem`, `*.key`…), a git config with a password or token in a remote URL, and agent configs that contain a token (`.mcp.json` and similar). It prints each name it left out, so you can decide. Add `--incluir-secretos` only if the agent really needs them: it will be able to read them.
- A partial copy is exit 3 (`la importación se ha quedado a medias`).

Prints `Importado <folder> en <target>: N archivos y M carpetas (B bytes).` Exit codes: `0` imported; `1` could not; `2` usage error; `3` left half done.

### `backtide exportar`

Copies the agent's work out to a **new** folder on your computer. The service first takes a snapshot, then copies from the snapshot, so the copy is consistent.

```sh
backtide exportar DEST [--config FILE] [--git FOLDER] [--incluir-config]
```

| Argument / flag | Default | Effect |
|---|---|---|
| `DEST` | required | An absolute path that does **not exist yet**, in a folder that does. It cannot be inside a folder backtide protects. backtide never writes over anything |
| `--git FOLDER` | off | Export only the git commits of that repository (a folder of `/workspace/work`, or `.` for the whole work folder), as one git **bundle** file at `DEST`. The agent makes the bundle inside its container |
| `--incluir-config` | off | Also copy what your tools can run or read by themselves when you open the folder (see below). Cannot be combined with `--git` |

What the export leaves out by default, and why. **What the agent wrote is untrusted.** A tricked agent can plant a file that runs code on your computer when you open the folder with your editor, direnv or Claude Code. So the export skips:

- symbolic links, and anything that is not a plain file or folder;
- every `.git` folder (its config can run code on your computer);
- everything whose name starts with a dot (`.claude/`, `.mcp.json`, `.vscode/`, `.envrc`, `.github/`…), except a few harmless files such as `.gitignore`, `.editorconfig` and `.python-version`;
- `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, MCP config files and `*.code-workspace`.

`--incluir-config` copies the dot files and those config files after all, with a warning to review them one by one. A `--git` bundle is data only, but its commits may carry such files, so it prints a warning: clone it with `git clone --no-checkout` and read `git ls-tree -r --name-only HEAD` and `git log -p` before you open anything.

Limits: 8 GiB and 500,000 entries. Prints `Exportado a <dest>: N archivos y M carpetas (B bytes), de la instantánea <id>.`, lists what it skipped, and ends with `AVISO:` lines. Exit codes: `0` exported; `1` could not; `2` usage error (a destination the service refuses, or `--git` with `--incluir-config`); `3` unknown.

## Spending

backtide prices every model response from the provider's own usage report, counts the day and the month, and refuses new model calls once a cap is reached. The values and the 50 / 80 / 100 % notices are in [configuration](configuration.md#budget-spending-cap). Both commands ask the running service.

### `backtide gasto`

Shows what the agent has spent on model calls today and this month, against the caps.

```sh
backtide gasto [--config FILE]
```

```text
Gasto hoy: 0,25 $ de 5,00 $.
Gasto este mes: 0,25 $ de 50,00 $.
Precios de fábrica del 2026-10-06.
```

The last line says whether the price table is the one that ships with backtide ("de fábrica") or was updated from the provider's page (`Precios actualizados el <date> (fuente: Anthropic).`). If a cap is reached, a line says `Tope de hoy alcanzado: las llamadas al modelo se rechazan.` (or "de este mes") and the command adds how to change it. Amounts use a decimal comma. Exit codes: `0` shown; `1` no service, or it cannot count right now (then model calls are refused); `2` error.

### `backtide tope`

Shows or changes the daily and monthly caps.

```sh
backtide tope [--config FILE] [--dia DOLLARS] [--mes DOLLARS]
```

- Without options it prints `Tope diario: 5,00 $` and `Tope mensual: 50,00 $`.
- `--dia` and/or `--mes` set new caps in dollars. An amount is greater than 0, has at most two decimals, is at most 100000, and is at most 12 characters. A comma or a dot both work (`7`, `7.5`, `7,50`).
- The change goes through the service by the same path as the Settings page. It is written to the black box **before** anything changes, and it applies to the next model call. If it lifts the cap above what was spent, calls go through again at once.
- A cap set this way is stored in the state folder (`budget.json`) and **wins over `[budget]` in the config file** from then on.
- Exit codes: `0` shown or changed; `1` no service, or not saved; `2` the amount is not valid, or another error; `3` cannot tell whether it was saved.

```sh
backtide tope --dia 3 --mes 20 --config ~/backtide-demo-run/backtide.toml
```

## Check the machine

### `backtide comprobar`

Checks whether this Linux machine has what backtide needs, and says how to fix what is missing. It reads and changes nothing. The installer runs the same checks before it touches anything.

```sh
sudo backtide comprobar
```

- What it looks at: root, the architecture (x86_64 or aarch64), the kernel (6.7 or later), Btrfs, loop devices, cgroup v2, systemd, time sync, the kernel's BTF (the process sensor needs it), free space in `/var/lib`, that the ids 61000 and 61001 belong to nobody, `btrfs-progs`, `openssl`, Docker Engine (not Docker Desktop, Podman or rootless Docker) and SELinux or AppArmor.
- Each line is `[ok]`, `[aviso]` (a warning: something works less, or the installer will do it with your permission) or `[falla]` (a failure: backtide cannot run safely here). Under each warning or failure, how to fix it.
- Without `sudo` it still runs, with a warning: some checks (Docker, SELinux) may come out short.
- **Fedora 43 and 44 with kernel 7.1 or later:** the process sensor (Tetragon v1.7.1) cannot read their BTF yet, so the agent runs but its commands are not recorded. `comprobar` warns about it. Ubuntu 24.04 and 26.04 are fine. It goes away with Tetragon 1.8.
- What else it looks at (T13-3): whether backtide's two Docker networks overlap a route of the machine that is not Docker's (a VPN or your LAN). A clash is a warning that says how to move them (`--subredes`).
- `--despues-de-instalar` ("after installing"), as root, tests the installed backtide for real: its four systemd units are active; the volume is mounted `nosuid,nodev,noatime`; the agent started under the service and answers; it runs as uid 61000 with no capability (and as `container_t` under SELinux, or with its AppArmor profile); from inside it nothing connects without the proxy; the black box verifies; the process sensor sees a test command (a warning only, see the kernel note above); the web listens, left its link and its journal holds no link; and `systemd-analyze security` of both services is at or under the level measured in clean VMs. It is the installer's last step.
- Exit codes: `0` no failure (warnings do not count); `1` at least one failure; `2` (with `--despues-de-instalar`) not root or a bad config.

## Install

### `install.sh` and `backtide instalar`

`install.sh` is a short `sh` script at the root of the repository: read it before you run it. It checks that it runs as root on Ubuntu 24.04 or 26.04 or Fedora 43 or 44 (x86_64 or aarch64), checks the sha256 of the release archive and, before it writes anything, that the archive's `requirements.txt` pins every dependency to one version with its sha256. Then it downloads `uv` (pinned by version and sha256), installs the release in `/opt/backtide/releases/<version>-<hash>` and hands over to `backtide instalar`. **Nothing is built on your machine:** it creates a Python 3.12 of uv's own (uv checks it against the hash it carries) and installs only ready-made packages ("wheels"), each checked against its sha256 (`uv pip install --require-hashes --no-build`). If a dependency had no wheel for your machine, or a hash did not match, it stops without installing anything. backtide itself is not installed as a package: its code stays in the release folder, and `/opt/backtide/current/.venv/bin/backtide` runs it with `python -I` (isolated: no `PYTHON*` variables, no current folder).

```sh
sudo sh install.sh --desde backtide-<version>.tar --sha256 <the hash> [backtide instalar flags]
```

The archive is a **release archive** (see below); a plain `git archive` of the repository is refused, because it has no `requirements.txt`.

#### Getting a release and checking it

There is no published release yet: the first one comes with the preview. When there is one, it is a single uncompressed `backtide-<version>.tar` with its sha256 next to it, published with the release. To check it:

```sh
sha256sum backtide-<version>.tar            # Linux; on a Mac: shasum -a 256 backtide-<version>.tar
```

The hash it prints must be exactly the published one. If not, do not use the archive. The installer checks it again (`--sha256`) and refuses an archive that does not match. Inside the archive:

| File | What it is |
|---|---|
| `backtide/`, `deploy/`, `lima/backtide-mac.yaml` | backtide's code, its systemd templates, seccomp profile and Tetragon policy, and the Mac VM's template |
| `install.sh`, `install-mac.sh` | The two installers, the same as in the repository at that commit |
| `requirements.txt` | The runtime dependencies, exported from `uv.lock`: one `name==version` per package with every sha256 the lock knows for it, and nothing else: no comments, options, URLs or paths, which the installer refuses |
| `pyproject.toml`, `uv.lock` | Where `requirements.txt` comes from, to check it |
| `release.txt` | The commit it was built from and the uv that exported `requirements.txt` |
| `LICENSE`, `README.md`, `SECURITY.md` | |

**You can rebuild it and compare.** The archive is reproducible: the same commit, built with the same uv and the same Python (`release.txt` says which), gives the same bytes and so the same sha256. From a clone of the repository:

```sh
git checkout <the commit in release.txt>
make release                     # dist/release/backtide-<version>.tar and its .sha256
```

`make release COMMIT=<ref>` builds another commit. `make release ARBOL=1` builds from the working tree, uncommitted changes included, for testing only: its name ends in `-arbol` and `release.txt` says so. Building the archive builds nothing either: it copies the commit's files and runs `uv export --frozen`, which only reads `uv.lock`.

`backtide instalar` does the rest, each step checked and recorded in `/var/lib/backtide/install-manifest.json`: the preflight of `comprobar` (any failure stops it before it changes anything), the `backtide-web` account, the folders and their permissions, `btrfs-progs`/`openssl`/`gnupg` if missing, Docker Engine from Docker's own repository if there is none (its signing key is checked by fingerprint), SELinux in Docker on Fedora, the three images by digest, the agent's volume, the config and keys, the two Docker networks, the systemd units, and the self-test. **Run it again and it changes nothing**; cut it half way and the next run goes on from there.

```sh
sudo backtide instalar [--si] [--dry-run] [--proveedor anthropic|openai]
                       [--clave-archivo FILE | --clave-stdin | --sin-clave]
                       [--tope-diario N] [--tope-mensual N] [--zona-horaria ZONE]
                       [--subredes A,B] [--volumen-gib N]
```

| Flag | Default | Effect |
|---|---|---|
| `--si` | off | Answer yes to every question (installing packages or Docker, SELinux in Docker). Without it, and without a terminal, it stops at the first question |
| `--dry-run` | off | Show the checks and the steps; change nothing |
| `--proveedor` | `anthropic` | Whose key it stores (`keys/<provider>.key`) |
| `--clave-archivo FILE` | none | Read the model's key from `FILE` (one line). Delete the file afterwards |
| `--clave-stdin` | off | Read the key from standard input |
| `--sin-clave` | off | No key now: set it later in the web's Settings page |
| `--tope-diario`, `--tope-mensual` | `5`, `50` | The spending caps in dollars, written to the first `backtide.toml` |
| `--zona-horaria` | the machine's | The time zone of "a day" for the cap |
| `--subredes A,B` | chosen | The subnets of the agent's network (A) and the egress one (B). By default two free `/24` from `172.29.0.0/16`, from the top, that no route, address or Docker network uses |
| `--volumen-gib N` | `20` | The agent's volume size (sparse: it takes what is written) |

How it behaves:

- **Keys never go in an argument** (`ps` would show them). With a terminal and none of the three key flags, it asks for the key without echo; an empty answer leaves it for the Settings page.
- An existing `/etc/backtide/backtide.toml` is kept as it is. An existing `volume.img` is never overwritten or formatted again.
- On Fedora with SELinux enforcing and a Docker that does not use it, it asks before changing Docker: first `live-restore` (a reload, nothing restarts), then `selinux-enabled` and one restart of Docker (your other containers keep running). A Docker that already uses SELinux is not touched.
- At the end it prints how to open the web (`sudo backtide enlace`) and repeats the warnings.
- Exit codes: `0` installed and tested; `1` stopped (it says where and how to go on); `2` not root or a bad flag.
- To remove it: [`backtide desinstalar`](#backtide-desinstalar-remove-backtide). Upgrading in place (`backtide actualizar`) is not there yet: uninstall keeping the data, then install the new version.

### `install-mac.sh`: backtide on a Mac

backtide needs a Linux kernel (Btrfs for the snapshots, eBPF for the sensor), and Docker Desktop's VM gives neither. So on a Mac, backtide lives in a small Linux VM of its own, made with [Lima](https://lima-vm.io) and Apple's virtualization, and the Linux installer above runs inside it, unchanged. `install-mac.sh` is a short `sh` script at the root of the repository (`sh install.sh` on a Mac hands over to it): read it before you run it. Run it as yourself; it never uses `sudo` on the Mac.

```sh
shasum -a 256 backtide-<version>.tar     # must be the published hash (see "Getting a release")
sh install-mac.sh --desde backtide-<version>.tar --sha256 <the hash> [--clave-archivo FILE | --clave-stdin | --sin-clave] [--si]
```

What it does, and nothing else:

1. Checks the Mac: Apple Silicon (Intel Macs are not supported yet), macOS 13.5 or later, at least 8 GiB of memory, 25 GiB free, and that port 8765 is free.
2. Uses your Lima if it is 2.x. If there is none, it downloads Lima 2.2.1 from Lima's GitHub releases, checks it against the sha256 written in the script, and keeps it in `~/.backtide/lima/2.2.1`. No Homebrew, nothing outside your home.
3. Checks the archive's sha256 and creates the VM `backtide` from `lima/backtide-mac.yaml` in that archive: Fedora 44 (its image pinned by digest), 4 CPUs, 6 GiB of memory, a 40 GiB disk that only takes the space it uses. **No folder of your Mac is mounted** (it checks from inside the VM before installing anything), and no ssh agent or proxy settings of the Mac go in. It refuses to go on if a Lima `default.yaml`, `override.yaml` or `base.yaml` could change the VM, if a VM called `backtide` exists that is not its own, or if the VM's mounts or forwarded ports are no longer the template's (checked on every run).
4. Copies the archive into the VM, checks its sha256 again there, and runs `install.sh` inside as the VM's root, with `--si` (the VM is only for backtide).
5. Leaves a small `backtide` command in `~/.local/bin` (add it to your `PATH`). It runs `sudo backtide …` inside the VM, so every command on this page works from the Mac: `backtide enlace`, `backtide comprobar --despues-de-instalar`, `backtide rebobinar`… If the VM is stopped, it starts it first. `backtide vm estado|arrancar|parar|shell` show, start, stop or open the VM.

Only the web's port is forwarded, to the Mac's `127.0.0.1:8765`: `backtide enlace` prints the link (after checking that the port is held by Lima, not by another program), and it opens in your Mac's browser. No other port of the VM reaches the Mac (tested with Lima 2.2.1). **The other direction is open for the VM itself:** its root and its own programs can reach services listening on your Mac's `127.0.0.1` through Lima's address for the host, `192.168.5.2`. The agent's jail cannot: it has no route there, and a scenario of the battery checks it. **Run it again and it changes nothing**: the VM, Lima and the `backtide` command stay as they are, and the Linux installer inside finds everything done.

**Keys never go in an argument, on the Mac or in the VM.** `--clave-archivo FILE` is read on the Mac and sent to the installer in the VM through standard input (`--clave-stdin` there), so the key is in no command line, no Lima log and no shell history. `--clave-stdin` passes your standard input on the same way, but only from a pipe or a file: from a terminal it is refused, since what you type there would be seen. Without either, and with a terminal, it asks for the key without echo; an empty answer leaves it for later. The Mac's `backtide` does the same with `--clave-archivo`.

**What to know about a Mac:**

- **When the Mac sleeps, the VM sleeps.** The agent stops, and no alert reaches you, until the Mac wakes up. backtide on a Mac watches an agent while you use the Mac; for an agent that runs all night, use a Linux machine.
- **After a restart of the Mac the VM is stopped.** Any `backtide …` command starts it again, or `backtide vm arrancar`.
- **The agent's files live in the VM, not on your Mac.** `backtide exportar <folder>` copies them to a new folder inside the VM, and `backtide vm shell` gets you there. Bringing them to the Mac in one step is not there yet.
- **The VM's clock.** While the Mac sleeps, the VM's clock stops. When it wakes, Lima's guest agent sets it from the Mac's within seconds (measured: a VM two hours behind was right again in under 10 seconds), and until then backtide does not prune old snapshots, because pruning refuses to run on a clock that is not synchronized. `backtide comprobar` says whether it is.
- **Port 8765 must be free on the Mac.** The web checks that it is called as `127.0.0.1:8765`, so the VM's port and the Mac's must be the same. `make web-demo` uses the same port: close one before the other.
- **Telegram is not in the installer yet**: it will be set in the web's Settings page.

### `backtide desinstalar`: remove backtide

```sh
sudo backtide desinstalar [--borrar-datos] [--quitar-docker] [--si] [--dry-run]
```

It removes what `backtide instalar` made, and only that: the installer writes down everything it creates or changes in `/var/lib/backtide/install-manifest.json`, and the uninstaller undoes that list. First it stops the agent (`backtide.service`, then the agent's container if it still runs), then it removes, in order: the systemd units (which unmounts the volume and the proxy's tmpfs), backtide's three containers, its two Docker networks, the images it downloaded (about 5.5 GiB), the volume's mount point, `/etc/backtide`, the `/usr/local/bin/backtide` command, the `backtide-web` account and `/opt/backtide` (the program itself, last). If it changed Docker's `daemon.json` (SELinux on Fedora), those two settings go back to what they were, and anything you added to that file since stays: `selinux-enabled` first, with one restart of Docker while `live-restore` keeps your other containers running, then `live-restore` with a reload. Before it changes anything it prints the list and asks.

**By default it keeps your data**, in `/var/lib/backtide` (root only): the black box with its key and checkpoint, the agent's volume `volume.img` (its work and all its snapshots), the model keys in `keys/`, and a copy of your `backtide.toml`. It prints where they are and how much the volume takes. **To install again over them**, run the same install command as the first time: the black box goes on with the same chain (`backtide verificar` still says it is intact), the old snapshots are still there, and your `backtide.toml` comes back.

| Flag | Effect |
|---|---|
| `--borrar-datos` | Also delete the data, **for good**: the black box and its key, the volume with the agent's work and its snapshots, the keys. And `/etc/backtide` goes whole, your own `prices.toml` included. It asks you to type the machine's name first (or `--si`). Once it is done, what the agent did can no longer be checked or recovered. To keep a copy, stop at the question and copy `/var/lib/backtide` and `/etc/backtide` somewhere first |
| `--quitar-docker` | Also remove Docker (`docker-ce`, `docker-ce-cli`, `containerd.io`), its repository and its signing key, **only if backtide installed them** and no other container is left. Without it, Docker stays, with its repository, so it keeps getting updates: you may be using it for other things by now. Docker's own data (`/var/lib/docker`, `/var/lib/containerd`) is never deleted. Use it together with `--borrar-datos` if you want both: once the data (and the manifest with it) is gone, nothing remembers that backtide installed Docker, and a later `--quitar-docker` leaves it |
| `--si` | Do not ask (not even the machine's name). Without it, and without a terminal, it stops before changing anything |
| `--dry-run` | Print what it would remove; change nothing |

How it keeps to "only what is ours":

- It refuses a manifest that is not root's own `0600` file, or a state folder others can write: either would let someone else pick what gets removed.
- It never touches a path outside backtide's folders (`/opt/backtide`, `/etc/backtide`, `/var/lib/backtide`, `/var/lib/backtide-agent`) or the few exact files the installer writes elsewhere (its units, the command, Docker's repository and key, `daemon.json`), whatever the manifest says. Each path is opened one folder at a time without following links, and checked to be root's.
- A container or network is removed only if it carries backtide's `backtide.role` label: one that only has the same name is left, and it says so. An image is removed only if backtide downloaded it; if another container uses it, it stays.
- Without `--borrar-datos`, your own files in `/etc/backtide` (a `prices.toml` you wrote, say) stay, and so does the folder. With it, the whole folder goes. The packages the installer added (`btrfs-progs`, `gnupg`…) stay too: other programs may use them.
- Nothing is deleted while something is mounted under it: if something other than backtide's own volume and proxy tmpfs is mounted under a folder it would delete, it stops before changing anything.
- Only backtide's own four units and the `backtide-web` account are ever removed, by their exact names. The group goes after its user, and only if no other account has it as its primary group.
- Containers and networks are removed by the ID of the object whose label was checked.

**Run it again** and it says there is nothing left to remove. If it stopped half way (a mount that was busy, a network another container uses), fix that and run it again: it goes on from where it stopped. Note that once it finishes the program itself is gone: to delete the kept data later without reinstalling, `sudo rm -rf /var/lib/backtide`. Exit codes: `0` removed, or nothing to remove; `1` stopped (it says where); `2` not root or a bad flag.

**On a Mac**, `backtide desinstalar` (the Mac's own command) or `sh install-mac.sh --desinstalar` does it for the VM:

- **By default it keeps the VM, stopped, with your data in it.** It runs the Linux uninstall above inside the VM (keeping the data), stops the VM and removes `~/.local/bin/backtide`. Nothing of backtide runs any more; the VM's files and the Lima it needs stay on your Mac, and it prints how much disk the VM takes. To install again over the data, run the same `sh install-mac.sh --desde …`: it uses that VM. To look at the data, `limactl start backtide` and `limactl shell backtide` (it prints the full path of `limactl`). Why not copy the data to a Mac folder instead: the agent's volume is a 20 GiB sparse Btrfs image whose snapshots only make sense inside Linux, and installing again would then need an import step. Keeping the VM is the simplest way that loses nothing.
- **`--borrar-datos` deletes the VM**, and with it the black box, the agent's work and its snapshots, for good, after you type the VM's name (or `--si`). If it downloaded Lima into `~/.backtide/lima` and no other VM is left in your Lima folder, that Lima goes too, with its download of the VM's image in `~/Library/Caches/lima` and the Lima folder the install made. **It never touches your own Lima, other VMs, `~/.lima` if it was there before, or Homebrew.**

### `backtide enlace`

```sh
sudo backtide enlace
```

Prints the one-time link of the installed web (`backtide-web.service`), its run name, and the `ssh -L 8765:127.0.0.1:8765 <user>@<server>` line to reach it from another computer without opening a port. The link lives in a file only the web's user and root can read (`/run/backtide-web/enlace`), never in the journal. For a new one, `sudo systemctl restart backtide-web`. Exit codes: `0` printed; `1` no running web, or a file that is not the web's link.

### `backtide imagenes`

Prints the three images this version runs (the agent, the proxy, the sensor), each pinned by digest: the only list of them, the one the installer pulls and checks.

## `make` commands

The `Makefile` is the normal way to use backtide today. Run `make help` for the live list. Most targets that touch Docker, Btrfs or eBPF run **inside the development VM** (`vigia-dev`, made by `make vm-up`). The commands below are the useful ones; the `make help` text of some is in Spanish.

| Command | What it does |
|---|---|
| `make vm-up` | Create (first time) and start the dev VM |
| `make vm-shell` | Open a shell inside the VM |
| `make vm-estado` | VM status: containers with CPU and memory, Docker leftovers, Btrfs mounts, the 5 busiest processes |
| `make vm-limpiar` | Delete only backtide's own leftovers (`backtide-*`, `vigia-demo-*`, unused volumes). It does not touch images. `FORZAR=1` if a test run is active |
| `make vm-down` / `make vm-delete` | Stop the VM / delete it (your code stays on the Mac) |
| `make test` | Unit tests, on the Mac |
| `make lint` | `ruff format --check` and `ruff check` |
| `make fmt` | Auto-fix lint and format |
| `make it` | Integration tests inside the VM. `IT=tests/integration/test_x.py` runs one file |
| `make ataques` | The evil-agent battery inside the VM. `PERFIL=claude-code` runs it with Claude Code; `ATK="-k name"` or `ATK_PATH=tests/attacks/test_x.py` selects some. See the [attack battery](attack-battery.md) |
| `make demo` | **Terminal 1.** Demo: a throwaway Btrfs volume plus `backtide vigilar` in the foreground. No money is spent |
| `make demo-crear` | Demo: the agent creates some files |
| `make demo-archivos` | Demo: show the agent's files |
| `make demo-borrar` | Demo: the agent deletes some of them |
| `make demo-instantaneas` | Demo: list the snapshots |
| `make demo-rebobinar` | Demo: rewind. `ID=<snapshot>` (default: the one `demo-crear` left), `SI=1` skips the question |
| `make demo-web` | Demo: the web of the running demo, with rewind and approval on, port 8766 (open the link on the Mac) |
| `make demo-parar` | Stop everything, unmount and delete the demo volume |
| `make web-demo` | Web view on the Mac, no VM, with invented data. Cannot really rewind |
| `make probar` | **Terminal 1.** Real run: the real agent thinking with a real model through the proxy. **It costs money.** Options below |
| `make probar-web` | Real run: the web with Settings, approve and rewind on (`--ajustes --aprobar --rebobinar`), port 8766 |
| `make probar-pedir MSG="…"` | Real run: send one message to the agent and print its answer |
| `make probar-instantaneas` | Real run: list the snapshots |
| `make probar-rebobinar ID=<id>` | Real run: rewind. `SI=1` skips the question |
| `make probar-entrar` | Claude Code profile: open it in your terminal. `CONTINUAR=1` continues the last conversation |
| `make probar-tarea MSG="…"` | Claude Code profile: one task and its answer. `CONTINUAR=1` continues |
| `make probar-importar RUTA=…` | Claude Code profile: copy a VM folder in. `REEMPLAZAR=1` writes over, `SECRETOS=1` includes secrets |
| `make probar-exportar RUTA=…` | Claude Code profile: copy the work out to a new VM folder. `GIT=<folder>` exports only the commits as a bundle, `CONFIG=1` includes `.claude/`, `.mcp.json`, `.vscode/`… |
| `make probar-parar` | Real run: stop everything, unmount, delete the volume and the key you set in Settings |

Options of `make probar`:

| Variable | Default | Effect |
|---|---|---|
| `MODEL=` | `claude-sonnet-5-5` | The model OpenClaw uses. Only characters `0-9 A-Z a-z . _ : / @ + -` |
| `PERFIL=` | `openclaw` | `openclaw` or `claude-code` |
| `LOCAL=` | unset | Use a model of your own Ollama (for example `LOCAL=qwen3-coder:30b`) instead of Claude: no key, no cost. Cloud-run Ollama models are refused, and so is `FALSO=1` |
| `FALSO=1` | unset | Fake internet: nothing leaves the VM. For checking only |

The `probar-*` targets and `make demo` share one folder and one web port in the VM, so a demo and a real run cannot be active at the same time. The demo script is in docs/demo.md (internal note) and the real run in docs/probar.md (internal note), both in Spanish; an English walk-through is in [real run](real-run.md).

The demo and real-run scripts use `sudo` inside the VM for a few fixed commands (mount, chown, unmount, quota). They live in `scripts/demo/` and are not part of the product.

## Environment variables

backtide reads **no environment variable for its settings**. Everything is in the config file ([configuration](configuration.md)). Two variables are looked at for narrow reasons:

| Variable | Used by | Why |
|---|---|---|
| `TZ` | the service | To find the machine's time zone, so that "a day" for the spending cap starts at your midnight (unless `[budget] timezone` is set) |
| `TERM` | `backtide entrar` | Passed to the agent's terminal, if it looks like a normal terminal name |

The `docker` commands that backtide runs inherit your environment, so the usual Docker variables apply to them.
