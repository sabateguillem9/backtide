# Troubleshooting and FAQ

backtide is **pre-alpha**. This page lists the problems the project's own scripts can hit, and what is and is not supported. It only says what the repository backs up. If your problem is not here, open an issue (not for a security problem: use [SECURITY.md](../../SECURITY.md)).

Output from the commands is in Spanish for now. Messages are quoted as they appear, with a translation.

First steps for most problems:

```bash
make vm-estado    # what the VM is doing (read-only, changes nothing)
make help         # every command
```

## Questions

### What does backtide support?

- **Host:** a Mac with Apple Silicon, with Lima and uv. This is the only setup the quickstart and the demo were written for. See [getting-started.md](getting-started.md).
- **Installing it as a service:** with `install.sh` on Linux, and on a Mac with Apple Silicon with `install-mac.sh`, which makes a Linux VM of its own (Fedora 44) and runs `install.sh` inside it. See [cli-reference.md](cli-reference.md#install-macsh-backtide-on-a-mac) for what changes on a Mac (sleep, files, the clock).
  - **Tested:** Fedora 44 and Ubuntu 24.04, on arm64 (`aarch64`) only so far.
  - **Accepted, untested:** Fedora 43, Ubuntu 26.04 and x86_64 (Intel and AMD). The installer installs on them and warns that nobody has tried them yet; if something fails there, tell us. Other distributions are refused.
- **Agents:** OpenClaw, and Claude Code (`PERFIL=claude-code` in the development setup, `--perfil claude-code` in the installer). Other agents are designed or planned, not built. The README's status table is the reference.
- **Models:** Claude through the proxy, or a local model through Ollama. See [real-run.md](real-run.md).

### What is not supported?

- **Windows**, including WSL2: not supported.
- **Intel Macs:** not tested, and `install-mac.sh` refuses them for now.
- **Linux without the VM:** the demo and test scripts refuse to run anywhere but the Lima VM `vigia-dev`. The code is designed for Linux with Docker and Btrfs, and `install.sh` installs it there as a service (see above). `make test` and `make lint` do run on Linux (the project's CI runs them on Ubuntu).
- **Messaging channels whose sessions break when rewound, such as WhatsApp and Signal:** not supported in this version. Rewinding restores the agent's working folder, but not the state of those sessions.
- **State outside the rewound folder:** configuration, channel tokens and the list of who may talk to the agent are not rolled back.
- **Taking back what already left:** an email, a payment or a deleted cloud resource that was approved, or that left through a hole the gate does not cover. A rewind does not unsend, unpay or undelete.
- **A container escape or a compromised host.** The agent shares the host kernel; the cage reduces what it can do but is not a virtual machine.

The full list is in the [README](../../README.md) and in [security-model.md](security-model.md).

### Does the demo cost money?

No. `make demo` runs fixed commands and calls no model. `make probar` (the real run) does cost money. See [real-run.md](real-run.md).

### Why is the output in Spanish?

The command line (`backtide`, the demo scripts) is in Spanish for now. The web view has an English and a Spanish version, chosen from your browser's language; the EN and ES links in the page switch it.

### Why is the VM called `vigia-dev`?

That was the project's name before it became backtide. Renaming the VM would mean rebuilding it, so the name stayed. The Python environment inside it (`~/.venvs/vigia`) keeps the old name for the same reason.

## The VM does not start

**`limactl: command not found`.** Install [Lima](https://lima-vm.io/) first. The VM definition asks for Lima 2.0.0 or newer (`minimumLimaVersion` in `lima/vigia-dev.yaml`). Check with `limactl --version`.

**`make vm-up` takes a long time the first time.** That is normal. It creates the VM, downloads Fedora, and installs Docker, the Btrfs tools and uv inside it. Wait for it to finish.

**`make vm-up` fails or hangs.** After booting, the VM waits up to five minutes for Docker and uv to be installed, and up to a minute for Docker to be usable by your user. If it gives up, the hint in `lima/vigia-dev.yaml` says to read `/var/log/cloud-init-output.log` inside the VM. The setup downloads Fedora packages, Docker and uv, so check your network too. To read the log: `limactl shell vigia-dev -- sudo tail -50 /var/log/cloud-init-output.log`.

**The VM exists but is stopped.** `make vm-up` starts it. `make vm-up` on a running VM only prints that it is already running.

**You want to start over.** `make vm-delete` deletes the VM (your code stays on the Mac), and `make vm-up` creates a new one. Everything inside the VM is lost, including downloaded Docker images, which will download again.

**It uses too much memory or disk.** The VM is set to 6 CPU cores, 8 GiB of memory and a 50 GiB disk in `lima/vigia-dev.yaml`. You can lower them in that file before the first `make vm-up`. Editing the file does not change a VM that already exists.

**`make vm-down`** stops the VM when you are done.

## Docker

Docker runs inside the VM, not on your Mac. The Docker Desktop on your Mac is not used and cannot replace it, because backtide needs Btrfs and kernel features that it does not give.

- **The first demo or real run takes minutes before anything appears.** It is downloading the agent's image (about 1.3 GB for OpenClaw, about 750 MB for Claude Code). The wait for the download is up to 30 minutes.
- **Leftovers from an earlier run** (containers, networks, volumes). See [`make vm-estado` and `make vm-limpiar`](#vm-estado-and-vm-limpiar) below.
- **Docker needs SELinux on in the VM.** The VM is provisioned that way (so the agent is confined and not unconfined). You do not have to do anything on the VM `make vm-up` creates.

## Btrfs and "sudo"

**Btrfs** is the Linux file system that makes snapshots instant. The demo creates a throwaway one inside the VM: a sparse 2 GiB file, mounted through a loop device, under `~/backtide-demo-run`.

- **"la demo solo corre dentro de la VM lima-vigia-dev: usa `make demo`"** (the demo only runs inside the VM). You ran `scripts/demo` directly, outside the VM. Use the `make` targets: they run the script inside the VM.
- **"ejecútala como el usuario normal de la VM, no como root"** (run it as the VM's normal user, not as root). Do not run the demo with `sudo` or as root.
- **"hace falta sudo sin contraseña en la VM para montar el volumen"** (passwordless sudo is needed to mount the volume). The VM user must be able to use `sudo` without a password. This is the default in the VM that `make vm-up` creates. The demo uses `sudo` only for a few fixed commands: `mount`, `chown`, `umount` and the quota limit, each checked against the demo's own volume. These scripts live in `scripts/demo/` and are never part of the product code.
- **"falta mkfs.btrfs: btrfs-progs debe estar instalado en la VM"** (btrfs-progs is missing). It is installed by the VM's setup. If you built the VM some other way, install the `btrfs-progs` package inside it.
- **A Mac cannot do snapshots.** The Mac has no Btrfs. That is why `make web-demo` shows an invented list of snapshots, and why everything that needs the kernel runs in the VM.

## The demo and the real run

**"ya hay una demo en marcha en otra terminal; `make demo-parar` la quita"** (a demo is already running). Run `make demo-parar`. For the real run, the message is "ya hay una prueba o una demo en marcha" and the command is `make probar-parar`.

**`make demo` and `make probar` cannot run together.** They share the same folder (`~/backtide-demo-run`), the same names and the same web port. Stop one before starting the other.

**"Quedaba una demo anterior" (an earlier demo was left).** Normal after a rehearsal: `make demo` removes it and starts again from zero.

**`make demo-parar` says `~/backtide-demo-run` is not the demo's.** It only deletes a folder that carries the `.backtide-demo` mark written by `make demo`. If the folder is some leftover of yours, delete it by hand.

**The service was killed with `kill -9`.** That leaves the volume mounted. `make demo-parar` unmounts it too.

**"el agente no está en marcha: arranca `make demo` en otra terminal"** (the agent is not running: start `make demo` in another terminal). Run the commands of the demo (`demo-crear`, `demo-borrar`...) only while `make demo` is running in terminal 1.

**"en 90 s no apareció la instantánea: ¿sigue `make demo`?"** (the snapshot did not appear in 90 seconds). The service is not running, or the VM is very loaded. Check terminal 1 and `make vm-estado`.

**`make demo-rebobinar` complains about the ID.** `ID` accepts only letters, digits, dots, underscores and dashes. Copy it from `make demo-instantaneas` or from the `Para deshacer:` line. With no `ID`, it uses the snapshot that `demo-crear` left.

**The rewind says it cannot rewind without a terminal.** The question `¿Rebobinar? [s/N]` needs a terminal. Add `SI=1` (`make demo-rebobinar SI=1`) to answer yes in advance.

## Ports and the web view

The web view listens only on `127.0.0.1`, so only your computer can open it.

| Command | Port | Where it runs |
|---|---|---|
| `make web-demo` | 8765 | On the Mac, invented data |
| `make demo-web` and `make probar-web` | 8766 | In the VM; Lima forwards the port to the Mac |

**The Mac's port 8766 is already used.** `make demo-web` and `make probar-web` check first and refuse (message "El puerto 8766 del Mac ya está ocupado": the port is taken, Lima could not forward it, and the link would reach another program). Find out what holds it with `lsof -nP -iTCP:8766 -sTCP:LISTEN` and stop it. The two commands share the port with each other, so close one before opening the other.

**"No hay demo en marcha: lanza antes make demo (terminal 1)".** `make demo-web` needs the demo to be running. For `make probar-web` the message says "No hay prueba en marcha: lanza antes make probar (terminal 1)".

**The link works once.** When you open the link (`http://127.0.0.1:<port>/s/<random>/?t=<key>`), the page stores a cookie in that browser and the link stops working. A copy of the link in your terminal history is useless. To open the page in another browser, press `Ctrl-C` and start the web again: you get a new link.

**The page stops letting you in** (for example, another site on your `127.0.0.1` filled your browser with cookies). Same fix: `Ctrl-C` and start the web again.

**The page says it cannot read.** The black box is read straight from the service's files. If the service is stopped, the web says it cannot read, and that is correct. Start the service (`make demo` or `make probar`).

**The rewind, approve and Settings buttons are disabled.** In `make web-demo` this is normal: there is no service. In `make demo-web` and `make probar-web` the web is started with the right options. The real `backtide web` only looks unless you start it with `--rebobinar`, `--aprobar` or `--ajustes`, and those need the same user as the service.

**The three-word name does not match.** The "Nombre de esta ejecución" in the terminal and the one in the page header must be the same. If they differ, you are not looking at the run you just started: use the newest link.

## `vm-estado` and `vm-limpiar`

**`make vm-estado`** only reads. It prints, in Spanish:

1. How long the VM has been up.
2. The running containers with their CPU and memory.
3. Docker leftovers: containers (running and stopped), networks, and volumes (how many are unused).
4. Btrfs mounts left behind by tests or the demo (loop mounts).
5. The five processes using the most CPU.

If containers are running while you are not testing, it warns you that they are probably spare.

**`make vm-limpiar`** deletes only backtide's own leftovers, and prints what it removed:

- containers named `backtide-*` or `vigia-demo-*` (the demo's name before the rename), running or not;
- networks with those names;
- unused Docker volumes (volumes no container uses).

It never touches images, or anything with another name. It refuses to run while `pytest` is running in the VM, because it would break a `make it` or `make ataques` that is in the middle of a test: "Hay pruebas en marcha (pytest) en la VM". Wait for the tests to end, or force it with `make vm-limpiar FORZAR=1`.

It does not unmount the demo's Btrfs volume or delete `~/backtide-demo-run`. For that, use `make demo-parar` (or `make probar-parar`).

## The real run (money, keys and Telegram)

Most of these are explained in [real-run.md](real-run.md). The short list:

- **The agent says "provider rejected the request schema or tool payload", terminal 1 shows `modelo blocked`.** You have not put the key in Settings yet. Until then the proxy answers for the provider and never calls it, so it costs nothing. Or the key belongs to no workspace in the provider's console.
- **Calls are rejected with "tope de gasto de backtide alcanzado" (backtide's spend cap reached).** You reached the daily or monthly cap. Raise it in Settings; it applies from the next call.
- **Telegram: "chat not found".** Send `/start` to your bot from your own chat first. Telegram does not let a bot write to you before that. Also check that the `chat_id` in the bot's file is your private chat with the bot.
- **The key is wrong or was disabled.** Paste it again in Settings. OpenClaw stops using a key for a while (30 seconds to a few minutes) after the provider says it is invalid.
- **Local model: `provider_local_unanswered`.** Ollama is not open on the Mac, or listens on another port.
- **Nothing in the black box for the agent's commands.** In the real run, the process sensor does not run, so commands are not recorded. Files, snapshots, network calls and the gate's decisions are.

The key must never go in a file you create, in a chat, or in a command. It goes in the Settings page only.

## The installed version

- **"backtide ya está instalado aquí con OpenClaw … desinstala antes"** (or with Claude Code). You ran the installer with another `--perfil` than the one the machine has. Nothing was changed. To switch agents: `sudo backtide desinstalar` (it keeps the black box, the agent's work and the keys), then the install command with the new `--perfil`. The new agent starts on the same data; the old agent's `backtide.toml` is kept aside as `/var/lib/backtide/backtide.toml.guardado.<agent>`.
- **"--telegram necesita el token del bot y aquí no hay terminal para pedirlo".** Without a terminal (a script, `--si` in a pipe), give the token with `--telegram-token-archivo FILE` or `--telegram-token-stdin` and the chat with `--telegram-chat N`. Or leave Telegram out and set it later in the web: `sudo backtide enlace` gives the link, then "Ajustes" ("Settings") > "Avisos" ("Alerts").
- **"eso no parece un token de bot de Telegram"** or **"el chat de Telegram tiene que ser…".** The token is `<digits>:<letters>`, as BotFather gives it; the chat is your private chat's number (positive). Nothing of Telegram was saved.
- **"Falta la clave del modelo".** Open the web (`sudo backtide enlace`) and put it in "Ajustes" > "Modelos", or run the installer again with `--clave-archivo FILE`.
- **"… se admite pero aún no se ha probado".** Your distribution or architecture is accepted but nobody has tried backtide on it yet (only Fedora 44 and Ubuntu 24.04 on arm64 have been). It should work; if something fails, tell us.

## Still stuck?

- Check `make vm-estado`, then `make vm-limpiar` if there are leftovers, then try again.
- The step-by-step guides: [getting-started.md](getting-started.md) and [real-run.md](real-run.md).
- Open an issue and say what you ran and what you saw. Do not paste keys, tokens or the contents of the black box. For a security problem, follow [SECURITY.md](../../SECURITY.md) instead.
- Contributing: [CONTRIBUTING.md](../../CONTRIBUTING.md).
