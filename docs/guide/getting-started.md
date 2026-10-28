# Getting started

This guide takes you from a fresh clone to the 60-second demo: an AI agent deletes its files, and you rewind them.

backtide is **pre-alpha**. It is a working prototype, not a product. Read the status and the security model in the [README](../../README.md) before you trust it with anything. This guide only covers how to run it.

> **This is a preview.** Read this before you install it:
>
> - It has had **no human security audit**. The reviews so far were done by AI agents.
> - **Do not use production keys.** Make a model key with a spending limit just for this.
> - **A rewind does not bring back what already left the machine.** An email, a payment or a push that went out stays out; holding those back is the gate's job.
> - **Calls to the model are never held**: what the agent tells its model provider goes out.
> - **On Fedora with kernel 7.1 or later, the process sensor does not start** (Tetragon v1.7.1 cannot read those kernels' BTF). Everything else works.
> - **On a Mac:** when the Mac sleeps, the agent and its alerts sleep, and the agent's files live in the VM, not on your Mac ([details](cli-reference.md#install-macsh-backtide-on-a-mac)).
> - **Tested:** Fedora 44 and Ubuntu 24.04 on arm64 (`aarch64`), and Macs with Apple Silicon. The installer also accepts Fedora 43, Ubuntu 26.04 and x86_64, and warns that they are untested.
> - **To remove it:** `sudo backtide desinstalar` on Linux, `backtide desinstalar` on a Mac. By default it keeps your data (the black box, the agent's work and its snapshots, the keys); `--borrar-datos` removes everything, for good ([details](cli-reference.md#backtide-desinstalar-remove-backtide)).

**Trying the installed version on your own machine?** Skip this page and read the [guide for preview testers](testers.md). This page is for the development setup and the demo.

The demo costs nothing. The agent runs fixed commands and never calls a model. The test with a real model (it costs money) is in [real-run.md](real-run.md).

## What you need

backtide watches an agent from outside, using features of the Linux kernel. So the parts that matter run on Linux. The supported way to get a Linux for development is a small virtual machine on a Mac.

A **virtual machine (VM)** is a whole second computer simulated inside your computer. Here it is a Fedora Linux that you start and stop with one command. [Lima](https://lima-vm.io/) is the tool that creates and runs it.

What the repository supports today:

| Setup | State |
|---|---|
| Mac with Apple Silicon (M1 or newer), with [uv](https://docs.astral.sh/uv/) and Lima 2.0.0 or newer | **The supported setup.** Everything in this guide was written for it. |
| Linux, running the commands directly (Docker + Btrfs) | The code is designed for it, and `install.sh` installs it as a service ([cli-reference.md](cli-reference.md#installsh-and-backtide-instalar)). The demo and test scripts refuse to run outside the VM named `vigia-dev`, so `make demo` does not work on a bare Linux host. `make test` and `make lint` do run on Linux (the project's CI runs them on Ubuntu). |
| Lima on a Linux host | Not tested. |
| Intel Mac | Not tested. |
| Windows | Not supported. |

Also needed:

- About 8 GiB of memory, 6 CPU cores and up to 50 GiB of disk for the VM. Those are the values in `lima/vigia-dev.yaml`; edit that file before the first `make vm-up` if you want less.
- About 1.3 GiB of download the first time you run the demo (the OpenClaw image).
- An internet connection for the first `make vm-up` (the VM downloads Fedora, Docker and uv).

Two words you will meet:

- **Docker** runs programs in isolated boxes called containers. backtide puts the agent in one, so the agent sees only its own files.
- **Btrfs** is a Linux file system that can take a snapshot of a folder almost instantly and without copying the data. backtide uses it to take photos of the agent's working folder, so you can go back to any of them.

Docker and Btrfs live inside the VM. You do not install them on your Mac. Do not use Docker Desktop for this: it cannot do what backtide needs from the kernel.

## 1. Get the code

```bash
git clone <repo url>
cd <repo folder>
uv sync --locked
```

`uv sync --locked` installs the Python packages at the exact versions in `uv.lock`, and fails if the lock file is out of date. The project needs Python 3.12 or newer, which uv fetches if you do not have it.

You should see uv create a `.venv` folder and list the installed packages.

## 2. Create the VM

```bash
make vm-up
```

The first time, this creates the VM from `lima/vigia-dev.yaml` and installs Docker, Btrfs tools and uv inside it. It takes several minutes. The VM sees only this project folder, not the rest of your home directory.

The VM is called `vigia-dev`. That is the project's name before it was renamed to backtide. It is kept because renaming it would mean rebuilding the VM.

Next times, `make vm-up` starts the VM if it is stopped, or tells you it is already running. To get a shell inside it, `make vm-shell`. To stop it, `make vm-down`. To delete it (your code stays on the Mac), `make vm-delete`.

## 3. Run the tests

```bash
make test    # unit tests, on the Mac
make lint    # formatting and style checks, on the Mac
```

You should see pytest finish with only passes, and `ruff` print `All checks passed!`. These two do not need the VM.

Two more suites run inside the VM and take much longer. You do not need them for the demo:

- `make it`: integration tests (real Docker, real Btrfs).
- `make ataques`: the attack battery, scripted scenarios of a hostile agent. They are destructive on purpose and run only inside the VM and its test containers. See [attack-battery.md](attack-battery.md).

`make help` lists every command.

## 4. The 60-second demo: delete, rewind, undo

You need two terminals, both in the repository folder. Output from backtide is in Spanish for now, and this guide quotes it as it appears.

1. Make sure the VM is up (`make vm-up`) and start clean:

   ```bash
   make demo-parar
   ```

   It is fine if there was nothing to stop.

2. **Terminal 1** starts the service:

   ```bash
   make demo
   ```

   This stays in the foreground. It creates a throwaway Btrfs volume in `~/backtide-demo-run` inside the VM (a 2 GiB file), caps the agent's folder at 192 MiB, and runs `backtide vigilar`, the backtide service. It also starts the real OpenClaw agent in its container.

   The first time, it downloads the OpenClaw image (about 1.3 GB), so do it before you plan to show the demo. Later starts take about 15 seconds.

   You should see a live list of what backtide records. Wait until you see `sistema agent_start` and the first `instantánea take` lines. A **snapshot** (`instantánea`) is one of those photos of the agent's folder.

3. **Terminal 2** runs the rest, one step at a time:

   | Command | What happens |
   |---|---|
   | `make demo-crear` | The agent creates four files in its working folder. The command waits (about 5 seconds) for backtide to take a snapshot that contains them. |
   | `make demo-instantaneas` | Lists the snapshots, newest first. Terminal 1 shows each file and each snapshot being recorded. |
   | `make demo-borrar` | The agent "makes a mistake" and deletes three of the four files. It waits for the snapshot that shows the deletion. |
   | `make demo-archivos` | Shows the agent's files. Only `notas.md` is left. Without backtide, there is no way back. |
   | `make demo-rebobinar` | Rewinds to the good snapshot, the one `demo-crear` left. backtide shows what the rewind undoes and what it cannot undo, then asks `¿Rebobinar? [s/N]`. Type `s` and press Enter. |
   | `make demo-archivos` | The three files are back, as they were. |
   | `make demo-rebobinar ID=<id>` | Every rewind leaves a point to undo it. Copy the id from the line `Para deshacer: make demo-rebobinar ID=...` and run it (type `s`). |
   | `make demo-archivos` | The folder is as it was right after the deletion again. Nothing is lost either way. |

   The rewind takes about 5 seconds. The service stops the agent, swaps the folder and starts the agent again. In terminal 1 you see `rewind_requested`, `agent_stop`, `agent_start` and `rewind_done`.

   To skip the question while rehearsing, add `SI=1`: `make demo-rebobinar SI=1`. For a recording, keep the question: it is the part that says what can and cannot be undone.

4. When you are done: press `Ctrl-C` in terminal 1. This stops the service and, with it, the agent. The volume stays, so you can still run `make demo-instantaneas`.

   Then clean up:

   ```bash
   make demo-parar
   ```

   This stops the service if it still runs, removes the agent's container and network, unmounts the volume and deletes `~/backtide-demo-run` in the VM. It only deletes a folder that carries the `.backtide-demo` mark written by `make demo`.

### Optional: Telegram alerts

If the VM has a file `~/.config/backtide/telegram.toml` (mode 600) with your own bot's token and chat id, `make demo` copies it to its state folder and alerts reach your phone. Without it the demo works the same, with no Telegram. How to create the bot is in 28-telegram.md (internal note) (in Spanish). The held-request buttons do not appear in this demo, because the agent sends nothing out; you can see them in the [real run](real-run.md).

## 5. The web view

The web view is a page in your browser that shows, live, what backtide has recorded. It has "Now" (what the agent is doing now), "History" (everything, with filters) and "Snapshots" (with a rewind button). It listens only on `127.0.0.1`, so only your computer can open it.

The page has an English and a Spanish version. It picks one from your browser's language (Spanish if it cannot tell). To force English, add `?lang=en` to the address, or use the language switch in the page. The Spanish names are "Ahora", "Historia" and "Instantáneas".

There are two ways to see it.

**With the real demo data.** In a **third terminal**, while `make demo` is still running:

```bash
make demo-web
```

It prints a link like `http://127.0.0.1:8766/s/<random>/?t=<key>` and a three-word "Nombre de esta ejecución". Open the link in your Mac's browser. Lima forwards the VM's port 8766 to the same port on the Mac, so the address works as printed. Check that the three-word name in the page header matches the one in the terminal.

Now run `make demo-crear`, `make demo-borrar` and `make demo-rebobinar` in terminal 2 and watch the files, the snapshots and the rewind appear. You can also rewind from the web: in "Snapshots", click the arrow on the good snapshot, read the notice, and confirm. `make demo-web` starts the web with rewind and approval switched on (`--rebobinar`, `--aprobar`). `Ctrl-C` stops the web and leaves the agent alone.

If no demo is running, `make demo-web` says so and does not start. If port 8766 is already used on the Mac, it also refuses, because the link would reach another program.

**With invented data, no VM.** On the Mac only:

```bash
make web-demo
```

This creates a temporary folder with a made-up black box (an hour of an agent writing notes, deleting a whole project, and a rewind) and keeps adding events live. It prints the same kind of link, on port 8765. `Ctrl-C` stops it and deletes the folder.

This is a mock-up of the page, not backtide at work. There is no service, so the rewind buttons are switched off. The Settings page and the approve/reject buttons work, but only change what the demo remembers: nothing is stored and nothing goes out.

Things to know about the link:

- **It works once.** When you open it, the page saves a cookie in that browser and the link stops working. To open the page in another browser, stop the web with `Ctrl-C` and start it again for a new link.
- If the page stops letting you in (for example, another site on your `127.0.0.1` filled the browser with cookies), do the same: `Ctrl-C` and start it again.
- The pages live under a random path that changes at every run, so another program on `127.0.0.1` cannot guess them.
- The page shows events as written. It does not say whether the black box is intact; `backtide verificar` does that.

## Clean up

| What | Command |
|---|---|
| Stop the demo and delete its volume | `make demo-parar` |
| See what the VM is doing (containers, leftovers, mounts) | `make vm-estado` |
| Delete leftover containers, networks and unused volumes of backtide | `make vm-limpiar` |
| Stop the VM | `make vm-down` |
| Delete the VM | `make vm-delete` |

`make vm-limpiar` only removes things named `backtide-*` or `vigia-demo-*` (the older demo name) and Docker volumes no container uses. It does not touch images. It refuses to run while tests are running in the VM; `make vm-limpiar FORZAR=1` forces it.

## Where to go next

- If something fails: [troubleshooting.md](troubleshooting.md).
- How the pieces fit together: [how-it-works.md](how-it-works.md), and what the security model promises: [security-model.md](security-model.md).
- The same demo with every talking point, in Spanish: demo.md (internal note).
- A test with a real agent and a real model: [real-run.md](real-run.md).
- All commands: [cli-reference.md](cli-reference.md). Settings: [configuration.md](configuration.md).
- Contributing: [CONTRIBUTING.md](../../CONTRIBUTING.md).
