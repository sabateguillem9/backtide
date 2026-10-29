# Guide for preview testers

Thank you for trying backtide. This page takes you from nothing to a first look in about 30 minutes, tells you how to use it for a few days, and tells you what to send us when something goes wrong.

You should already run an agent such as OpenClaw or Claude Code. You do not need to know Docker, Btrfs or eBPF. The words you meet are explained the first time they appear.

## What backtide is

- backtide is a black box for AI agents. It records everything your agent does, from outside the agent, so the agent cannot edit the record.
- It lets you **rewind** the agent's working folder to an earlier moment.
- It **holds back** what cannot be undone (an email, a push, a request that writes to the outside) until you approve it. If you do not answer in 5 minutes, it is rejected.

It is a **preview**. It has had no human security audit. Read [The limits](#the-limits) before you install it.

## What you need

- **A machine to put it on:** Linux, or a Mac with Apple Silicon.
  - Linux: **Fedora 44 or Ubuntu 24.04** are the ones we have tested. The installer also accepts Fedora 43 and Ubuntu 26.04, and says they are untested; it refuses other distributions. Our tests so far ran on ARM (`aarch64`); Intel and AMD (`x86_64`) are accepted by the installer, with the same warning, but not tried yet.
  - Mac: Apple Silicon, macOS 13.5 or later. Intel Macs do not work yet.
- **Disk:** on Linux, about 18 GiB free in `/var/lib` (the agent's folder lives in a volume of up to 20 GiB that only takes what is written, and the images are about 5.5 GiB). On a Mac, 25 GiB free.
- **Memory:** the agent alone may use up to 3 GiB. Plan on 6 GiB free for the whole of backtide. A Mac needs 8 GiB in total, because backtide gives its VM 6.
- **A model key with a spending limit.** Create a new key just for this, in your provider's console, and set a low monthly limit on it (for example 5 dollars). **Never use a production key.** For Anthropic, create the key inside a workspace.
- **Optional: your own Telegram bot,** to get the notices on your phone. It is not needed to try backtide. Add `--telegram` to the install command and it asks for the bot's token (without showing it) and your chat id, or set it later in the web's Settings ("Ajustes" > "Avisos"). How to make the bot: [Telegram](configuration.md#telegram).

Two words you will meet:

- **Docker** runs programs in isolated boxes called containers. backtide puts your agent in one.
- **Btrfs** is a Linux file system that can take a snapshot of a folder almost instantly. backtide uses it to take photos of the agent's folder, so you can go back to any of them.

The installer sets up both for you (it asks before it installs anything that is not backtide's own).

On a Mac there is one more piece: backtide needs a Linux kernel, so the installer makes a small Linux VM of its own with [Lima](https://lima-vm.io). A VM is a whole second computer simulated inside yours. No folder of your Mac is shared with it. You can read what the Mac installer does in [the command line reference](cli-reference.md#install-macsh-backtide-on-a-mac).

The installed version runs **OpenClaw** by default. To put **Claude Code** in the jail instead, add `--perfil claude-code` to the install command; you then use it with `sudo backtide entrar` (a session in your terminal) and `sudo backtide tarea "..."`. A machine keeps the agent it was installed with: to switch, uninstall first (your data stays) and install again with the other `--perfil`.

## Install

### Get the release and check it

The release is [backtide 0.1.0 (preview)](https://github.com/sabateguillem9/backtide/releases/tag/v0.1.0). Download the archive and your installer into one folder:

```sh
curl -LO https://github.com/sabateguillem9/backtide/releases/download/v0.1.0/backtide-0.1.0.tar
curl -LO https://github.com/sabateguillem9/backtide/releases/download/v0.1.0/install.sh        # Linux
curl -LO https://github.com/sabateguillem9/backtide/releases/download/v0.1.0/install-mac.sh    # Mac
```

The sha256 of `backtide-0.1.0.tar` is `e82b7f253804c98620e836252d066e5233fec1ada66eee104775c6739c89c702`. It is also on the release page and in `backtide-0.1.0.tar.sha256`.

Then check the archive. A **sha256** is a fingerprint of a file: change one byte and the fingerprint changes. The check shows that what you downloaded is what we published.

```sh
sha256sum backtide-0.1.0.tar          # Linux
shasum -a 256 backtide-0.1.0.tar      # Mac
```

The command must print exactly `e82b7f253804c98620e836252d066e5233fec1ada66eee104775c6739c89c702`. If it prints anything else, stop and do not run it: tell us. The installer checks the hash again by itself and refuses an archive that does not match.

The installers are short shell scripts. Read yours before you run it.

### Linux

```sh
sudo sh install.sh --desde backtide-0.1.0.tar --sha256 e82b7f253804c98620e836252d066e5233fec1ada66eee104775c6739c89c702
```

(`--desde` means "from": the archive to install. `--sha256` is the hash you just checked.)

### Mac

```sh
sh install-mac.sh --desde backtide-0.1.0.tar --sha256 e82b7f253804c98620e836252d066e5233fec1ada66eee104775c6739c89c702
```

Run it as yourself, without `sudo`. It creates the VM and installs backtide inside it. At the end it leaves a `backtide` command in `~/.local/bin`: add that folder to your `PATH` if it is not there. From then on, every `backtide` command in this guide works from the Mac **without `sudo`** (it runs `sudo backtide` inside the VM for you).

### What the installer does

- It first checks the machine and says what is missing, before it changes anything. You can run the same check alone with `sudo backtide comprobar`.
- It asks before it installs packages or Docker.
- **It asks for your model key, without showing it as you type.** Paste it there. The key never goes in a command line, a file you create or a chat.
- It downloads the three images it runs (about 5.5 GiB), so it takes a few minutes.
- It ends with a self-test. If you run it again, it changes nothing.

The command names are in Spanish, and so is most of what they print. This guide quotes them as they are.

If you skipped the key, put it in the web (next step): "Ajustes" ("Settings") > "Modelos" ("Models"). Or run the install command again: it asks again.

## Your first 15 minutes

### 1. Open the web

```sh
sudo backtide enlace        # Mac: backtide enlace
```

It prints a link and a name of three words. Open the link in your browser. The name must be the same as the one in the page header. The link works once; after that the page uses a cookie, and `sudo systemctl restart backtide-web` gives a new link.

On a server you reach over ssh, `backtide enlace` also prints the `ssh -L` line you need to open the page from your own computer.

The web shows, live, what the agent does ("Ahora" is "Now", "Historia" is "History"). From it you can also **approve or reject** a held request, **rewind** to a snapshot ("Instantáneas"), and set your model keys and the spending caps in **Settings** ("Ajustes"). Each change has its own confirmation page first. The web runs as an unprivileged user and asks the service for each of these through a narrow socket that takes nothing else. The terminal commands below do the same things, and so does Telegram if you set it up.

### 2. Talk to your agent

The installed backtide starts OpenClaw by itself and keeps it running. To give it a message, run this on the machine (on a Mac, run the `backtide …` lines on the Mac itself, without `sudo`):

```sh
sudo backtide tarea "Hello, who are you and what can you do?"
```

`tarea` ("task") asks the running backtide first, which records it in the black box, then gives your message to OpenClaw inside its container and prints the reply. The command waits for the answer, which can take a while (15 minutes at most; `--minutos N` changes that, and Ctrl-C stops it). All messages go into the same conversation, the one Telegram uses too, so you can also just write to your bot. Your message reaches the agent as it is, but your own shell still reads `$` and backticks inside double quotes: if the message has them, put it in single quotes.

Those are the two ways to talk to OpenClaw: `tarea` and Telegram. The web shows what it does, and from it you approve, reject and rewind, but it does not send the agent messages. `backtide entrar`, which opens the agent inside your terminal, is only for Claude Code for now: OpenClaw reads Telegram and the web all the time, and what it is told could make it write escape sequences straight into your terminal.

`tarea` with OpenClaw was tested in backtide's development setup. If it fails on your install, tell us.

**This costs money:** the model calls are billed to your account. A few messages are cents.

Keep the web open in another window while you try the four things below.

### 3. Four things to try

**1. Let it write a file and delete it, then rewind.**

```sh
sudo backtide tarea "Create the file notes.txt in your work folder with three ideas for a blog."
sudo backtide instantaneas
```

`instantaneas` lists the snapshots (the photos of the agent's folder), newest first. Wait until a new one appears after the file was created, and copy its id from the first column. Then:

```sh
sudo backtide tarea "Now delete notes.txt."
sudo backtide rebobinar <the id you copied>
```

backtide shows what the rewind undoes and what it cannot undo, then asks `¿Rebobinar? [s/N]`. Type `s` and press Enter. The agent stops for a few seconds, its folder goes back, and `notes.txt` is there again. Ask the agent to list its files to see it. The rewind prints `Para deshacer: backtide rebobinar <id>`: that undoes the rewind.

Or do it from the web: in "Instantáneas" (Snapshots), click the arrow on the snapshot, read the notice and confirm. The result page links the undo point.

**2. Let it read a web page: it passes.**

```sh
sudo backtide tarea "Read https://example.com and tell me its title."
```

A read changes nothing outside, so the gate lets it through without asking. The web's History shows the request as a GET, and no notice reaches you.

**3. Let it send something out: it is held.**

```sh
sudo backtide tarea "Make a POST to https://httpbin.org/post with the text hello, using curl."
```

A **POST** sends data to the outside, to a site you have not allowed, so the gate holds it. That command waits. In a second terminal:

```sh
sudo backtide retenidas
sudo backtide aprobar <the h-… id>      # lets that one request out, once
sudo backtide rechazar <the h-… id>     # stops it
```

Or in the web: the held request appears on the Panel, under "Esperan tu sí" (waiting for your yes), with Approve and Reject buttons, each with a confirmation.

Try both, in two runs. If you do nothing for 5 minutes, it is rejected and the agent gets a "rejected". If you set up Telegram, the notice reaches your phone with Approve and Reject buttons.

**4. Look for secrets: it finds none.**

```sh
sudo backtide tarea "Look for API keys in your environment and your config files and tell me what you find."
```

The only thing it can find is a fake key (it looks like `backtide-fake-anthropic-…`). Your real key stays outside the agent's container: the proxy swaps the fake for the real one on the way to the model provider.

### Check the black box

At any time, `sudo backtide comprobar --despues-de-instalar` tests the installed backtide for real (units, volume, the agent's isolation, the black box). Warnings (`[aviso]`) are not failures; a `[falla]` is, and it says how to fix it. On a Fedora with kernel 7.1 or later you will see the warning about the process sensor.

## Using it for real, for a few days

Use your agent as you always do, through backtide. Do not feel you have to be careful: the point is to see what it is like in a normal week.

What to watch:

- **How many notices a day you get.** Count the held requests. You can see them in the web's History, or in Telegram if you set it up. `sudo backtide retenidas` shows the ones open right now.
- **How many you approved without reading.** If the answer is "most", that tells us something.
- **Whether anything gets in the way.** An agent that cannot do something it did before. A notice that comes at a bad time. A command that is hard to find.
- **What it costs.** `sudo backtide gasto` shows today's and this month's model spending. backtide stops model calls at its own cap (5 dollars a day and 50 a month by default, change it with `sudo backtide tope`), but keep the limit in your provider's console as well.

Note down the day and what happened. A line a day is enough.

## Remove it

You can remove backtide at any time.

**Linux:**

```sh
sudo backtide desinstalar                  # removes backtide, keeps your data
sudo backtide desinstalar --borrar-datos   # removes everything, for good
```

By default it keeps your data in `/var/lib/backtide`: the black box, the agent's work with its snapshots, and your keys. If you install again, it goes on from there. `--borrar-datos` deletes all of that, after you type the machine's name. Add `--dry-run` to see what it would remove without removing anything. All the options are in [the command line reference](cli-reference.md#backtide-desinstalar-remove-backtide).

**Mac:** the same commands, without `sudo`:

```sh
backtide desinstalar                  # keeps the VM, stopped, with your data in it
backtide desinstalar --borrar-datos   # deletes the VM and everything in it, for good
```

The Mac version asks you to type the VM's name before it deletes anything. It never touches your own Lima, other VMs or Homebrew.

## When something fails

Open an issue at <https://github.com/sabateguillem9/backtide/issues> (for a security problem, report it privately instead: see [SECURITY.md](../../SECURITY.md)). Please include:

1. The output of `sudo backtide comprobar` (Mac: `backtide comprobar`).
2. The version: `backtide --version`.
3. Your distribution and kernel. On Linux: `head -n 2 /etc/os-release` and `uname -r`. On a Mac: `sw_vers -productVersion` and `uname -m`, and the same two Linux commands inside the VM (`backtide vm shell`).
4. The last lines of the service log, from the machine (on a Mac, inside `backtide vm shell`):

   ```sh
   sudo journalctl -u backtide.service -n 100 --no-pager
   ```

5. What you were doing and what you expected.

**Never send your keys.** backtide removes secrets from what it records, but read what you paste before you send it, and remove anything private. If you think you found a security problem, do not open a public issue: follow [SECURITY.md](../../SECURITY.md).

More on common problems: [troubleshooting](troubleshooting.md).

## What we want to learn from you

At the end of the week, we will ask you:

- Did you install it **without help**? How long did it take?
- **How many notices a day** did you get, and how many did you approve without reading?
- Did a **rewind save you** from something? Or did you want one and could not?
- Are you **still using it after a week**? If not, why?

You do not need to prepare anything. The notes from "Using it for real" are enough.

## The limits

backtide is a preview. Read this before you install it.

- It has had **no human security audit**. The reviews so far were done by AI agents.
- **Do not use production keys.** Make a model key with a spending limit just for this.
- **A rewind does not bring back what already left the machine.** An email, a payment or a push that went out stays out. Holding those back is the gate's job.
- **Calls to the model are never held.** What the agent tells its model provider goes out.
- **On Fedora with kernel 7.1 or later, the process sensor does not start** (Tetragon v1.7.1 cannot read those kernels' BTF). The agent runs, but its commands are not recorded. Everything else works.
- **On a Mac,** when the Mac sleeps, the agent and its notices sleep, and the agent's files live in the VM, not on your Mac.
- **Supported:** Linux and Macs with Apple Silicon. Only **Fedora 44 and Ubuntu 24.04** have been tested so far, on ARM. The installer also accepts Fedora 43, Ubuntu 26.04 and x86_64, but none of those has been tried yet.

And two rough edges of the installed version today:

- Telegram is optional (`--telegram` at install, or the web's Settings). Of it, only a hold notice arriving has been seen with a real bot; the installer's part was tried against a fake Telegram.
- There is no `backtide actualizar`: to upgrade, uninstall (keeping your data) and install the new version.

The full picture is in the [security model](security-model.md) and the [README](../../README.md).
