# A real run: a real agent, a real model

The [demo](getting-started.md) uses fixed commands and no model. This guide is the other test: a real agent, thinking with a real model, with backtide watching it from outside and the gate asking you before anything leaves.

**This costs money.** The model calls are billed to your account at your model provider. Read "What costs money" before you start.

This is a hands-on test, not part of the automated tests. In the README's status table it is marked as done once by the maintainer (60 model calls, two rewinds from the web, one held `POST` rejected and another approved). Treat it as a prototype. Part of the Telegram side has only been tried against a fake Bot API (see [Telegram](#telegram-optional)).

You need the setup from [getting-started.md](getting-started.md) first: the VM running (`make vm-up`) and the demo working. All of this runs inside the VM; you drive it from the Mac with `make`.

Three agent setups are covered:

- OpenClaw thinking with Claude (the main one).
- Claude Code thinking with Claude.
- Either of them thinking with a local model on your Mac, with no key and no cost.

## How the key stays safe

A few words first.

- A **proxy** is a middleman. The agent's container has no direct way out to the internet. Everything it sends goes through a proxy container that backtide runs. The proxy records each request before it leaves, and holds back the ones that write or send something until you approve them.
- An **API key** is the secret that lets a program call a model and bill you.

The agent never holds your real key. It gets a fake one (it looks like `backtide-fake-anthropic-...`). When a request goes out to the model provider, the proxy swaps the fake key for the real one. If the agent is tricked into printing or sending "its key", all it can leak is the fake, which is useless outside the proxy.

Your real key goes in the **Settings** page of the backtide web view, which stores it in a file that only the service can read (mode 600), outside the agent's reach. Settings is write-only: after you save a key, the page shows only its last four characters. Never put the key in a file you create, in a chat, or in a command line.

## What costs money

Only the model calls cost money. The VM, backtide, the web and Telegram are free.

Before you start:

1. Create a **new API key just for this test**, in your provider's console (for Anthropic: platform.claude.com). Create it inside a **workspace** (use `Default` or create one). A key that belongs to no workspace is rejected with a 400 error, and OpenClaw reports it as "provider rejected the request schema or tool payload".
2. In the same console, set a **low monthly spending limit** on that key's workspace or account (for example $5). This is your safety net. backtide has its own cap, but it only counts what the proxy can measure, and it charges unknown things high so it stops early. It is not your provider's bill. **Keep a limit in the console as well.**
3. When you stop testing, delete the key in the console.

backtide's own brakes during this test:

- **Only the listed models reach the provider.** The proxy refuses any call to another model. With OpenClaw, that means yours plus OpenClaw's small helper model.
- **Spend cap.** The proxy prices every model response from the usage the provider reports. Defaults: $5 a day and $50 a month, editable in Settings. It warns you at 50, 80 and 100 %, and at the limit it rejects new calls without sending them. See the spend-cap design (internal note) (in Spanish).
- **Request limits.** At most 20 requests per second and 100,000 per day.
- **Reads to unknown sites** are limited to 256 KiB per site and 2 MiB in total per hour. After that they are held.

How much will it cost? OpenClaw sends a lot of context with every message (its instructions and tools), so each message costs about cents with a large model, and less with a small one. The maintainer's estimate for an afternoon of testing is one or two dollars. Look up current prices on your provider's pricing page; this guide gives none. To use a cheaper model, `make probar MODEL=claude-haiku-5-5`.

## OpenClaw with Claude

You need two or three terminals. Output from the tools is in Spanish for now.

**Terminal 1, the service:**

```bash
make probar
```

This stays in the foreground. It starts from zero every time (it removes any earlier test or demo), mounts a throwaway Btrfs volume, starts the proxy and the real OpenClaw in its container, and shows what backtide records: starts, snapshots, the agent's files, each model call with its tokens, what goes out to the network, and what the gate holds (`PUERTA held`). Wait for `sistema agent_start`.

It will say "FALTA LA CLAVE DE ANTHROPIC". That is expected: it is the next step. The first time it also downloads the OpenClaw image (about 1.3 GB).

`make probar` and `make demo` share the same folder, names and port, so they cannot run at the same time.

**Terminal 2, the web, and your key:**

```bash
make probar-web
```

This prints a one-time link like `http://127.0.0.1:8766/s/.../?t=...` and a three-word name. Open it in your Mac's browser and check the name matches. Then:

1. Go to **Settings** (Spanish: Ajustes), row **Anthropic**, paste your key, and confirm. The page should say the proxy already uses it and the agent keeps its fake key. Terminal 1 prints `ajustes secret_set anthropic`.
2. Leave the tab open. **Now** (Ahora) shows what is happening, **Requests** (Peticiones, and the "Esperan tu sí" box) shows held requests with their buttons, and **Snapshots** (Instantáneas) lets you rewind. The page follows your browser's language; the EN and ES links in the page switch it, or add `?lang=en` to the address.

If `make probar-web` says no test is running, start `make probar` first.

**Terminal 3, talk to the agent:**

```bash
make probar-pedir MSG="Hello, who are you and what can you do?"
```

This sends one message and waits for the answer. It can take a while, and minutes if a request is held. All messages go into the same conversation, so the agent remembers the earlier ones. Avoid the `$` character in the message: `make` swallows it. Underneath it is `backtide tarea`, the same command an installed backtide uses. `make probar-entrar` is for Claude Code only, for now.

### Five things to ask it

1. **Write and delete, then rewind.**
   `make probar-pedir MSG="Create the file notes.txt with three ideas for a blog. Then delete it."`
   Terminal 1 shows `archivo create work/notes.txt` and later `archivo delete work/notes.txt`, with snapshots in between. In the web, open **Snapshots**, click the arrow on a snapshot between the two lines, read the notice, and confirm. The agent stops for a few seconds, its folder goes back, and the file is there again. From the terminal: `make probar-instantaneas`, then `make probar-rebobinar ID=<id>`. The result gives you a point to undo the rewind.

2. **Read a web page: it passes.**
   `make probar-pedir MSG="Read https://example.com and tell me its title."`
   A read changes nothing outside, so the gate lets it through (recorded first). Terminal 1 shows `red request GET https://example.com/...` and no notice reaches you.

3. **Send something out: it is held.**
   `make probar-pedir MSG="Make a POST to https://httpbin.org/post with the text hello, using curl."`
   This is a write to an unknown site, so the gate stops it. Terminal 1 shows `PUERTA held riesgo 2 POST https://httpbin.org/post`, and the web shows it in the "waiting for your yes" box (Spanish: "Esperan tu sí"). With Telegram set up, your phone gets a notice with **Aprobar** and **Rechazar**. If you approve, it goes out once. If you reject, or do not answer within 5 minutes, it does not go out and the agent gets a "rejected". Try both.

4. **Look for secrets: there are none.**
   `make probar-pedir MSG="Look for API keys in your environment and your config files and tell me what you find."`
   The only thing it can find is the fake key. Your real key, the black box, the snapshots and backtide's configuration are not in its world. If it tries to send any of them out, the gate holds it.

5. **Telegram with a bot of its own (optional).** The agent has no Telegram bot. To test the trusted-chat rule, create a second, disposable bot with @BotFather just for the agent, and never give it the token of backtide's own bot. The agent (and the model provider, because it travels in the conversation) will see that token, so delete the bot afterwards with `/deletebot`. A message to your own chat passes; the same message to an unknown chat is held.

### Telegram (optional)

backtide can send its alerts and hold notices to your phone and let you approve or reject there. You need your own bot and the file `~/.config/backtide/telegram.toml` inside the VM (mode 600). How to create the bot is in 28-telegram.md (internal note) (in Spanish). `make probar` copies the file without reading or showing it.

Before you start, send `/start` to your bot from your Telegram chat. Telegram does not let a bot message you before you have talked to it first (the error appears as "chat not found" in terminal 1).

Without the file, everything works the same and holds are only visible in the web.

Honest status: Telegram is tested against a fake Bot API. With a real bot, only a hold notice arriving has been seen by hand. `/estado`, `/pausar`, `/seguir` and approving from the phone are not yet tried by hand.

## Claude Code

The same test with Claude Code in the cage instead of OpenClaw. The key still goes in Settings, and the gate, the spend cap, the snapshots and Telegram work the same. Claude Code chooses its own Anthropic models, so backtide's spend cap is your safety net here.

1. Terminal 1: `make probar PERFIL=claude-code`. The first time it downloads the Claude Code image (about 750 MB).
2. Terminal 2: `make probar-web`, and paste the key in Settings.
3. Give it code: `make probar-importar RUTA=/path/to/your/folder`. The folder must be one the VM can see (for example inside this repository). The copy goes to `/workspace/work/<name>` in the agent's folder. Symlinks are skipped, and the command tells you which. If the folder already exists there, it is left alone; `REEMPLAZAR=1` writes over it.

   The import **leaves out anything that looks like a secret** and tells you what: files such as `.env*`, `.npmrc`, `.netrc`, private keys (`id_*`, `*.pem`, `*.key`), `.aws`, `.ssh` and `.gnupg` folders, a `.git/config` whose remote has a user and password or a token, and agent configuration files that hold something that may be a key. `SECRETOS=1` includes them, knowing the agent will be able to read them. It never imports your whole home folder or `~/.ssh`, `~/.aws`, `~/.config` or `~/.claude`. The full list of rules is in probar.md (internal note) (in Spanish).

4. Work with it:
   - `make probar-entrar` opens Claude Code in your terminal. Leave with `/exit`. When you leave, backtide resets your terminal and prints "Sesión del agente cerrada. Estás otra vez en tu terminal." The session has really ended only when `make` gives you your prompt back: the agent can print text that looks like backtide's. `CONTINUAR=1` continues the last conversation.
   - `make probar-tarea MSG="..."` runs one task without an interface and prints the answer. `CONTINUAR=1` continues the previous conversation.
5. Get the code out: `make probar-exportar RUTA=/path/to/new/folder`. backtide takes a snapshot and copies the agent's work folder to a folder that must not exist yet (it never overwrites). It leaves out symlinks, every git repository and everything that starts with a dot (except a short list of harmless ones like `.gitignore`), because tools can run such files automatically when you open the folder (hooks, editor tasks, direnv). It tells you what it left out; `CONFIG=1` includes those files, and you should read each one before opening the folder. To get the commits: `make probar-exportar RUTA=/path/to/new/project.bundle GIT=project`. That produces a git *bundle* (a single file with the commits). Review it with `git log -p` before extracting.

   **What was exported was written by the agent.** Do not run anything from it (git, make, npm, tests, an editor) without reviewing it. Export to a folder inside the VM and **outside the repository**, for example `RUTA=$HOME/exported`; backtide refuses a destination inside its own repository or a Python environment. The details of the exclusion rules are in probar.md (internal note) (in Spanish).

Everything is recorded in the black box: who opened a session or a task, what you imported and exported, and what the agent did. If you rewind with a session open, the session is cut; `CONTINUAR=1` resumes from the snapshot. What already left (an export, an approved push) does not come back. A `git push` from the cage is held by the gate.

## A local model (Ollama on your Mac)

Both agents can think with a model on your own Mac through Ollama instead of Claude. No key, no cost, and what you tell the model does not leave your machine. The design is in 35-diseno-t20-modelo-local.md (internal note) (in Spanish).

The agent does not know where your Mac is. It calls `https://ollama.backtide.internal`, a name only the proxy understands, and the proxy forwards it to your Ollama, only on the model routes (never `/api/pull`, `/api/delete` or the account routes).

Once, on the Mac:

1. Install Ollama from ollama.com and keep it up to date. backtide asks for version 0.14.0 or newer (the first with Anthropic's API, which Claude Code uses). At start it asks Ollama for its version and notes it in the black box (`provider_local_ready`); if it is older, it warns you.
2. Set two options in a Mac terminal, then quit and reopen Ollama:

   ```bash
   launchctl setenv OLLAMA_NO_CLOUD 1
   launchctl setenv OLLAMA_CONTEXT_LENGTH 65536
   ```

   `OLLAMA_NO_CLOUD=1` turns off Ollama's "cloud" models. A `:cloud` model looks local, but Ollama sends the conversation to ollama.com. backtide already rejects those names; this closes it on the Mac too. `OLLAMA_CONTEXT_LENGTH` is how much text the model can read at once. The default is 4,096 tokens, and Ollama silently cuts what does not fit, so the agent would forget its instructions. OpenClaw needs at least 32,768 and Claude Code 64,000 or more. More context needs more memory. `launchctl setenv` lasts until you restart the Mac, for programs you open from the Dock or Spotlight.
3. Do not change `OLLAMA_HOST`. Ollama listens only on the Mac's `127.0.0.1`; the VM reaches it through `host.lima.internal`.
4. Download a model that can use tools, for example `ollama pull qwen3-coder:30b` (about 19 GB; use a smaller one with less memory).

Then:

- OpenClaw: `make probar LOCAL=qwen3-coder:30b`, then `make probar-pedir MSG="..."` as usual.
- Claude Code: `make probar PERFIL=claude-code LOCAL=qwen3-coder:30b`, then `make probar-entrar` or `make probar-tarea MSG="..."`.

No key goes in Settings. Terminal 1 shows `modelo request qwen3-coder:30b` and the web shows the calls with cost 0. Local calls do not count towards the spend cap, but at most two run at once (`[budget] max_inflight_local`).

About quality, honestly:

- A local model is much slower than Claude and gets tools wrong more often. It may write a tool call as plain text, or loop. Answering a short question well does not mean it will finish a long task.
- It has no big provider's safety filters and falls more easily for prompt injection (hidden text in a web page or file that gives it orders). The gate matters even more with it.
- The first call is slow while Ollama loads the model. backtide waits up to 5 minutes per call.

If it fails:

- `provider_local_unanswered` in the black box: Ollama is not open on the Mac, or listens on another port. Open it and run `make probar` again.
- The agent answers a model error: check the model is downloaded (`ollama list` on the Mac) and that its name is exactly what you gave in `LOCAL=`.
- `LOCAL=` together with `FALSO=1` is refused: the fake internet cannot reach your Mac.

## What this test does not record

In this test the process sensor (Tetragon, which watches commands and connections from the kernel with eBPF) does not run. eBPF is a way to watch what programs do from inside the Linux kernel, without changing them. The sensor needs privileges that this hands-on setup does not give, and it is covered by the integration tests (`make it`).

So in a real run, **the agent's commands are not recorded** (neither OpenClaw's nor Claude Code's). What is recorded: its files, the snapshots, everything that goes to the network, and what the gate does.

## Stop

- `Ctrl-C` in terminal 1 stops the service and, with it, the agent.
- `Ctrl-C` in the web terminal.
- `make probar-parar` deletes everything: the volume, the test's black box and **the key you pasted in Settings** (you paste it again next time).
- `make vm-down` stops the VM.
- If you will not test again, delete the key in your provider's console.

## If something fails

- "ya hay una prueba o una demo en marcha" (a test or demo is already running): `make probar-parar`.
- The agent says "LLM request failed: provider rejected the request schema or tool payload", and terminal 1 shows `modelo blocked`: you have not put the key in Settings yet. Until then the proxy answers on the provider's behalf with "backtide: no key set yet for anthropic" and never calls it, so it costs nothing. Once you save the key, the next call uses it. If you already did, the key may not belong to a workspace (see "What costs money").
- The agent says the key is not valid: you copied it wrong, or the console disabled it.
- "Inline API key ... temporarily disabled": OpenClaw stops using the key for a while (30 seconds to a few minutes) after the provider says it is invalid. Fix the key in Settings and wait.
- Calls are rejected with "tope de gasto de backtide alcanzado": you reached the daily or monthly cap. Raise it in Settings if you want to continue; it applies from the next call.
- The web link no longer works: `Ctrl-C` and run `make probar-web` again.
- Always set the key from Settings. Writing `keys/anthropic.key` by hand is possible but fragile; see probar.md (internal note) (in Spanish) if you must.
- More: [troubleshooting.md](troubleshooting.md).

## Where to go next

- What the gate sees and what it cannot: 32-diseno-t10-puerta.md (internal note) (in Spanish), and [security-model.md](security-model.md).
- All commands: [cli-reference.md](cli-reference.md). All settings: [configuration.md](configuration.md).
- The full source of this guide, with more detail: probar.md (internal note) (in Spanish).
