# backtide

A black box for AI agents.

backtide records what an AI agent does, from outside the agent.
It lets you rewind the agent's working folder to any earlier moment.
It holds back what cannot be undone, such as sending a message or deleting something in the cloud, until you approve it from your phone or the web. If you do not answer, the request is rejected.

> **Status: pre-alpha.** This is a working prototype, not a product. Do not rely on it to protect anything you cannot afford to lose. Read [What works today](#what-works-today) and [Security model](#security-model) first.

**How it was built:** the founder made the product and security decisions; Claude Code wrote nearly all of the code, tests and security reviews, and no human has audited it. The details are in [docs/how-it-was-built.md](docs/how-it-was-built.md).

## Why

Agents like [OpenClaw](https://github.com/openclaw/openclaw) run with broad access to files, shells, mail and the network. When one goes wrong, or is manipulated, it can delete data and then misreport what it did. A record kept by the agent is only as trustworthy as the agent.

backtide keeps the record, the snapshots and the controls outside the agent's container, with more privileges than the agent has, never fewer.

## What works today

Developed and tested against OpenClaw, on Linux with Docker and Btrfs.

| Piece | State |
|---|---|
| Snapshots of the agent's working folder (Btrfs, copy-on-write), with Time Machine-style retention | Works |
| Rewind to any snapshot, and undo the rewind | Works |
| Black box: an append-only SQLite log where each event carries the hash of the previous one, with secrets redacted before writing; `backtide verificar` detects edits and deletions | Works |
| The agent's cage: OpenClaw in a container with no root, no capabilities, a read-only root filesystem, an internal network with no way out, and a seccomp profile | Works |
| Disk quota for the agent, so it cannot fill the volume; the quota follows the folder across rewinds | Works |
| File watcher (inotify) that records file changes in the black box | Works |
| Service (`backtide vigilar`): snapshots every 2 minutes while there is activity, freezes the agent when space runs low, `backtide seguir` to resume | Works |
| Web view on `127.0.0.1`: live feed, history with filters, snapshots, and rewind with a confirmation step. With `--aprobar` it also lists the held requests, with Approve, Reject and View, each behind a confirmation | Works |
| Outbound proxy (mitmproxy): the agent's only way out. Every request is recorded in the black box before it leaves; with no recording, nothing leaves. The agent only ever sees a fake API key; the proxy swaps in the real one. Private addresses, OAuth logins and provider-side tools are refused; writes to unknown destinations are held (the strict mode `unknown_hosts = "deny"` refuses them) | Works |
| Process and connection sensor (Tetragon, eBPF): every command and connection of the agent, recorded from the kernel; losses are reported, never silent | Works |
| Risk rules: each event gets a level from 0 to 3; risk 3 takes an evidence snapshot and alerts | Works |
| The approval gate: the proxy holds writes and other outgoing actions until you approve them (from the terminal, Telegram or the web) and rejects them if you do not answer in 5 minutes. Reads pass without asking. Translators read the content of Gmail, Microsoft mail, Telegram, Slack and Discord requests, so the notice says who gets what. Batches ("everything to this recipient", "sends of this kind for 1 hour") and trusted recipients cut down the number of questions | Works, tested in the VM against a fake internet and with the real OpenClaw. Mail trust is switched off until backtide knows your own accounts |
| Telegram: alerts with Pause and Rewind buttons, `/pausar`, `/seguir`, `/estado`, and approval of held requests with `/retenidas` and `/lotes` | Works against a fake Bot API in tests. With a real bot, the founder has so far seen only a hold notice arrive; `/estado`, `/pausar`, `/seguir` and approving from the phone are not yet tried by hand |
| Settings page in the web (`backtide web --ajustes`): put, change or remove the model API keys and the Telegram bot token from the browser. Keys are write-only: the page shows only the last four characters | Works. The Telegram change applies on restart |
| First real run (`make probar`): the real OpenClaw in its cage thinking with Claude through the proxy, with the gate, Telegram notice and web | Done once by the founder (60 model calls, two rewinds from the web, a held `POST` rejected and another approved). It is a hands-on test, not part of the automatic tests |
| Attack battery: scripted "evil agent" scenarios that run inside the VM | 80 scenarios with tests; 13 more are listed and still pending (they wait for later tasks) |
| Spend cap: the proxy prices every model response from the provider's usage report and refuses new calls at the limit ($5 a day and $50 a month by default, editable in Settings), with notices at 50, 80 and 100 %. Anthropic's prices update daily from its official pricing page | Works, tested in the VM with attack scenarios. What the proxy cannot measure is charged high, so the cap stops early rather than late. Keep a spending limit in your provider's console as well |
| Claude Code in the same cage (`make probar PERFIL=claude-code`, `backtide entrar`, `backtide tarea`), and any Linux container image through a restricted `[agent]` profile | Works in the VM; the attack battery runs with Claude Code (12 scenarios) as well as with OpenClaw. Shell mode only, with an API key |
| Installer (Linux, then Mac), Codex and other agents | Designed or planned |

Two consequences of that table:

- The agent reaches the internet only through the proxy. Everything it sends is recorded first. By default reads to any host pass and writes to hosts you have not allowed are held; in the strict mode only the hosts you allow (its model provider by default) are reachable.
- The gate decides by what a request *does*, not only where it goes. A read passes (it is recorded first). A write or a send to anything else is held, with a short sentence saying what it would do. What the gate cannot see is listed in the design (internal note), section 13: a read can still carry some data in its URL (capped by a budget per host), and a request to the model provider carries the whole conversation.
- backtide can restore the agent's folder; it cannot take back an email, a payment or a deleted cloud database that was approved or that left through a hole the gate does not cover.

Start with the [documentation guide](docs/guide/README.md). The tasks are in docs/backlog.md (internal note). Most design documents are written in Spanish.

## Security model

backtide assumes the agent may be mistaken, manipulated or hostile, and tries to make sure that does not cost you your data or your record of what happened.

**What it is built to protect against**

- The agent deleting or overwriting its own working files: you can rewind.
- The agent editing or erasing the record: it never sees the black box, and any change to it breaks the hash chain.
- The agent reaching the snapshots, the configuration of backtide or the Docker socket: none of them is mounted in its container.
- The agent filling the disk to break rewinding: it has a quota, and the service freezes it before space runs out.
- The agent reaching the internet directly: its network has no route out, and a test checks it.
- API keys, tokens and authorization headers ending up in the log: they are redacted before anything is written.

**What it does not protect against**

- Anything that has already left the machine, including what you approved. Rewinding does not unsend, unpay or undelete.
- A request the gate misreads: if a translator calls something a read that in fact writes, it goes out without asking. Without a translator, writes are held and reads pass.
- Cost beyond the cap's own errors: the cap counts what the proxy sees and charges unknowns high, but it is not your provider's bill. Keep a limit at your model provider too.
- A container escape. The agent shares the host kernel. The cage reduces the attack surface (no capabilities, seccomp, read-only root) but is not a virtual machine.
- A compromised host, root access on the host, or a malicious operator.
- Vulnerabilities in OpenClaw, Docker, Btrfs or the kernel.
- State outside the rewound folder: configuration, channel tokens and the list of who may talk to the agent are not rolled back.
- Messaging channels whose sessions break when rewound (WhatsApp, Signal): not supported in this version.
- Small information leaks from the filesystem, such as free space or device counters. They are tracked in the backlog, not fixed.
- Anything you did not run in the supported setup.

The invariants the code is held to are in [SECURITY.md](SECURITY.md). Nobody outside the project has audited this yet.

## Quickstart (development)

You need a Mac with Apple Silicon, [uv](https://docs.astral.sh/uv/) and [Lima](https://lima-vm.io/). Everything that needs the Linux kernel (Docker, Btrfs, eBPF) runs in a Fedora VM called `vigia-dev`, which mounts this folder. Linux-only code is not tested on the Mac.

```bash
git clone https://github.com/sabateguillem9/backtide.git
cd backtide
uv sync --locked

make vm-up      # create and start the dev VM (first run takes a while)
make test       # unit tests, on the Mac
make help       # every command
```

**Demo: delete, rewind, undo (about 60 seconds)**

The first `make demo` downloads the OpenClaw image (about 1.3 GB).

```bash
make demo           # terminal 1: volume + service in the foreground
make demo-crear     # terminal 2: the agent creates some files
make demo-borrar    # the agent deletes most of them
make demo-rebobinar # rewind to the good snapshot
make demo-parar     # stop everything and clean up
```

The step-by-step script is in docs/demo.md (internal note), in Spanish.

**Web view**

```bash
make web-demo   # on the Mac, no VM: invented data, served on 127.0.0.1
make demo-web   # in a third terminal, while `make demo` runs: the real demo data
```

Both print a one-time link. Open it in your browser. `make web-demo` uses invented data: it cannot rewind, and its approve and reject buttons only change what the demo remembers. `make demo-web` runs the real web with rewind and approval switched on (`--rebobinar`, `--aprobar`).

**Real run: OpenClaw thinking with Claude (hands-on test)**

`make probar` starts the same cage with the real OpenClaw talking to Claude through the proxy, the gate and Telegram. It costs money (your Anthropic account pays for the model calls) and needs a key with a spending limit. Read docs/probar.md (internal note) first, in Spanish. The key goes in the web's Settings page (`make probar-web`), never in a file or a chat, and the agent only ever sees a fake one.

The demo scripts use `sudo` inside the VM for a few fixed commands (mount, chown, umount, quota limit). They live in `scripts/demo/` and are never part of the product code.

## Architecture

```
Linux
  agent container      OpenClaw. Internal network, no direct exit.
                       Its working folder lives on a Btrfs volume.
  proxy                mitmproxy + our extension. The only way out: records, holds, swaps keys.
  sensor               Tetragon (eBPF): processes and connections.
  backtide service     black box, snapshots, rules, gate decisions, web, Telegram bot.
```

Python modules in `backtide/`:

| Module | What it does |
|---|---|
| `blackbox` | Hash-chained event log, redaction, verification |
| `snapshots` | Btrfs snapshots, retention, rewind, quotas, space signals |
| `jail` | The agent's container and its OpenClaw profile |
| `sensors` | File watcher (inotify) and the process and connection sensor (Tetragon) |
| `gate` | The proxy extension: records every request, holds the ones that write or send, translators for the content of mail and messaging requests |
| `analyzer` | Risk rules: a level from 0 to 3 for each event |
| `service` | The long-running service: snapshot cycle, rewind, pause, holds and batches, settings, control socket |
| `notify` | Alerts and the Telegram bot, with the held-request notices and their buttons |
| `web` | The web view: live feed, history, snapshots, held requests, Settings. It only reads, unless you switch on rewind, approval or settings |
| `cli` | The `backtide` command |

Each black-box event has an `id`, `ts`, `source` (exec, file, net, llm, gate, snapshot), `action`, `target`, `details`, `risk` (0 to 3), `snapshot_id`, `prev_hash` and `hash`.

## Related work

The closest project to backtide is [nono](https://nono.sh) (Apache-2.0, by the Sigstore team). nono is an excellent, fast, zero-setup capability sandbox: it runs an agent — or, more granularly, each tool the agent calls — under Landlock/seccomp (Linux) or Seatbelt (macOS), injects real credentials so the agent only ever sees a phantom token, filters egress by domain, keeps a hash-chained audit log, and takes per-session filesystem snapshots you can roll back. It runs natively on macOS, Linux and WSL2 with no container or VM.

backtide makes a different trade-off. Where nono reduces an agent's authority from *inside its own process tree and user*, backtide records it *from the outside*: the agent runs in a hardened container with no direct egress, while a separate, higher-privileged service watches every process and connection from the kernel (eBPF/Tetragon), records each command, file, network call and model request into an append-only, hash-chained black box the agent can never reach, and snapshots the whole workspace every two minutes so you can rewind — and un-rewind — to any point. Holding back irreversible or outbound actions *by their content* until you approve them from your phone is the gate, now built and tested (see [What works today](#what-works-today) for what is and is not tried with a real bot).

nono is the better fit for "give a coding agent least privilege on my laptop"; backtide is built for "record everything from outside, hold back what's irreversible, and rewind." They compose: you can run backtide's container with nono inside it. A hands-on comparison (in Spanish) is in docs/31 (internal note).

## Contributing and reporting problems

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
- Security issues: [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.

## License

Apache License 2.0. See [LICENSE](LICENSE). Copyright 2026 Guillem Sabaté.
