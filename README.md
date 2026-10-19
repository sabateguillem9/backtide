<!-- DRAFT for founder review. Not published. Decisions are listed in docs/26-que-publicar.md. -->

# backtide

A black box for AI agents.

backtide records what an AI agent does, from outside the agent.
It lets you rewind the agent's working folder to any earlier moment.
It is meant to hold back what cannot be undone before it leaves your machine. That part is not built yet.

> **Status: pre-alpha.** This is a working prototype, not a product. Do not rely on it to protect anything you cannot afford to lose. Read [What works today](#what-works-today) and [Security model](#security-model) first.

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
| Web view on `127.0.0.1`: live feed, history with filters, snapshots, and rewind with a confirmation step | Works |
| Outbound proxy (mitmproxy): the agent's only way out. Every request is recorded in the black box before it leaves; with no recording, nothing leaves. The agent only ever sees a fake API key; the proxy swaps in the real one. Private addresses, OAuth logins, provider-side tools and unknown destinations are refused | Works |
| Process and connection sensor (Tetragon, eBPF): every command and connection of the agent, recorded from the kernel; losses are reported, never silent | Works |
| Risk rules: each event gets a level from 0 to 3; risk 3 takes an evidence snapshot and alerts | Works |
| Telegram: alerts with Pause and Rewind buttons, `/pausar`, `/seguir`, `/estado` | Works against a fake Bot API; not yet tested with a real bot |
| Attack battery: scripted "evil agent" scenarios that run inside the VM | 50+ scenarios, all passing; a few are still pending |
| The approval gate: hold irreversible actions by their content until you approve them from your phone | In progress (next) |
| Spend cap, installer (Linux, then Mac), any agent beyond OpenClaw | Designed or planned |

Two consequences of that table:

- The agent reaches the internet only through the proxy, and only to the hosts you allow (its model provider by default). Everything it sends is recorded first.
- Nothing yet *holds* an irreversible action for your approval: that is the gate, in progress. Within the allowed hosts, a request goes out once it is recorded. backtide can restore the agent's folder; it cannot take back an email, a payment or a deleted cloud database.

The plan is in docs/08-plan-de-desarrollo.md (internal note) and the tasks are in docs/backlog.md (internal note). Most design documents are written in Spanish.

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

- Anything that has already left the machine. Rewinding does not unsend, unpay or undelete.
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
git clone <repo url>
cd <repo folder>
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

Both print a one-time link. Open it in your browser. The page is read-only.

The demo scripts use `sudo` inside the VM for a few fixed commands (mount, chown, umount, quota limit). They live in `scripts/demo/` and are never part of the product code.

## Architecture

```
Linux
  agent container      OpenClaw. Internal network, no direct exit.
                       Its working folder lives on a Btrfs volume.
  proxy                mitmproxy + our extension. The only way out. (in progress)
  sensor               Tetragon (eBPF): processes and connections. (not yet)
  backtide service     black box, snapshots, rules, web, Telegram bot.
```

Python modules in `backtide/`:

| Module | What it does |
|---|---|
| `blackbox` | Hash-chained event log, redaction, verification |
| `snapshots` | Btrfs snapshots, retention, rewind, quotas, space signals |
| `jail` | The agent's container and its OpenClaw profile |
| `sensors` | File watcher (inotify) |
| `service` | The long-running service: snapshot cycle, rewind, pause, control socket |
| `notify` | Alerts (log only for now) |
| `web` | The read-only web view |
| `cli` | The `backtide` command |

Planned and not present yet: `gate` (the proxy and approvals) and `analyzer` (risk rules).

Each black-box event has an `id`, `ts`, `source` (exec, file, net, llm, gate, snapshot), `action`, `target`, `details`, `risk` (0 to 3), `snapshot_id`, `prev_hash` and `hash`.

## Related work

The closest project to backtide is [nono](https://nono.sh) (Apache-2.0, by the Sigstore team). nono is an excellent, fast, zero-setup capability sandbox: it runs an agent — or, more granularly, each tool the agent calls — under Landlock/seccomp (Linux) or Seatbelt (macOS), injects real credentials so the agent only ever sees a phantom token, filters egress by domain, keeps a hash-chained audit log, and takes per-session filesystem snapshots you can roll back. It runs natively on macOS, Linux and WSL2 with no container or VM.

backtide makes a different trade-off. Where nono reduces an agent's authority from *inside its own process tree and user*, backtide records it *from the outside*: the agent runs in a hardened container with no direct egress, while a separate, higher-privileged service watches every process and connection from the kernel (eBPF/Tetragon), records each command, file, network call and model request into an append-only, hash-chained black box the agent can never reach, and snapshots the whole workspace every two minutes so you can rewind — and un-rewind — to any point. Holding back irreversible or outbound actions *by their content* until you approve them from your phone is the next piece being built (the gate).

nono is the better fit for "give a coding agent least privilege on my laptop"; backtide is built for "record everything from outside, hold back what's irreversible, and rewind." They compose: you can run backtide's container with nono inside it. A hands-on comparison (in Spanish) is in docs/31 (internal note).

## Contributing and reporting problems

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
- Security issues: [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.

## License

Not chosen yet. Until a license file is added, no permission to use, copy or distribute this code is granted.
