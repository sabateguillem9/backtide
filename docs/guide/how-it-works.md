# How backtide works

This page explains how backtide is built, from the simple picture to the details. You do not need to know Docker, networking or eBPF. Each technical word is explained the first time it appears.

backtide is **pre-alpha**. Everything described here exists in the code and has tests, but it has only been run on the supported development setup (a Fedora VM on a Mac, see [getting started](getting-started.md)). Nobody outside the project has audited it. For what it does and does not protect against, read the [security model](security-model.md).

## The idea in one paragraph

An AI agent that can run commands, edit files and call the internet can make mistakes, or be tricked by a malicious web page or email. If the only record of what it did comes from the agent itself, you cannot trust that record. backtide puts the agent in a locked box and keeps the **recording, the snapshots and the controls outside that box**, in places the agent cannot reach. So the agent cannot erase its own tracks, and you can go back in time.

## The four pieces

backtide is made of four pieces. Three of them are **containers**. A container is a program started with its own private view of the machine: its own files, its own processes and its own network. Docker is the tool that makes and runs them. The fourth piece, the backtide service, is an ordinary program on the host.

| Piece | What it is | What it does |
|---|---|---|
| **Agent** | A container with the agent inside (OpenClaw or Claude Code) | Does the work. Sees only its own working folder. Has no way out except the proxy. |
| **Proxy** | A container with [mitmproxy](https://mitmproxy.org/) and backtide's extension | The agent's only door to the internet. Inspects every request, and asks the service whether it may go. |
| **Sensor** | A container with [Tetragon](https://tetragon.io/) | Watches the agent from inside the kernel: every program it starts and every connection it tries. |
| **Service** | The `backtide vigilar` process on the host | The brain. Keeps the black box, takes snapshots, decides what the gate does, serves the web page and runs the Telegram bot. It starts and stops the three containers. |

The service has more privileges than the agent, never fewer. It starts the agent only while it is watching, and stops it when the service stops normally. If the service is killed hard (`kill -9`), the agent keeps running unwatched until `backtide vigilar` is started again, and that first thing it does is stop the agent and start it again under watch. Restarting the service automatically after a crash needs an installer that does not exist yet.

Here is how a request from the agent travels. The next sections explain each box.

```
 AGENT container          PROXY container             SERVICE (host process)         OUTSIDE
 (internal network,       (mitmproxy + gate)
  no route out)

 1. the agent makes
    a request
         |
         v
 2. goes to the proxy --> 3. fixed rules: only ports
    (the only neighbour)     80/443, no private addresses,
                             no real key in the request,
                             no OAuth logins ...
                             On a model provider's host:
                             fake key -> real key
                                      |
                                      v
                             4. "May this go?" ---------> 5. THE GATE decides:
                                (private Unix socket)           - read       -> pass
                                                                - write/send -> HOLD
                                                                - forbidden  -> reject
                                                                     |
                                                                     v
                                                          6. write the event in the
                                                             BLACK BOX (secrets struck,
                                                             hash-chained). A held request
                                                             leaves a "held" event now and
                                                             its own when you approve it.
                                      |                              |
                             7. answer comes back <------------------+
                                allow + event number
                                or deny
                                      |
                                      v
                             8. only if allowed:  ------------------------------> INTERNET
                                the request leaves
                                      |
                             9. the response comes back, is counted
                                and recorded, then reaches the agent
```

Two rules hold in this picture:

- **Recorded before it leaves.** The event goes into the black box first, and the request is let out only after that. If the recording fails, the request is refused (`not_recorded`).
- **Held means waiting.** If the gate holds a request (step 6), it stays in the proxy until you approve it from Telegram, the web or the terminal. If you do not answer in 5 minutes, it is rejected.

## The black box

The black box is the permanent record of everything that happens. It is one SQLite file (SQLite is a small database that lives in a single file) that only the service writes to. The agent never sees it.

Each **event** has a sequence number, a time, a source (`exec` for a program, `file`, `net` for a request, `llm` for a model call, `gate` for a hold or approval, `snapshot`, `system`), an action, a target, some details, a risk level from 0 to 3, and the id of the nearest snapshot.

Three properties make it trustworthy.

**It only adds.** The database has triggers (rules that run on every change) that abort any `UPDATE` or `DELETE`, and any insert that is not exactly the next sequence number. Nobody, including backtide, edits or removes an event through the normal path.

**It is chained.** Each event stores the hash of the one before it. A **hash** is a short fingerprint of some data: change one letter in the data and the fingerprint changes completely. Here the hash is an HMAC-SHA256, a hash that is computed with a secret key. Each event's hash covers all its fields, including the previous hash. So the events form a chain. If someone edits event 40, its fingerprint no longer matches. If they delete event 40, event 41 points at something that is gone. Without the key, nobody can recompute a valid chain.

**It never stores secrets.** Before anything is written, backtide strikes out API keys, tokens, passwords, cookies, `Authorization` headers, private-key blocks and card numbers, replacing them with `[REDACTED]`. It prefers to strike too much rather than too little. Long texts are cut to 4 KiB. The redaction is applied in layers: the proxy and the sensor strike what they see, and the black box strikes again on every write.

You can check the chain at any time with `backtide verificar`. Here is a real run on a black box with two events (the second contained a bearer token, now struck out):

```
$ backtide verificar --db blackbox.sqlite3 --key blackbox.key --checkpoint blackbox.checkpoint
OK: 2 eventos íntegros (último: 2)
```

(The message is in Spanish: "2 events intact (last: 2)".) The exit code is 0 when the chain is intact, 1 when something was tampered with, and 2 when the file cannot be read. Treat any non-zero code as an alert.

Cutting off the **end** of the chain would not break it, because nothing comes after to disagree. So backtide also keeps a **checkpoint**: a small signed file, outside the database, with the number and hash of the last event. `backtide verificar` compares the two. This catches deletion at the end, and deletion of the checkpoint itself (a first checkpoint is written when the box is created).

What this does **not** do is stop someone who owns the host and has the key. They could rewrite the database and the checkpoint together. The black box makes tampering **detectable** against the agent and against people without the key. It does not make it impossible. A copy of the checkpoint outside the machine (for example in Telegram) was planned but is not built. See [known limits](security-model.md#honest-limits).

## Snapshots and rewind

backtide uses **Btrfs**, a Linux file system, to photograph the agent's working folder. Btrfs works by **copy-on-write**: when you take a snapshot, it does not copy any data. It just remembers the current state. When a file is changed later, Btrfs writes the new version to a new place and leaves the old one where it was, so both versions exist. That makes a snapshot almost instant and almost free.

The service takes a snapshot about every 2 minutes, but only when something changed. It asks Btrfs whether the folder changed (a transaction counter), rather than trusting a file watcher. Snapshots live in a folder that the agent cannot see.

A snapshot has a reason in its name: `periodic`, `manual`, `evidence` (taken automatically when something of risk 3 happens), `pre_restore` (the undo point of a rewind) and `recovered`. Only `periodic` snapshots are ever deleted automatically, using a Time Machine-style rule:

- the last 2 hours: all of them;
- up to 24 hours: the newest of each hour;
- up to 30 days: the newest of each day;
- older: the newest of each week.

**Rewind** (`backtide rebobinar <snapshot>`, also available from the web and Telegram) puts the folder back as it was in that snapshot:

1. backtide writes down its intent (so a crash half way can be repaired on the next start).
2. It stops the agent and swaps the working folder for the snapshot in one atomic step.
3. The old folder is kept as a `pre_restore` snapshot. That is the **undo point**: to undo a rewind, rewind to it.
4. It starts the agent again, and records every step in the black box.

Rewind shows you what will be undone and what will not, and asks for confirmation.

Two honest limits. Snapshots are **crash-consistent**: they capture the files as they were at that instant, like a power cut would leave them. A database in the middle of a write is not guaranteed to be tidy. And rewind restores **only the working folder**. It cannot unsend an email, undo a payment or restore something the agent changed on the internet.

The agent also has a **disk quota** on its folder (Btrfs "simple quotas") so it cannot fill the volume. The quota follows the folder across rewinds. If free space still runs low, the service freezes the agent (`docker pause`) and tells you. Resume with `backtide seguir` when there is room.

## The cage

The agent runs in a container built with these settings, all of which are in `backtide/jail/config.py`:

- **No root.** It runs as its own user and group (id 61000), not as root and not as any real person.
- **No capabilities.** Linux splits "root powers" into small pieces called capabilities. backtide drops all of them (`--cap-drop ALL`) and sets `no-new-privileges`, so a program inside cannot gain more.
- **Read-only root file system.** The agent cannot change the system inside its container. It can write only to its working folder, to a small temporary `/tmp` in memory, and nowhere else.
- **A seccomp profile.** Seccomp is a filter on **system calls**, the requests a program makes to the kernel. backtide uses Docker's default profile plus two blocks: the Btrfs control calls (so the agent cannot create hidden subvolumes that snapshots would miss, or lift its own quota) and `copy_file_range` (a cheap-copy trick that sidesteps the quota).
- **An internal network.** The agent's network has no route to the outside and no address of the host on it. This is the main protection for invariant 3. The agent cannot "forget" to use the proxy, because there is nothing else to reach.
- **Limits.** 2 GiB of memory with no swap, 512 processes, 2 CPUs by default.
- **Three mounts, no more.** The container sees its working folder, its own config folder (read-only) and the proxy's certificate (read-only). It never sees the black box, the snapshots, backtide's state folder or the Docker socket.

backtide does not trust that the container is what it asked for. Before every start, it compares the existing container with the expected settings, field by field, and refuses any difference (for example a leftover container with an extra mount). While the service runs, it checks again every cycle and kills a container that shows something it must not.

The cage is not a virtual machine. The agent shares the host's kernel. See [honest limits](security-model.md#honest-limits).

## The proxy and the fake key

A **proxy** is a go-between: instead of the agent talking to a website directly, it talks to the proxy, and the proxy talks to the website. backtide's proxy is mitmproxy with an extension. It runs in its own container on two networks: the agent's internal one and a second one that has a way out. It is the only thing that is on both.

The agent is told to use the proxy through the usual environment variables (`HTTPS_PROXY` and friends). But those variables are only a convenience. A program that ignores them still has no route out.

For secure (HTTPS) traffic the proxy has to read the request to inspect it. It does this with its own certificate authority, and the agent's container trusts only that certificate. The certificate's secret key stays in the proxy's folder; the agent receives only the public certificate.

**The fake key.** The agent never holds a real model API key. It is given a fake one, like `backtide-fake-anthropic-<32 random characters>`. When a request goes to the model provider's host, the proxy removes the credential headers and puts the **real** key in. The real keys live in backtide's state folder (or come from the Settings page) and are sent to the proxy's memory over the private channel. So:

- if the agent is tricked into printing its key, it prints a fake;
- if the agent tries to send the real key somewhere (because it found it), the proxy refuses any request, in any header, URL or body, that contains it, and also checks responses coming back.

The proxy applies fixed rules before it even asks the service: only ports 80 and 443, no private or internal addresses (so the agent cannot use the proxy to reach machines on your network), no OAuth logins, no "provider-side tools" (tools that run on the provider's servers instead of in the agent), and size limits.

The proxy also counts how much each model call costs. See [the spend cap](#the-spend-cap).

## The sensor

The **sensor** sees what the agent does from below, at the level of the kernel. It uses **eBPF**: a Linux feature that lets small, checked programs run inside the kernel at chosen points (for example "when any program starts" or "when any program opens a connection"), and report what happened. Because it runs in the kernel, the agent cannot turn it off or hide from it by changing its own files. **Tetragon** is the tool that loads the eBPF programs and writes the events.

backtide's Tetragon container is the most privileged of the three containers, because loading kernel programs needs it. In exchange it has no network, no ports, and none of backtide's files. Its policy is pinned by hash: a policy file that differs is refused.

It only **observes**. It records each program the agent starts, with its arguments (secrets struck out), and each connection it tries, even the ones that fail. It does not block anything: blocking is the job of the cage and the proxy. The sensor's value is that it catches what the other layers were not asked to look at.

Two more watchers complete the picture:

- A **file watcher** using inotify (a Linux feature that reports file changes) records which files the agent creates, edits, moves and deletes. Its records are descriptive; Btrfs, not the watcher, decides when a snapshot is needed. If the watcher cannot keep up, it folds events into a summary and says so.
- A **heartbeat**: every 30 seconds the service runs a harmless uniquely-named command in the agent's container and checks that the sensor saw it. If not, it records `sensor_down` and alerts. Losses are reported, never silent.

By default the agent keeps running if the sensor goes down (with a warning). With `[sensor] required = true` in the configuration, the service stops the agent whenever the sensor is blind.

## Risk levels

Every event gets a risk level from 0 to 3 **before** it is recorded, from a list of rules:

| Level | Meaning | What happens |
|---|---|---|
| 0 | Normal | Nothing. |
| 1 | Curious | It is noted. |
| 2 | Suspicious | It shows in the web and in the history filter. |
| 3 | Dangerous | An **evidence snapshot** is taken right away, and you get an alert. |

Examples of the default rules: deleting 20 files in a minute is level 2, deleting 100 is level 3, and rewriting 300 files in a minute is level 2. The rules use simple patterns (globs, not regular expressions) on purpose, because the agent chooses the file names and commands the rules read, and a badly written regular expression could be made to hang the watcher.

Rules only raise a level, never lower it. If a rule fails, the event is recorded anyway with level 2 at least. The default rules are in `backtide/analyzer/default_rules.toml`. You can replace them with your own file in backtide's state folder.

## The approval gate

The **gate** is the part of the service that decides what to do with each request the proxy asks about. The test it applies is what the request **does**, not only where it goes.

| What the request is | What the gate does |
|---|---|
| A call to a model provider | Passes (recorded first). Provider-side tools are refused by the proxy. |
| A **read** (`GET`, `HEAD` or `OPTIONS`, no body) | Passes, recorded first, with guards on very long URLs and a budget of how much a read can carry to unknown hosts. |
| A **write or send** (`POST`, `PUT`, `PATCH`, `DELETE`, or anything unknown) | **Held** until you approve it. A `DELETE` is risk 3, another write is risk 2, and a write that carried a secret is risk 3. |
| A WebSocket, or something forbidden | Passes only to hosts on the allowed list, or is rejected. |

Some APIs are understood by **translators**. A translator reads the content of a request to Gmail, Microsoft mail, Telegram, Slack, Discord, GitHub (git pushes and the GraphQL API) and some search-by-POST APIs. For these, the HTTP method does not decide: a `GET` that actually sends a Telegram message is held, and the notice says who would get what. Without a translator, the plain rule applies: writes held, reads pass. A request that a translator misreads as a read goes out without asking.

When something is held:

1. The request waits in the proxy, and the event `gate/held` is written to the black box.
2. You get a notice (Telegram, web, or `backtide retenidas` in the terminal) with a short sentence about what the request would do, and the agent's own text shown quoted and marked as the agent's.
3. You choose **Approve** (the request goes out once), **Reject**, or **View**. Each decision is recorded: `gate/approved` or `gate/rejected`, with who decided.
4. **If nobody answers in 5 minutes, it is rejected** (`gate/expired`). The same request is refused for the next 10 minutes without asking again.

To cut down the number of questions, you can approve a **batch** ("everything to this recipient this session", "sends of this kind for 1 hour") or mark a recipient as **trusted**. Batches are never offered for deletions, forwards, risk 3, or anything that carried a secret. A pause or a rewind ends them all. Anything the service forgets on a restart is forgotten in the safe direction: open holds are expired, not approved.

## The spend cap

Model calls cost money, and an agent in a loop can spend a lot. The proxy prices each model response from the provider's own usage report, and the service keeps the totals for the day and the month. A call that would go over the limit is refused **before** it reaches the provider. The defaults are $5 a day and $50 a month, which you can change on the Settings page. You get notices at 50 %, 80 % and 100 %.

What the service cannot measure, it charges high: a stream cut short is charged its whole `max_tokens`, and a call that never got an answer is charged its estimate. So the cap errs on the side of stopping early. It is still an estimate and **not your provider's bill**. Keep a spending limit in your provider's console as well.

## Telegram and the web

Two ways to look at backtide and act on it. Both talk to the service through its control socket, so a decision made in one place closes the notice in the other.

**Telegram.** The service runs a Telegram bot. It sends you alerts with **Pause** and **Rewind** buttons, held-request notices with **Approve / Reject / View**, and answers `/pausar`, `/seguir`, `/estado`, `/retenidas` and `/lotes`. Only one private chat, yours, is obeyed. Groups, other people and forwarded messages are ignored (and recorded as `telegram_ignored`). The bot polls Telegram, so no port is opened to the internet. The bot's token lives in backtide's state folder, never in the agent's container. Use a bot made only for backtide. Status: the bot is tested against a fake Telegram API. With a real bot, only the notice of a held request has been seen arriving so far; `/estado`, `/pausar`, `/seguir` and approving from the phone have not yet been tried by hand.

**The web.** `backtide web` serves a page on `127.0.0.1` (your own machine only). It shows a live feed, the history with filters, snapshots, and held requests. It prints a one-time link; the first visit trades it for a session cookie. By default it **only reads**. Rewind, approve/reject and the Settings page each need their own flag (`--rebobinar`, `--aprobar`, `--ajustes`), and each action asks for a confirmation first. The web never holds the black box's key, so it cannot verify or forge anything.

## Where the code lives

| Folder in `backtide/` | What it does |
|---|---|
| `blackbox` | The chained log, redaction, verification |
| `snapshots` | Btrfs snapshots, retention, rewind, quotas |
| `jail` | The agent's, proxy's and sensor's containers and their checks |
| `sensors` | The file watcher and the Tetragon reader |
| `gate` | The proxy's extension, the decision table, the translators |
| `analyzer` | The risk rules |
| `service` | The long-running service: snapshot cycle, holds, spend cap, control socket |
| `notify` | Alerts and the Telegram bot |
| `web` | The web page |
| `setup` | The installer, the machine check and the uninstaller (`backtide instalar`, `comprobar`, `desinstalar`) |
| `cli` | The `backtide` command |

Besides OpenClaw, a Claude Code profile exists and has its own attack scenarios, but OpenClaw is the agent the project is tested against most.

## Where to go next

- [Security model](security-model.md): what backtide assumes, and what it does not protect against.
- [The attack battery](attack-battery.md): how each of these protections is tested against a hostile agent.
- [Getting started](getting-started.md): run the 60-second demo.
