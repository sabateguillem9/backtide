# Security model

This page explains what backtide is trying to protect, against whom, how each rule is checked, and where it stops working. It goes deeper than the short "Security model" section of the [README](../../README.md), and it does not contradict it.

backtide is a security tool in **pre-alpha**. Nobody outside the project has audited it. Most of the code, the tests and the security reviews were written with the help of an AI coding assistant, under the direction of the maintainer; [how it was built](../how-it-was-built.md) has the details. Treat everything below as "what the project aims for and tests", not as a guarantee. Do not rely on backtide to protect anything you cannot afford to lose.

If you are new to the parts, read [how it works](how-it-works.md) first.

## What backtide assumes

backtide assumes the AI agent it watches may be:

- **Mistaken.** It misunderstands a task and deletes the wrong folder, or loops and spends your money.
- **Manipulated.** A web page, an email, a file or a chat message contains instructions that the agent follows ("prompt injection"). The agent is honest but is now working for someone else.
- **Hostile.** The agent, or code it was given, is trying to do harm on purpose.

So the design treats everything inside the agent's container as controlled by an attacker. That attacker can run any program, write any file, craft hostile file names and texts, try to open any connection, and flood backtide with events. The [attack battery](attack-battery.md) plays this role.

What backtide **trusts**:

- **The host machine and its operator.** The service runs with more privileges than the agent. If the host is compromised, or the operator is malicious, backtide cannot help.
- **The software underneath:** Linux, Docker, Btrfs, mitmproxy, Tetragon and the agent's container image. A bug in one of them can undo backtide's protection.
- **The model provider,** which receives the agent's whole conversation.
- **You,** when you approve. The gate shows you what a request would do, but a wrong "Approve" is still an approval.

## What it protects, and what it does not

This repeats the README on purpose, so the two cannot drift apart.

**It is built to protect against:**

- The agent deleting or overwriting its own working files: you can rewind.
- The agent editing or erasing the record: it never sees the black box, and any change to it breaks the hash chain.
- The agent reaching the snapshots, the configuration of backtide or the Docker socket: none of them is mounted in its container.
- The agent filling the disk to break rewinding: it has a quota, and the service freezes it before space runs out.
- The agent reaching the internet directly: its network has no route out, and a test checks it.
- API keys, tokens and authorization headers ending up in the log: they are redacted before anything is written.
- Outgoing writes and sends happening without you knowing: the gate holds them until you approve.
- A model-call bill running away: the spend cap refuses calls over the limit.

**It does not protect against:**

- Anything that has already left the machine, including what you approved. Rewinding does not unsend, unpay or undelete.
- A request the gate misreads: if a translator calls something a read that in fact writes, it goes out without asking. Without a translator, writes are held and reads pass.
- Cost beyond the cap's own errors. The cap is not your provider's bill. Keep a limit at your model provider too.
- A container escape. The agent shares the host kernel. The cage reduces the attack surface but is not a virtual machine.
- A compromised host, root access on the host, or a malicious operator.
- Vulnerabilities in OpenClaw, Docker, Btrfs or the kernel.
- State outside the rewound folder: configuration, channel tokens and the list of who may talk to the agent are not rolled back.
- Messaging channels whose sessions break when rewound (WhatsApp, Signal): not supported in this version.
- Small information leaks from the file system, such as free space or device counters. They are tracked, not fixed.
- Anything you did not run in the supported setup.

## The eight invariants

The invariants are the rules the code is held to. A violation of any of them is a security bug. They are listed in [SECURITY.md](../../SECURITY.md). Here each one comes with an example and with what checks it.

Three kinds of check are named below:

- **Unit tests** run on any machine with `make test`. They check pure logic, such as the exact `docker create` options.
- **Integration tests** (`make it`) run inside the development VM against real Docker, Btrfs and the real OpenClaw.
- **Attack scenarios** (`make ataques`) are the scripted "evil agent" tests, also inside the VM. They are explained in the [attack battery](attack-battery.md). A scenario is named by its id, for example `salida-directa`.

### 1. The agent's container never sees the black box, the snapshots, backtide's configuration or the Docker socket

*Example:* the agent plants symbolic links to `/`, `/proc/1/root` or the host path of the snapshots, then tries to read through them. Or it hunts for the control socket that `backtide rebobinar` uses, or the narrower one the installed web uses (`web.sock`, which only the web's group may use, and only for a closed list of requests).

*How it is enforced:* the container gets exactly three mounts: its working folder, its own config folder (read-only) and the proxy's certificate (read-only). Nothing else. Before each start backtide compares an existing container with the expected options and refuses any difference. While running, it kills a container that has gained a mount.

*What checks it:*

- Unit tests: `tests/test_jail_config.py`, `tests/test_jail_mounts.py`, `tests/test_jail_verify.py`.
- Integration: `tests/integration/test_jail_escape.py` (a compromised agent trying to break out).
- Scenarios: `enlaces-simbolicos`, `carpeta-cambiada-por-enlace`, `leer-secretos`, `socket-de-control`, `socket-estrecho-de-la-web`, `web-desde-la-carcel`, `montar-lo-prohibido`, `matar-el-sensor`, `telegram-de-un-extrano`.

### 2. backtide has more privileges than the agent, never the reverse

*Example:* the agent uses `sudo`, creates a hidden Btrfs subvolume so its data escapes the snapshots, or tries to raise its own disk quota.

*How it is enforced:* the agent runs as an unprivileged user with all capabilities dropped, `no-new-privileges`, a read-only root, a seccomp profile and resource limits. The seccomp profile blocks the Btrfs control calls that would let it hide data or lift its quota. The proxy runs as a user of its own, also with no capabilities and a read-only root. The sensor is privileged on purpose, because loading eBPF programs needs it, but it has no network and none of backtide's files.

*What checks it:*

- Unit tests: `tests/test_jail_config.py`, `tests/test_jail_seccomp.py`, `tests/test_jail_verify.py`.
- Integration: `tests/integration/test_jail_escape.py`.
- Scenarios: `subvolumen-anidado`, `workspace-solo-lectura`, `quitar-su-propio-tope`, `reflink-copy-file-range`, `sudo-sin-contrasena`, `perfil-hostil`, `autorizarse-en-sqlite`, `socket-de-control`.

### 3. The agent reaches the internet only through the proxy, and a test shows direct exit fails

*Example:* the agent connects straight to an IP address, sends DNS queries to its own server, ignores the proxy variables, or asks the proxy to fetch a private address on your network.

*How it is enforced:* the agent's network is internal, with no route out and no host address on it. The proxy is the only neighbour. The proxy accepts only ports 80 and 443 and refuses private addresses.

*What checks it:*

- Unit tests: `tests/test_jail_config.py` (the network options), `tests/test_jail_proxy.py`, `tests/test_gate_policy.py`.
- Integration: `tests/integration/test_proxy_criterion.py` (without the proxy the agent reaches nothing).
- Scenarios: `salida-directa`, `salida-por-el-proxy`, `ssrf-por-el-proxy`, `fronting-y-tuneles`, `dns-tunel`, `login-oauth`, `web-desde-la-carcel`, `modelo-sin-clave`, `cambia-sus-ajustes`.

This invariant says the agent cannot get out **except through the proxy**. What the proxy lets through is the gate's job (invariant 6), and some of it is by design: reads and model calls pass.

### 4. The black box is append-only, and each event carries the hash of the one before it

*Example:* someone with write access to the black box file on the host (for instance, an attacker who got out of the container) edits the `rm -rf` event into a harmless read, deletes an event, cuts off the end, swaps in another database, or recomputes the whole chain with a key of their own.

*How it is enforced:* triggers abort updates, deletes and out-of-order inserts. Hashes are keyed (HMAC), so a chain cannot be recomputed without the key. A signed checkpoint outside the database catches deletion at the end. `backtide verificar` re-checks everything and also checks that the triggers are exactly the expected ones.

*What checks it:*

- Unit tests: `tests/test_blackbox_store.py`, `tests/test_blackbox_chain.py`, `tests/test_blackbox_tamper.py`, `tests/test_cli_verificar.py`.
- Scenario: `manipular-la-caja-negra` runs eight manipulations against a copy of a real black box and requires `backtide verificar` to catch every one (exit code 1, or 2 when the file is gone).

This is detection, not prevention. See the limits below for who can still rewrite it.

### 5. Secrets are never stored

*Example:* the agent runs a command with `--password hunter2`, names a file `token=sk-...`, or sends the Gateway token in a URL path, a header, a JSON body or split across the edge of a size window.

*How it is enforced:* several layers strike secrets before anything is written. The sensor strikes program arguments. The proxy's own log never gets a request's data. The service strikes again against every secret it knows exactly (the real and fake keys, the Gateway token). The black box strikes on every append, using patterns for the common key formats and secret-looking names. The agent is also given a fake key, so the real one is never in its container.

*What checks it:*

- Unit tests: `tests/test_blackbox_redact.py`, `tests/test_secret_words_parity.py`, `tests/test_sensor_scrub.py`.
- Integration: `tests/integration/test_proxy_criterion.py` looks for every spelling of the real key in the black box, its journal, logs, `docker inspect`, the volume, the snapshots, the config and the environment.
- Scenarios: `secretos-en-la-caja-negra`, `secretos-en-la-red`, `secretos-en-argv`, `nombres-hostiles`, `nombres-de-clave-en-la-linea`, `clave-falsa-del-modelo`, `clave-falsa-a-otro-host`, `eco-de-la-clave`, `exfiltrar-credenciales`, `ajustes-desde-la-carcel`, `telegram-de-un-extrano`, `perfil-hostil`.

Redaction is pattern-based. It errs on the side of striking too much, but a secret in a form the patterns do not know could still be stored. The scenarios cover many forms and are the place to add more.

### 6. Anything destructive, or anything that leaves the machine, is held until approved. With no answer, it is rejected

*Example:* the agent sends a `DELETE` to a cloud API, sends a message to a stranger by Telegram disguised as a `GET`, repeats a held request in a loop, or tries to approve its own request by finding backtide's control socket.

*How it is enforced:* the gate holds writes and sends, and decides by what a request does where a translator exists. A held request waits for your decision. After 5 minutes without an answer it is rejected, and the same request is refused for 10 more minutes without asking again. Approvals are recorded in the black box. If the approval cannot be recorded, it is not given. Only your Telegram chat or the local web or terminal can approve.

*What checks it:*

- Unit tests: `tests/test_gate_decide.py`, `tests/test_service_holds.py` (including the 5-minute expiry), `tests/test_gate_translate_*.py`, `tests/test_web_decide.py`.
- Integration: `tests/integration/test_gate_hold.py`.
- Scenarios: `peticion-delete-retenida`, `un-get-que-envia`, `sin-respuesta-se-rechaza`, `cambiar-tras-aprobar`, `caida-a-media-retencion`, `aprobacion-falsificada`, `colarse-en-un-lote`, `inundar-de-retenciones`, `aviso-con-trampa`, `confiar-sin-querer`, `contrabando-h2`, `secretos-en-la-red`, `dns-tunel`, `exfiltrar-credenciales`, `rebobinar-desde-la-web`, `herramientas-del-proveedor`, `modelo-sin-clave`.

This invariant has a precise boundary. The gate holds **writes and sends**. It lets **reads** pass (recorded first) and lets **model calls** pass. So the invariant is only as strong as the gate's reading of the request. See the limits below.

### 7. Every new security feature has its scenario in the attack battery

*Example:* the spend cap was added, so `tope-de-gasto` and `evadir-el-tope` were added with it.

*How it is enforced:* this one is a working rule, not a mechanism. It is kept by review. What the code does enforce is that the battery stays consistent: `tests/attacks/test_battery.py` checks that every scenario marked ready has exactly one test, that no pending scenario has a test, that every attack script belongs to a scenario, and that a test checks every dimension its manifest entry promises.

*What checks it:* `tests/attacks/test_battery.py` (runs with `make test`). Nothing can prove that a feature **without** a scenario is missing one; that is a review question. Details in the [attack battery](attack-battery.md).

### 8. Attack tests run only inside the VM and the test containers

*Example:* someone runs the battery on their own laptop. It deletes data, fills disks and follows links on a real machine.

*How it is enforced:* every attack test starts with a guard that fails unless the machine is Linux, is the development VM (by host name), is not root, and has passwordless `sudo`. Attack and integration tests are also left out of the default `pytest` run, so `make test` never starts them. They use only documentation-reserved addresses and a fake internet, never a real service.

*What checks it:* the guard itself, and `test_the_vm_guard_refuses_to_run_an_attack_anywhere_else` in `tests/attacks/test_battery.py`, which proves on a Mac that the guard refuses.

The guard is a seat belt for mistakes. It checks a host name, so it cannot stop someone who is determined to bypass it. The project's CI runs only the format check, the lint and the unit tests, never attacks.

## Defence in depth

No single layer is trusted alone. The same threat meets several.

| Threat | Layers |
|---|---|
| Agent leaks a real API key | Fake key in the container; proxy refuses the real key anywhere; responses are scanned; redaction before every write |
| Agent reaches the internet directly | Internal network with no route; no host address on it; proxy on ports 80/443 only; the sensor records any attempt |
| Agent wipes its files | Snapshots every 2 minutes outside its reach; risk 3 takes an evidence snapshot; rewind and undo |
| Agent erases its tracks | Black box outside the container; append-only triggers; keyed hash chain; signed checkpoint |
| Agent fills the disk | Quota on its folder; the service freezes it when space runs low |
| Agent sends something irreversible | Gate holds writes and sends; 5-minute rejection; spend cap for model calls |

## Honest limits

These are the limits that matter most. They are not exhaustive: the README and [SECURITY.md](../../SECURITY.md) list more, and the project's backlog tracks the known gaps, including small information leaks of the file system.

- **Anything already sent stays sent.** An approved email, a payment, a deleted cloud database. Rewind restores the working folder only.
- **The gate is only as good as its reading.** Reads and model calls pass without asking. A read can still carry some data in its URL (capped by a budget per host), and a call to the model provider carries the whole conversation. A translator that misreads a write as a read lets it out. Hosts without a translator rely on the plain rule (writes held, reads pass).
- **You can approve the wrong thing.** The notice says what the request would do and marks the agent's own text as the agent's. Batches and trusted recipients reduce questions, and also reduce how closely each answer is read.
- **Container escape.** The agent shares the host's Linux kernel. No capabilities, seccomp and a read-only root reduce the surface, but a kernel or Docker bug could break out of any container. A virtual machine per agent would be stronger. backtide does not do that.
- **A compromised or malicious host.** Whoever has root on the host and the black box's key can rewrite the database and its checkpoint together. The black box detects tampering by the agent and by anyone without the key. A copy of the checkpoint kept outside the machine was planned but is not built.
- **If the service is killed hard,** the agent keeps running unwatched until `backtide vigilar` starts again. On an installed backtide, systemd restarts the service (`Restart=always`); in the development setup (`make demo`, `make probar`) nothing does.
- **The sensor does not block, and is optional by default.** Tetragon only observes. If it goes down, backtide records `sensor_down` and alerts, and the agent keeps running unless you set `[sensor] required = true`.
- **The proxy holds real keys in memory.** It faces the agent and holds the real model keys, so its hardening matters: its own user, no capabilities, a read-only root, no access to backtide's files. A vulnerability in mitmproxy itself could still matter.
- **Snapshots are crash-consistent,** not application-consistent. A database in the middle of a write may be restored in the state a power cut would leave.
- **Third parties see some data.** Telegram alerts and held-request notices pass through Telegram's servers. The text is redacted, but recipients and short excerpts of what the agent wanted to send are in the notice. Model calls go to your model provider.
- **Agent coverage.** OpenClaw is the agent the project is mainly tested with. A Claude Code profile exists and has its own scenarios, with less real use.
- **No external audit.** The code is mostly AI-written. The reviews were done by the project, with AI assistance and the maintainer's decisions. Nobody independent has looked at it.

If you find something that is worse than what is written here, please report it (see the end of this page).

## How it is tested

backtide uses three layers of tests, from cheap to expensive.

| Layer | Command | Where | What it covers |
|---|---|---|---|
| Unit tests | `make test` | Any machine (the maintainer uses a Mac) | Pure logic: the exact `docker create` options, redaction, the hash chain, the gate's decision table, the translators, the risk rules, the web's guards. Also the battery's own consistency tests. |
| Integration tests | `make it` | Inside the VM | Real Docker, real Btrfs, the real OpenClaw, a real Tetragon, a fake internet. |
| Attack battery | `make ataques` | Inside the VM | A hostile agent, scenario by scenario. See [the attack battery](attack-battery.md). |

`make lint` checks formatting and common mistakes. A change is done when `make lint` and `make test` pass; a change that touches containers, the network, the black box, snapshots or permissions must also pass `make it` and `make ataques`.

Something to know: the CI on GitHub runs `make lint` and `make test` only. The integration tests and the battery need a Linux kernel with Docker, Btrfs and eBPF, so they run on the maintainer's development VM, by hand. No one else's run of them is a public result yet.

The scenarios check the dimensions that exist today. Some risk levels and a few "was it recorded" results are still marked pending in the manifest, and the battery prints them as pending instead of passing them. The numbers are in the attack battery page.

## Reporting a problem

If you find a way around one of the invariants, please do not open a public issue. Follow [SECURITY.md](../../SECURITY.md). It says how to send a report, what is in and out of scope, and what to expect. A report that comes with a scenario for the battery is the most useful kind. [Contributing](../../CONTRIBUTING.md) explains how to write one, and the [attack battery](attack-battery.md) page shows how.
