# How backtide was built

This page says who did what, how the work was organised, and what that means for how far you should trust the result. Everything here can be checked in the repository: the git history, the backlog (internal note), the development log (internal note) and the design documents. Most of those documents are in Spanish.

## A word from the founder

**[Founder: write this in your own words]**

<!-- Why you started backtide, what you were learning along the way, what you want a reader to take away. Keep it short. -->

## 1. Summary

- **The founder** decided what backtide is and what it must never do: the product, its scope, its security rules (the eight invariants in CLAUDE.md (internal note) and [SECURITY.md](../SECURITY.md)), and the choices that each design document put to the founder. The project's rules require the founder's approval for every new privileged command (`sudo`) and every new dependency. The founder ran the first end-to-end test with a real model.
- **Claude Code**, with Anthropic's Claude models, wrote nearly all of the code, the tests, the design documents, the attack scenarios and the security reviews. It worked as a small team of specialised agents, each with written instructions, described below.
- **Every one of the 109 commits** in the history carries a `Co-Authored-By: Claude` line.
- **No human security expert has reviewed this code.** The security reviews were done by an AI agent too. Section 5 explains what that means.

## 2. The process

### One task per session

- The work is split into tasks in the backlog (internal note). Each task has a written "done when" criterion.
- A session takes one task. It starts with a short plan that the founder approves before any code is written (the `/siguiente` skill in `.claude/skills/`).
- A session ends with `/cerrar-dia`: lint and unit tests, the security review if the task touched containers, the network, the proxy, the black box, snapshots or permissions, a commit, the backlog updated, and an entry in the development log.
- A task is ticked only when its criterion is met. When a review or a check finds something still open, the backlog says so under the task.

### Design first for risky work

- Tasks with unknowns started with a practical check in the VM: T06-1 for the proxy, T07-1 for the kernel sensor, T10-1 for the gate. From 2026-10-19 this is the job of a research agent, `equipo-id`, modelled on those first checks.
- The check is a set of small tests that run inside the Linux VM (`tests/integration/test_*_assumptions.py`). It measures what the tools really do, and it ends in a design document with options, a recommendation and numbered decisions for the founder.
- The founder answered those decisions, usually before the code was written (the exceptions are at the end of section 3). Examples: 21 (internal note) (the proxy), 23 (internal note) (the sensor), 32 (internal note) (the gate), 34 (internal note) (any agent).
- Working in the VM found things the documentation did not say. For example, the mitmproxy image adds a writable volume that had to be covered, and Tetragon can lose events without writing it in its log (only its metrics count the losses).

### Tests first

- The rule in `CLAUDE.md` is tests first for the logic: snapshots, the black box, the rules and the gate.
- Unit tests run on the Mac. Everything that needs the Linux kernel (Docker, Btrfs, eBPF) runs in a Fedora VM, through `make it`.

### An attack scenario for every security function

- Invariant 7 says every new security function gets a scenario in the "evil agent" battery. An evil-agent scenario is a script that behaves like a compromised agent inside the test container and tries to break a rule: delete in bulk, read secrets, leave by another route, erase the record.
- The scenarios are written with the `agente-malvado` agent and listed in [tests/attacks/manifest.toml](../tests/attacks/manifest.toml). Each one declares what backtide must do: stop it, record it, give it a risk level, let you recover, or hold it for approval.
- The battery is checked mechanically: a scenario marked ready without a test, or an expectation that no test checks, makes the test run fail.
- The battery runs only inside the VM, against fake servers, never against the Mac or real services (invariant 8).

### An independent security review before closing

- Before a security task is closed, a separate agent, `revisor-seguridad`, reviews the change. It has read-only tools: it cannot edit files.
- Its instructions are to think like the watched agent, check each invariant, and rank its findings as critical, high, medium or low, with the file, the attack and the fix.
- Tasks were not closed while a high finding was open: the proxy (T06) and the sensor (T07) stayed open for that reason. Several tasks had two to four review passes. The fixes came with tests, most of them written first, and new attacks found by a review became new scenarios.

### The rest of the team

The agents live in .claude/agents/ (internal note). The project started on 2026-10-05 with three: the security reviewer, the evil agent and an OpenClaw researcher. The other seven were added on 2026-10-19:

- `equipo-id`, the research agent described above.
- `investigador-mercado` looks at competitors and at what people say online.
- `equipo-tests` looks for gaps and flaky tests.
- `limpieza-codigo` reports dead code and outdated documentation, without deleting anything.
- `documentador` keeps the backlog, the log and the guides in line with the code.
- `equipo-frontend` builds the web view inside the brand and its strict content security policy, and checks it in a browser.
- `equipo-creativo` drafts texts. They are drafts only, for the founder to decide on.

The OpenClaw researcher, `investigador-openclaw`, reads OpenClaw's documentation and code for exact facts, so that the integration does not rest on guesses.

### Continuous integration

- GitHub Actions runs `make lint` and `make test` on every push to `main` and on every pull request ([.github/workflows/ci.yml](../.github/workflows/ci.yml)).
- The VM tests and the attack battery do **not** run in CI. They need the VM, so the agents ran them by hand during each task, and the results are recorded in the design documents and the backlog.

### Rules that came from mistakes

- On 2026-10-18 an agent ran `git checkout` on a file that held another session's unsaved work, and then had to rewrite it. Since then every agent is forbidden from running `git stash`, `reset` and `checkout` (devlog (internal note)).
- On 2026-10-21 the founder's first real run found two problems that no test had seen. The proxy container had the same name as the alias the agent uses to reach it, so it refused everything. And an Anthropic key outside a workspace is rejected. Both are fixed or documented. The test labs had used different names, so they could not see the first one.

## 3. The founder's key decisions

Each row is a decision recorded with its date. The source column points to where it is written down.

| Date | Decision | Source |
|---|---|---|
| 2026-10-05 (first commit) | Build a black box for AI agents: record from outside the agent, let you rewind, and stop what cannot be undone before it leaves. Start with OpenClaw on Linux. | [How it works](guide/how-it-works.md) |
| 2026-10-06 | The agent gets a fake model key; the proxy swaps in the real one, so the agent never sees it. | backlog (internal note), T06 |
| 2026-10-06 | A spending cap stops being optional. | backlog (internal note), T11 |
| 2026-10-06 | A `/pausar` command in Telegram freezes the agent from outside, at once. | backlog (internal note), T09 |
| 2026-10-06 | Default gate rules: reads pass; sending, deleting and paying are held, showing who gets what; the unknown is held rather than refused; batch approval to avoid fatigue. | backlog (internal note), T10 |
| 2026-10-06 | If the disk quota cannot be put back on a rewind, the rewind does not happen. When space runs out, backtide may grow the volume once, with a ceiling, and never deletes snapshots to make room. | backlog (internal note), T03b and T04 |
| 2026-10-07 | No plugin with hooks inside coding agents: it would run inside the agent, which could switch it off, and if it failed the action would go through. | backlog (internal note), "Después" |
| 2026-10-17 | The product is called backtide, always in lower case. | devlog (internal note) |
| 2026-10-17 | Proxy: mitmproxy pinned by digest; the real key lives only in the proxy's memory; until the gate exists, unknown hosts are refused. Six decisions, the recommended option in each. | 21 (internal note) |
| 2026-10-17 | Kernel sensor: Tetragon only observes and never kills; it is optional by default, and `required = true` makes the agent stop without it. Twelve decisions. | 23 (internal note) |
| 2026-10-17 | One new `sudo` command for the emergency-growth test, and only that one. | 19 (internal note) |
| 2026-10-17 | Installers for Mac and Windows become tasks, and backtide must work for any agent, not only OpenClaw. | backlog (internal note), T13b, T13c, T17 |
| 2026-10-19 | After a hands-on comparison with nono: credit it in the README, add a fail-closed mount check, stay with Linux plus containers. | 31 (internal note) |
| 2026-10-19 | An interpreter hiding commands in a long streak of unseen lines counts as blindness after 10 minutes, and stops an agent whose sensor is required. | backlog (internal note), T07-5 |
| 2026-10-19 | The web view becomes a control room for several agents, with colour that means something. | backlog (internal note), T12d |
| 2026-10-20 | The gate waits up to 90 s, then answers "pending"; with no answer in 5 minutes the request is rejected; an approval covers that exact request for 10 minutes. The first translators are mail and messaging. Without a translator, reads pass and writes are held. | 32 (internal note), section 18 |
| 2026-10-20 | Ten more gate decisions, the recommended option in each. For example: deleting is never approved in a batch, and "approve and trust" exists only in the web. | 32 (internal note), section 18 |
| 2026-10-20 | OpenClaw's own Telegram bot runs with native commands off, so starting it does not trigger a held request. | 32 (internal note), section 18 |
| 2026-10-20 | A Settings page in the web for keys and the cap, so nobody edits files in the VM to set a key. Before publishing, explain how backtide was built (this page). | backlog (internal note), T12e and T18 |
| 2026-10-21 | Anthropic's price table updates itself daily from the official pricing page, with strict checks. | 33 (internal note) |
| 2026-10-22 | Any agent in the jail: Claude Code is the second agent, API keys only in the first version, OpenHands stays out because it needs the Docker socket and root. Twelve decisions. | 34 (internal note), section 12 |
| 2026-10-22 | First public version: mail credentials (T19) stay out; a local model through Ollama (T20) and a browser inside the jail (T21) are in. The local-model design is approved, with Ollama's cloud API added. | backlog (internal note), D1 and D3; 35 (internal note) |
| 2026-10-22 | Apache License 2.0. | backlog (internal note), D11; [LICENSE](../LICENSE) |
| 2026-10-22 | Transparency goes in its own document (this page), and the launch is prepared as its own task. | backlog (internal note), D13 and D14 |

Not every choice in the design documents was made by the founder. Many are marked "decided by default (revisable)": an agent picked a safe value so the work could go on, and the founder has not confirmed it yet. Examples: the five defaults of the spending cap (33 (internal note), "Decisiones para el founder") and refusing provider-side tools (21 (internal note)).

## 4. What the reviews found

First drafts had real bugs, including serious ones. A few that the reviews caught and that were fixed, with tests:

- **The secret key could reach any host through the model provider** (proxy, T06-5). Requests to the provider's host leave with the real key, so the provider's own server-side tools (web fetch, connectors) would have let the agent reach any host without going through the allow list or the record. Fixed in T06-6: the proxy only lets through what a normal model client sends, and refuses provider-side tools.
- **Large requests left before they were recorded** (proxy, T06-4). A mitmproxy setting for streaming large bodies also streamed chunked requests or those over 1 MiB before our hook ran. They went out unrecorded and unchecked. Fixed.
- **Passwords stuck to their flag were stored in clear** (sensor, T07). `mysql -pSecret`, `sshpass -p` and `redis-cli -a` went into the black box as typed. This one was found by a late review after earlier passes had missed it, so the sensor task was reopened. It was fixed with a closed list of about 25 tools.
- **Secrets in credential headers to any host** (gate, T10-3). A `GET` to an unknown host carrying a recognisable token in `Authorization` or `Cookie` passed as a plain read. Now it is held. The same review showed that the design document had underestimated how much data a stream of reads could carry out: it said about 100 bytes per request, and the real figure was about 8 KiB. The document was corrected and a per-hour read budget was added (32 (internal note), section 13).
- **A disguised delete inside a batch** (gate, T10-4). A `POST` with `X-HTTP-Method-Override: DELETE` fitted into an approved batch of `POST` requests to the same host. Now that header blocks batching and is treated as a delete.
- **"Approve and trust" released other held messages** (gate, T10-5). Trusting a recipient from one held message let a second held message to the same recipient leave without approval. Now each one is decided on its own.
- **A cut stream was almost free under the spending cap** (T11). If the client closed the stream just before the final usage figures, backtide charged almost nothing. Now an incomplete answer is charged its full `max_tokens`. The rule since then: what backtide does not know is charged high, never low (33 (internal note)).
- **`exportar` could plant code that runs on the host** (T17a-4). A `.git/config` written by the agent (an fsmonitor, a pager, hooks) or a hidden bare repository would run as soon as the owner used git in the exported folder. Now `.git` folders and repository-shaped folders are never copied, and commits leave as a git bundle (34 (internal note)). The attack scenario for this is still missing.

## 5. Limits

- **No human security audit.** Nobody outside the project has reviewed backtide. Do not rely on it to protect anything you cannot afford to lose.
- **The reviewer is an AI too.** The code, the tests and the reviews come from the same family of models. They may share blind spots, and a bug that the author did not imagine may not occur to the reviewer either. The sensor's passwords in clear show this: several review passes missed them.
- **Tests written by the same team.** A green test means the code does what the team thought of testing. The VM tests and the attack battery are not in CI, so their results come from the runs recorded in the documents. Some tests have been flaky at times, and the log says so.
- **Experimental and pre-alpha.** Developed and tested on one machine, in one Fedora VM, against OpenClaw and fake servers. The installer and most real-world use (T13, T16) do not exist yet.
- **Known limits of the threat model.** What the gate cannot stop is listed in 32, section 13 (internal note): data hidden in reads, what goes to the model provider, WebSockets, anything a translator misreads as a read. What backtide does not protect against at all, such as a container escape, a compromised host or anything already sent, is in the [README](../README.md#security-model) and in [SECURITY.md](../SECURITY.md).

## 6. Numbers

Measured on 2026-10-22, at commit `0800a5a`.

| What | Count | How it was counted |
|---|---|---|
| Commits | 109, all with a `Co-Authored-By: Claude` line | `git rev-list --count HEAD`, and `git log --format=%B` searched for the trailer. 108 name Claude Opus 5.5 and one names another Claude model. |
| Calendar | 2026-10-05 to 2026-10-22, commits on 10 different days | `git log --date=short` |
| Unit tests (Mac) | 9,212; in a run of `make test` that day, 9,208 passed and 4 were skipped | `uv run pytest --collect-only -q` |
| VM integration tests | 453 | `uv run pytest --collect-only -q -m integration` |
| Attack battery | 86 scenarios: 80 ready with tests, 6 pending | `tests/attacks/manifest.toml`, field `status`; each ready one has an `@scenario` test |
| Product code | 56,683 lines in 122 Python files | `wc -l` of `backtide/**/*.py` tracked by git, blank lines and comments included |
| Test code | 101,273 lines in 272 Python files | the same for `tests/` |
| Documents | 36 numbered documents in `docs/`, plus the backlog, the log and two guides | `ls docs/*.md`. Documents 01 to 06 are an older, long-term vision, not about backtide itself. |
| Specialised agents and skills | 10 agents, 6 skills | `.claude/agents/`, `.claude/skills/` |

These numbers are counts, not quality. More tests do not mean fewer bugs, and the test code being larger than the product code says as much about the style as about the coverage.
