# Frequently asked questions

These are the questions people ask first, answered as plainly as we can. Where backtide falls short, the answer says so. The long version of every limit is in the [security model](security-model.md).

If you want to try it, start with the [guide for preview testers](testers.md). For problems with the scripts and the setup, see [troubleshooting](troubleshooting.md).

## Is it ready for real use?

No. backtide is a **0.1.0 preview**, and the [README](../../README.md) calls the project pre-alpha. It works end to end in the setups we tested, but nobody outside the project has audited it, and it has had little use outside the maintainer's machines. Do not rely on it to protect anything you cannot afford to lose, and do not use a production key with it. The [testers' guide](testers.md#the-limits) lists the known rough edges.

## Did an AI write this?

Almost all of it, yes. Claude Code wrote nearly all of the code, the tests and the security reviews. The founder decided what backtide is and what it must never do, approved every new privileged command and every new dependency, and ran the first real test with a real model. Every commit in the history carries a `Co-Authored-By: Claude` line. **No human security expert has reviewed the code**, and the reviews were done by an AI agent too. The reviews caught real bugs and also missed some for a while; both are in [how it was built](../how-it-was-built.md). Treat backtide as unaudited.

## Why not just use git?

Use git as well. But git keeps what you commit, and an agent with a shell can rewrite or delete history, `.git` included, if `.git` is inside the folder it can write to. It also ignores files you did not add, such as untracked files and the agent's own notes and memory. backtide takes a Btrfs snapshot of the whole working folder from outside, about every two minutes while something changes, and the agent cannot reach the snapshots. Git also does not record what the agent ran or tried to send, and it cannot hold back an email. A snapshot, like git, brings back only files: see [how rewind works](how-it-works.md#snapshots-and-rewind).

## Doesn't my agent already have checkpoints (Claude Code, for example)?

Some do, and they are useful. Claude Code's checkpoints belong to the tool and track the edits made by its own file-editing tools; [its documentation](https://code.claude.com/docs/en/checkpointing) says a file that only shell commands changed is not tracked. They live on the same side of the line as the agent. backtide snapshots the whole folder from outside the agent's container, so a `rm -rf` or a script that rewrites files is covered, and the agent has no way to edit the snapshots. Neither one brings back an email that was already sent.

## Isn't this just a Docker wrapper?

Docker is the cage, not the point. What backtide adds is around it:

- a record taken from the kernel and from the proxy, kept where the agent cannot reach, in a log where any edit breaks a hash chain;
- snapshots of the whole folder, with undo;
- a proxy that reads what a request does and holds sends and deletes until you say yes.

If isolation is all you need, a plain container, or a tool such as nono (next question), is simpler.

## How is it different from nono, or from a sandbox?

[nono](https://nono.sh) is an excellent, fast sandbox that needs no setup and runs natively on macOS and Linux. It reduces what an agent may do, from inside the agent's own user and process tree. It is the better fit for "give a coding agent least privilege on my laptop". backtide makes a different trade-off: the agent runs in a container with no way out except the proxy, and a separate, higher-privileged service records every command and connection from outside, snapshots the folder and holds requests by their content. The price is a Linux kernel (a VM on a Mac) and more setup. The README's [related work](../../README.md#related-work) section has the longer comparison. A sandbox and backtide solve different parts of the problem, and we have not tested running them together.

## What if the agent attacks backtide itself?

That is the case the design assumes. Inside the agent's container, everything is treated as controlled by an attacker. The container sees exactly three mounts (its folder, its config and the proxy's certificate), so it never sees the black box, the snapshots, backtide's configuration or the Docker socket. It has no route to the internet except the proxy. The [attack battery](attack-battery.md) is a set of scripted "evil agent" scenarios that try to break each rule (reading the control socket, planting links, editing the log, going around the proxy), and they run inside the VM.

The limits are real. The agent shares the host's Linux kernel, so a kernel or Docker bug could let it out of any container: the cage is not a virtual machine. Someone with root on the host can rewrite the black box. Read the [honest limits](security-model.md#honest-limits).

## Does it see my keys? What does it record, and what does it strike out?

The agent never holds your real model key. It is given a fake one, and the proxy swaps in the real key only on the way to the model provider. Your real key lives in backtide's state folder on your machine, and in the proxy's memory.

Before anything goes into the black box, backtide strikes out API keys, tokens, passwords, cookies, `Authorization` headers and private-key blocks. What it records:

- every program the agent starts, with its arguments, and every connection it tries;
- the file changes it makes (paths, not contents);
- every request: the method, the address (secret-looking query values struck), the names of the headers, and, for requests that send text, a redacted excerpt of at most 2 KiB;
- model calls as metadata only (model, sizes, token usage), not the conversation text;
- never the body of a response.

Three limits. The striking is pattern-based, so a secret in a form the patterns do not know could still be stored; the attack scenarios cover many forms and are where we add more. The snapshots hold your files as they are, so a secret the agent wrote into a file is in them. And the model provider, and Telegram if you turn it on, see what you send them: the whole conversation goes to the provider. Details are in [how the black box works](how-it-works.md#the-black-box) and the [security model](security-model.md).

## Will I end up clicking Approve on everything?

Possibly, and that would defeat the gate. That is why it asks little: reads pass, and only writes, sends and deletes are held, with batches and trusted recipients to cut repeats. We have no measurement from real use yet, and one of the things we want to learn from testers is how many notices you get and how many you approve without reading. If nobody answers in 5 minutes, the request is rejected. See [the approval gate](how-it-works.md#the-approval-gate).

## Why a VM on the Mac?

backtide is Linux software. It needs Btrfs for the snapshots, eBPF for the process sensor and Docker on a real Linux kernel. macOS is not Linux, and Docker Desktop on a Mac does not give backtide those. The Mac installer creates a small Linux VM of its own with [Lima](https://lima-vm.io), and puts backtide inside it. No folder of your Mac is shared with it. This also means the agent's files live in the VM, not on your Mac, and that when the Mac sleeps, the agent sleeps. If you have a Linux machine, you can install there directly. See [what you need](testers.md#what-you-need).

## Which agents and systems does it support?

Agents: **OpenClaw** is the default and the one it is mainly tested with. **Claude Code** is supported with a profile (`--perfil claude-code` when you install) and has its own attack scenarios, with less real use so far. Other agents are planned, not built.

Systems: Linux (Fedora 44 and Ubuntu 24.04 are the ones we tested) and Macs with Apple Silicon, through Lima. All our tests ran on ARM. Intel Macs do not work yet, and Windows is not supported. The installer accepts Fedora 43, Ubuntu 26.04 and x86_64, and says nobody has tried them. The [testers' guide](testers.md#what-you-need) has the details.

## Why is the command line in Spanish?

backtide began as a Spanish-language project. The commands (`vigilar`, `verificar`, `rebobinar`, `tarea`…) and most of what they print are not translated yet. The web view and its Settings page have an English version, and the [command line reference](cli-reference.md) has a table with the English meaning of every command. Translating the messages is welcome: see [CONTRIBUTING.md](../../CONTRIBUTING.md).

## What does it cost?

backtide is free software under the Apache License 2.0. What costs money is the model: your calls to the provider are billed to your own account. A few messages are cents, a long agent session is more. backtide stops model calls at its own spending cap (5 dollars a day and 50 a month by default; you can change it), but that cap counts what the proxy sees and is not your provider's bill. Set a limit in the provider's console as well. With a local model through Ollama there is no per-call bill. See the [spend cap](how-it-works.md#the-spend-cap) and [configuration](configuration.md).

## I found a bug, or I have an idea. Where do I say so?

Open an issue in the repository: there are forms for a bug, for "I tried it" (how far you got, and what was confusing) and for an idea. The "I tried it" reports are the feedback we most want. If you think you found a security problem, do not open a public issue: report it privately as described in [SECURITY.md](../../SECURITY.md). Never paste keys, tokens or the contents of your black box into an issue.
