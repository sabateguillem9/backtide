# backtide documentation

backtide is a black box for AI agents: it records what an agent does from outside the agent, lets you rewind its working folder, and holds back what cannot be undone until you approve it.

It is **pre-alpha**. Read the [README](../../README.md) first for what works today and what does not, then pick a path below.

## I want to try it

**Testing the preview on your own machine?** Read the [guide for preview testers](testers.md): install, try it with your own agent for a few days, remove it, and tell us how it went. It assumes you already run OpenClaw or Claude Code and have 30 minutes. For the development setup and the demo:

1. [Getting started](getting-started.md): what you need, how to set up the development VM, and the 60-second demo (delete, rewind, undo).
2. [Run it with a real agent](real-run.md): OpenClaw or Claude Code thinking through the proxy, with the gate, Telegram and the web. It costs money, so read it before you start.
3. [Troubleshooting and FAQ](troubleshooting.md).

## I want to understand it

1. [How it works](how-it-works.md): the four pieces (three containers and the service), the black box, snapshots, the cage, the proxy, the sensor, the rules and the gate.
2. [Security model](security-model.md): what backtide assumes, the invariants it is held to, what it protects against and what it does not.
3. [The attack battery](attack-battery.md): the scripted "evil agent" scenarios, how to run them and how to write a new one.
4. Design documents (internal note): the detailed technical design of each piece (in Spanish).
5. [How it was built](../how-it-was-built.md): who decided what, and what Claude Code wrote.

## I want to use or change it

- [Command line reference](cli-reference.md): every `backtide` command and the useful `make` targets.
- [Configuration](configuration.md): settings, the web's Settings page, the spend cap, allowed hosts and the gate.
- [Contributing](../../CONTRIBUTING.md) and [Security policy](../../SECURITY.md).
- Backlog (internal note) and development diary (internal note): what is planned and what was done (in Spanish).

## A note on languages

The code, the command names' help, the guides in this folder, the README and the security policy are in English. The design documents, the backlog and the diary are in Spanish, each with an English copy in [`docs/en/`](../en/). The command names (`vigilar`, `verificar`, `rebobinar`, …) are in Spanish; the [command line reference](cli-reference.md) has a table with their English meaning.
