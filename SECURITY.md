# Security policy

backtide is a security tool in pre-alpha. It has not been audited by anyone outside the project. Reports are welcome and taken seriously.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a vulnerability.

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Only the maintainers can see the report.

Include, as far as you can:

- what you found and what it lets an attacker do;
- the steps to reproduce it, ideally as a scenario for the attack battery (see [CONTRIBUTING.md](CONTRIBUTING.md));
- the commit or version you tested, and your setup (VM image, Docker version, kernel).

Do not send real secrets, personal data or anything you do not want us to hold.

What you can expect from us:

- an acknowledgement of your report within 7 days (best effort: this is a small pre-alpha project);
- a fix or a plan, and a say in when details become public;
- credit in the fix, if you want it.

There is no bug bounty.

Please test only in your own VM and test containers, never against a machine or service you do not own. The attack battery is meant to run only inside the dev VM.

## Supported versions

Pre-alpha. Only the latest preview release ([0.1.0](https://github.com/sabateguillem9/backtide/releases/tag/v0.1.0)) and the latest commit on the main branch are supported.

## Scope

In scope: anything in this repository that weakens one of the invariants below, in particular ways for the watched agent to:

- see, change or delete the black box, the snapshots, the backtide configuration or the Docker socket;
- leave its container or gain privileges beyond the minimum it is given;
- reach the internet other than through the proxy;
- get a secret recorded in the black box;
- make an event in the black box change or disappear without the hash chain breaking;
- bypass a hold on a destructive or outbound action;
- break rewinding, for example by exhausting space or metadata;
- attack the web view (which can rewind, approve holds and change settings when started with those options), its Settings page or the control socket from inside the agent's container;
- raise the spending cap, or make a model call cost less than it did, from inside the agent's container.

Also in scope: the supply chain of this repository, such as the CI workflow and pinned dependencies.

## Invariants

These are the rules the project is held to. A violation of any of them is a security bug.

1. The agent's container never mounts or sees the black box, the snapshots, the backtide configuration or the Docker socket.
2. backtide has more privileges than the agent, never the reverse. The agent runs unprivileged with the minimum capabilities.
3. The agent reaches the internet only through the proxy, and a test shows that direct exit fails.
4. The black box is append-only. Events are never updated or deleted, and each event carries the hash of the one before it.
5. Secrets are never stored. API keys, tokens, cookies and authorization headers are redacted before anything is recorded.
6. Anything destructive, or anything that leaves the machine, is held until it is approved. With no answer, it is rejected.
7. Every new security feature has its scenario in the evil-agent attack battery.
8. Attack tests run only inside the VM and the test containers, never against the host machine or real services.

Status note: invariants 3 and 6 are implemented (the proxy and the gate exist and have attack scenarios), but invariant 6 depends on the gate reading requests correctly: a write without a translator is held, while a request that a translator misreads as a read is not. The spend cap counts what the proxy sees, not the provider's bill. See the README.

## Out of scope

- Vulnerabilities in OpenClaw itself, or in any other agent being watched. Report them to that project. If you found one while testing backtide, tell the affected project first.
- Vulnerabilities in Docker, Btrfs, Lima, mitmproxy, Tetragon or the Linux kernel. Report them upstream. We do want to hear if backtide's use of them makes the impact worse.
- Attacks that need root on the host, physical access to the machine, or control of the operator's account.
- A container escape that works on the kernel regardless of backtide's configuration.
- Anything that has already left the machine (a sent email, a payment, a deleted cloud resource). backtide cannot take it back.
- Social engineering of maintainers or users.
- Findings in code under `scripts/demo/` and `scripts/web-demo/`. They are demo tools, and they use `sudo` and relaxed settings on purpose inside the dev VM.
- Denial of service against the local web view, where the attacker is already the machine's user.
- Missing hardening in a feature marked "Preview" or "Planned" in the README.
- Automated scanner output without a working scenario.

Known and tracked, not new findings: small filesystem information leaks available to the agent (free space, device counters, mount ids). They are listed in the backlog.
