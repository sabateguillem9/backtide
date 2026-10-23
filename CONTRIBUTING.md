# Contributing

backtide is pre-alpha and moves quickly. Please open an issue to talk about a change before you write a large one.

For a security problem, do not open an issue. See [SECURITY.md](SECURITY.md).

## Setup

You need a Mac with Apple Silicon, [uv](https://docs.astral.sh/uv/) and [Lima](https://lima-vm.io/). See the quickstart in the [README](README.md). Run `make help` to list every command.

## Tests

| Command | What it runs | Where |
|---|---|---|
| `make test` | Unit tests | On the Mac |
| `make lint` | `ruff format --check` and `ruff check` | On the Mac |
| `make it` | Integration tests (Docker, Btrfs) | Inside the VM |
| `make ataques` | The evil-agent attack battery | Inside the VM |

A change is ready when `make lint` and `make test` pass. If it touches containers, the network, the black box, snapshots or permissions, `make it` and `make ataques` must pass too.

Write the tests first for logic: snapshots, the black box, rules and the gate. A new security feature needs its scenario in the attack battery. The scenarios are listed in `tests/attacks/manifest.toml`.

## Attack tests run only in the VM

Attack tests behave like a hostile agent: they delete data, fill disks, follow symlinks and try to escape containers. They run only inside the `vigia-dev` VM and its test containers. Never run them on your own machine, and never point them at a real service or a real agent with real credentials. `make ataques` runs them in the right place, and they are excluded from `make test`.

## Code

- Python 3.12, type hints, ruff and pytest. Lines are at most 100 characters.
- Small modules and clear functions. No abstractions before they are needed.
- No silent exceptions on the security path. If something fails, record it and alert.
- Do not add a dependency without discussing it first.
- Code, comments, identifiers and commit messages are in English. The command line and many design documents in `docs/` are currently in Spanish.
- Never commit secrets. Test fixtures use obvious fake values.

## Pull requests

- One logical change per pull request.
- Say what changed, why, and how you tested it.
- Sign off your commits (`git commit -s`). By doing so you state that you wrote the change or have the right to submit it under the project's license.
