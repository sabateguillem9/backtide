# Configuration

This page lists everything you can configure in backtide: the files, the options in them, their defaults and what each one does. It also says what is safe to change and what is deliberately not configurable.

> **Status: pre-alpha.** Every name and default below was read from the code of this repository. The installer is not written yet, so there is no wizard: today the config file is written for you by `make demo` and `make probar`, or by hand. Read the [security model](security-model.md) before you loosen anything.

Other guides: [command-line reference](cli-reference.md), [getting started](getting-started.md), [real run](real-run.md), [troubleshooting](troubleshooting.md).

## The short version

- **One main file, `backtide.toml`.** It holds paths, numbers and options. It **never** holds a secret: a key, token or password in it is refused and the service does not start.
- **Secrets live in backtide's state folder**, in files only the service's user can read. You set them from the web's Settings page (`backtide web --ajustes`) or by writing the file yourself.
- **Settings you change often** (the spending cap, the API keys, the Telegram bot) can be changed from the Settings page or the terminal without editing a file.
- **No setting is read from an environment variable** (see the [end of this page](#environment-variables)).
- The service reads its files when it **starts**. After editing `backtide.toml` or `rules.toml`, restart `backtide vigilar`. The exceptions are the API keys and the spending cap, which apply at once.

## Where things live

| What | Where | Who writes it |
|---|---|---|
| Main config | `backtide.toml`. Default path `/etc/backtide/backtide.toml`; any other with `--config FILE`. In the development VM: `~/backtide-demo-run/backtide.toml` | you, or `make demo` / `make probar` |
| State folder | The `state_dir` of the config. In the development VM: `~/backtide-demo-run/state` | backtide |
| Risk rules (optional) | `<state_dir>/rules.toml` | you |
| Telegram bot | `<state_dir>/telegram.toml` | you, or the Settings page |
| Real API keys | `<state_dir>/keys/<provider>.key` | you, or the Settings page |
| Fake API keys | `<state_dir>/keys/<provider>.fake` | backtide, once, the first time it is needed |
| OpenClaw's Gateway token | `<state_dir>/gateway.token` | you, or `make demo` / `make probar` |
| Trusted recipients added from the web | `<state_dir>/trusted.json` | the web, through the service |
| Spending count and caps set from the web or terminal | `<state_dir>/budget.json` | the service |
| Price table read from the provider's page | `<state_dir>/prices.json` | the service |
| Black box, its key and its checkpoint | `<state_dir>/blackbox.db`, `blackbox.key`, `blackbox.checkpoint` | the service. The key is made on the first start and never replaced |

Also in the state folder: `backtide.lock`, `control.sock` (the [control socket](cli-reference.md#four-ideas-used-on-this-page)), `rewind.pending`, `proxy-ca/`, `agent-ca/`, `proxy-channel/`, `sensor/` and the agent's config folder (`<state_dir>/<profile name>`). They are backtide's own; do not edit them.

**The agent's container never sees the state folder** (apart from its own config folder and the proxy's CA certificate). That is a core guarantee: the config cannot be made to mount it, and the service refuses to start if the paths overlap.

### File rules (backtide checks them)

The service refuses a file that someone else could have swapped. When it says "cannot be used", look here.

| File | Must be |
|---|---|
| `backtide.toml`, `rules.toml` | A regular file (not a symbolic link), owned by the user running backtide, **not writable by group or others**, at most 64 KiB, valid UTF-8 |
| State folder | Owned by that user and **not writable by group or others** (`chmod 700`) |
| `keys/` folder | Owned by that user, mode `700`. backtide creates it if missing |
| `keys/<provider>.key`, `gateway.token`, `telegram.toml` | Regular files, owned by that user, **mode `600`**, no symbolic link |

Errors name the file and its size, mode and owner. They never print what is inside.

### Checking a config without starting anything

`backtide gasto --config FILE` reads and validates the whole config first. A bad config gives exit 2 and says why. A good one gives exit 1 with "no hay un `backtide vigilar` en marcha". It has two small side effects: it creates `keys/` and the fake key files for the providers you listed, and it takes and releases `backtide.lock` for an instant.

## `backtide.toml`: top level

```toml
state_dir = "/var/lib/backtide"       # required
volume    = "/srv/backtide/volume"    # required
workspace_limit = 2147483648          # bytes
cycle_interval  = 120                 # seconds
prune_interval  = 600                 # seconds
```

| Key | Default | Effect |
|---|---|---|
| `state_dir` | required | backtide's private folder (see above). Absolute path, no `.` or `..` parts |
| `volume` | required | Root of the **snapshot store**, on a Btrfs filesystem. The agent's workspace is `<volume>/workspace`. Absolute path. It must not contain `state_dir` or be inside it: the agent writes the volume, so the black box can never live there |
| `workspace_limit` | none | The agent's disk quota, in bytes (positive whole number). It stops the agent from filling the volume, and it **switches on the space watch**: when the volume runs low, the service freezes the agent before rewinding becomes impossible (`backtide seguir` resumes it). **Without it there is no quota and no pause by space.** The service logs a warning, records `space_unwatched` (risk 2) and sends an alert at every start. The demo uses 192 MiB |
| `cycle_interval` | `120` | Seconds between two checks "did the agent's folder change?". A snapshot is taken only if it did. This is the snapshot interval: with the default, at most one every 2 minutes. Positive number. The demo uses 5, the real run 10 |
| `prune_interval` | `600` | Seconds between two retention passes (deleting old snapshots, see below). Positive number |
| `volume_image` and `max_volume_bytes` | none | Go together (set both or neither). The file behind the volume and the size it may never pass, for growing the volume when a rewind runs out of space. **Not wired up yet:** the privileged steps are not configured, so a growth attempt is recorded as failed and nothing changes |

Unknown top-level keys are refused (a key that looks like a token gets a hint that the token lives in a file).

### Snapshot retention: fixed

How long snapshots are kept is not a setting. The policy is, by age:

- under 2 hours: keep all;
- 2 to 24 hours: keep the newest of each hour;
- 24 hours to 30 days: keep the newest of each day;
- older than 30 days: keep the newest of each week, forever.

Only `periodic` snapshots are ever thinned. Manual, undo-point (`pre_restore`) and evidence snapshots stay until someone deletes them. A snapshot is also kept next to each protected one, so "rewind to just before the problem" keeps working hours later. The space thresholds that trigger the pause are fixed too.

## `[agent]`: which agent and its container

`[agent]` chooses the agent and tunes its container's size. **Nothing that decides security is settable.** The container always runs without root and without capabilities, with a read-only root filesystem, a seccomp profile, an internal network with no route out, and only its own folders mounted. Putting a security option here (`privileged`, `cap_add`, `volumes`, `network_mode`, `dns`, `ports`, `user`…) is refused by name, with the reason.

| Key | Default | Effect |
|---|---|---|
| `profile` | `"openclaw"` | Which agent: `"openclaw"`, `"claude-code"` or `"custom"` (see [agent profiles](#agent-profiles)) |
| `name` | `"backtide-agente"` | Container name |
| `network` | `"backtide-agente-net"` | Name of the agent's internal Docker network |
| `hostname` | `"agente"` | Hostname inside the container. Fixed on purpose so a restored session sees the same host |
| `image` | the profile's | The container image, **pinned by digest**: `name@sha256:<64 hex>`. A tag such as `:latest` is refused. Leave it alone for the named profiles; the custom profile requires it |
| `uid`, `gid` | `61000` | The user and group the agent runs as. Refused if they equal backtide's own |
| `memory` | `"2g"` | Memory limit (Docker size: digits then `k`, `m` or `g`). The real-run script sets `3g` |
| `cpus` | `"2"` | CPU limit (a positive number, up to two decimals) |
| `pids_limit` | `512` | Maximum processes |
| `tmp_size` | `"256m"` | Size of the agent's `/tmp` (memory-backed) |
| `stop_timeout` | `30` | Seconds Docker waits after SIGTERM before SIGKILL |
| `ready_timeout` | `120` | Seconds to wait for the agent to be ready after start. At most 600. `[agent.ready] timeout` sets the same thing; set only one |
| `config_dir` | `<state_dir>/<profile name>` | The folder with the agent's config files, mounted read-only into the container. It must never be, contain or sit inside any other backtide folder |

Unknown keys are refused.

### Agent profiles

A **profile** says what is specific to one agent: its image, command, variables, working folder and the lines that the rewind notice shows. The jail around it is the same for every profile.

| Profile | Mode | What it is |
|---|---|---|
| `openclaw` (default) | service | OpenClaw's Gateway runs as the container's main program. Needs `<state_dir>/gateway.token`: 32 to 256 URL-safe characters, mode `600`. It is OpenClaw's own token between its processes, not a model key; backtide passes it to the container and strikes it from everything it records. Make one with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `claude-code` | shell | Claude Code, in an image pinned by digest. The container waits and you drive it with `backtide entrar` and `backtide tarea` (and `importar`/`exportar` for files). It adds the package registries (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`) to the allowed hosts. Needs an API key; a subscription login is not supported in this version. No gateway token |
| `custom` | service | Any container image you describe in `[agent]`. Experimental: it goes through the same checks as the named profiles |

The `claude-code` profile accepts one more setting, `[agent.model] provider = "<name>"`: the provider (a `[[proxy.providers]]` name of kind `anthropic`, such as a local Ollama) it thinks with, instead of Anthropic's own.

The `custom` profile accepts these settings (all other custom keys are refused for the named profiles):

| Key | Default | Effect |
|---|---|---|
| `image` | required | Image pinned by digest |
| `entrypoint` | required | A list: the program and its first arguments, for example `["tini", "--"]` |
| `command` | `[]` | Arguments after the entry point |
| `workdir` | the image's | Where it starts: `"work"`, `"home"` or a folder below them (relative to `/workspace`) |
| `env` | none | A table of your own variables, `NAME = "value"`, at most 64. Refused: the jail's variables (`HOME`, `PATH`, `*_PROXY`, the CA's), variables that load code (`LD_*`, `NODE_OPTIONS`, `PYTHON*`…), Docker's, names that look like a secret, and values shaped like a secret |
| `[agent.model]` | none | `provider` (a `[[proxy.providers]]` name), `key_env` (the one variable that receives the **fake** key; its name ends in `_KEY`, `_API_KEY` or `_TOKEN`) and `allow_params` (up to 16 names of plain top-level request fields that the agent's model client sends, such as `["diagnostics"]`; backtide adds the `param:` prefix itself). `provider` and `key_env` go together |
| `[agent.ready]` | none | `log_line` (a log line that means "ready"), `probe` (a command, as a list) and `timeout` (seconds) |
| `[agent.rewind] notice` | `[]` | Up to 8 lines added to the rewind notice, after a fixed line that says backtide does not know this agent |

Example of a `claude-code` setup with a local model:

```toml
[agent]
profile = "claude-code"

[agent.model]
provider = "ollama"

[[proxy.providers]]
name = "ollama"
kind = "anthropic"
local = "http://host.lima.internal:11434"
models = ["qwen3-coder"]
```

Claude Code and local-model support exist in the code and have tests and attack scenarios in the VM. They have had less hands-on use than the OpenClaw path. Design notes: docs/34 (internal note) and docs/35 (internal note), both in Spanish.

## `[proxy]`: the only way out

The proxy (mitmproxy plus backtide's extension) is the agent's only route to the internet. Every request is recorded before it leaves.

### What is allowed to leave, in layers

1. **Fixed rules you cannot change.** Only ports 80 and 443. Private and local addresses are refused. OAuth logins are refused. A model request must be a plain model call: the provider's own search, fetch and tool features are refused (see `allow_provider_tools`). The proxy accepts at most 20 requests per second sustained and 100,000 a day.
2. **Model providers** (`[[proxy.providers]]`). Calls to a provider's host pass, but only to its model routes and only for the models you list. The agent holds a fake key; the proxy swaps in the real one on the way out.
3. **Allowed hosts** (`allow_hosts`).
4. **Everything else** is decided by the gate: reads pass, writes are held. See [`[gate]`](#gate-what-is-held-and-for-how-long).

### `[proxy]` options

| Key | Default | Effect |
|---|---|---|
| `allow_hosts` | `[]` | Hosts you vouch for. A list of up to 1000 names, each a host name or `"*.domain"` (no scheme, port or path). For a listed host: the agent may open WebSockets to it, and a request that carries credentials to it is not held just for that (to an unlisted host, a credential header is held, with risk 3 if it looks like a real token). Reads to listed hosts do not use the read budget either. In strict mode (`unknown_hosts = "deny"`) it is the list of every host the agent may reach. A profile may add its own reviewed package registries on top (see above) |
| `allow_provider_tools` | `[]` | Extra things a model request may carry that the proxy normally refuses, because they make the provider act on its side (web search, fetching URLs, running code, connectors). Each entry is a name of 1 to 64 lower-case letters, digits or `_.:-`: a tool type (for example `web_search`), or `param:<field>` for a plain top-level request field (the real-run script uses `param:fallbacks`). Up to 64. Every use is recorded. **Adding one weakens the gate.** Leave it empty unless you know why |
| `[[proxy.providers]]` | none | The model providers (see below). At most 16 |
| `name`, `network`, `image`, `uid`, `gid`, `memory`, `cpus`, `pids_limit` | `"backtide-egress"`, `"backtide-salida-net"`, a pinned mitmproxy image, `61001`, `61001`, `"1g"`, `"1"`, `128` | The proxy's container. The ids must differ from backtide's and the agent's |

Unknown keys are refused, and so is any key whose name contains `key`, `token`, `secret`, `password` or `credential`.

### `[[proxy.providers]]`: model providers

A provider tells the proxy where a model API is and which models the agent may use. Without a provider, the agent has no model to think with.

| Key | Default | Effect |
|---|---|---|
| `name` | required | `a-z`, `0-9` and `-`, up to 32 characters, unique. The real key lives in `keys/<name>.key`. The Settings page manages the providers named exactly `anthropic`, `openai` and `ollama-cloud` |
| `kind` | required | `"anthropic"` (key sent as `x-api-key`) or `"openai"` (`Authorization: Bearer`, for OpenAI and compatible APIs) |
| `host` | `api.anthropic.com` for `anthropic`, `api.openai.com` for `openai` | The API host: one exact name. A host that belongs to the other kind is refused (the real key would go to the wrong place) |
| `models` | `[]` | The model ids the proxy lets through (up to 32). A call to any other model is refused. For OpenClaw list the main model and its helper model; for Claude Code leave it empty, because Claude Code picks its own |
| `stream_usage` | `true` | Only for `kind = "openai"`, not local: whether the proxy asks the provider to report the usage of streamed calls, so the spending cap can count them. Set `false` for a compatible API that rejects the extra field |
| `local` | none | Makes this a **local provider**: `"http://<name or private IPv4>:<port>"`, exactly that shape (plain HTTP, no path). For a model server on your own machine or network, such as Ollama. See below |

Example:

```toml
[proxy]
allow_provider_tools = ["param:fallbacks"]   # optional

[[proxy.providers]]
name = "anthropic"
kind = "anthropic"
models = ["claude-sonnet-5-5", "claude-haiku-4-5"]
```

The real key is **not** here. Put it in `<state_dir>/keys/anthropic.key` (mode `600`), or in the Settings page. A provider with no usable key *waits*: the service starts normally, the proxy refuses that provider's calls, and the Settings page says it is waiting.

**Local providers** (an Ollama you run yourself) use no key and cost nothing. The agent calls a made-up name, `<name>.backtide.internal`, and the proxy takes it to your machine. `host` is refused for them, `models` is required, and models that run in Ollama's cloud are refused (your data would leave home). The address must be a private IPv4 (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`), or a machine name that the service resolves itself. Loopback and public addresses are refused. At most 4 local providers. In the development VM, `host.lima.internal` is the Mac. Calls to a local provider are never stopped by the spending cap and use their own in-flight limit (`max_inflight_local`). A local provider has been tested against a fake Ollama in the VM, not yet by hand against a real one.

**Ollama's cloud API** is a normal public provider (`kind = "openai"`, `host = "ollama.com"`, key name `ollama-cloud`). It is billed by plan, not by token, so backtide cannot know its price: each of its models needs a price you set in `[budget.prices]`, or the service does not start. Not tested against the real service.

## `[gate]`: what is held, and for how long

The **gate** is the part of the proxy that decides by what a request *does*. A read passes (after being recorded). A write or a send goes to a **hold**: it waits for you to approve it. If you do not answer, it is rejected. Full design: docs/32 (internal note) (in Spanish).

| Key | Default | Range | Effect |
|---|---|---|---|
| `unknown_hosts` | `"hold"` | `"hold"` or `"deny"` | How to treat hosts that are not in `allow_hosts` and are not providers. `"hold"`: reads pass (with a guard, see below) and writes are held. `"deny"`: the strict mode, everything to an unlisted host is refused |
| `hold_s` | `300` | 30 to 300 | How long an open hold lives before it is rejected on its own. Default: 5 minutes |
| `wait_s` | `90` | 1 to 90 | How long a held request keeps its connection open waiting for your answer. After that the agent gets "pending" and retries. An approval after that lets the next identical request through, once |
| `preapproval_s` | `600` | 30 to 600 | How long a "yes" given when nobody was waiting stays valid for one identical request. Default: 10 minutes |
| `read_budget_host_kib` | `256` | 0 to 1048576 | KiB per hour that reads to one **unlisted** host may carry out in their URLs and headers. Past it, reads to that host are held. `0` holds every read to an unlisted host that carries anything |
| `read_budget_total_kib` | `2048` | 0 to 1048576 | The same, across all unlisted hosts together |
| `read_endpoints` | `[]` | up to 64 | Extra search-like APIs that are read with `POST`: entries `"host/path"` (no scheme or query). They are treated as reads instead of being held. Add one only if you are sure the endpoint cannot change anything |
| `trusted` | `[]` | up to 256 | Recipients you trust (next section) |
| `trust_owner_chat` | `true` | true/false | Whether your own Telegram chat (the `chat_id` of `telegram.toml`) counts as trusted. Messages the agent sends to *you* then pass without asking |

All times are whole numbers of seconds, and **can only be shortened** from the defaults. A value outside the range is refused.

Things the gate does that you cannot configure: a read whose URL or headers carry a secret, or are over 2 KiB, is held; the bytes of a read to an unlisted host are charged to the read budget; at most 20 holds are open at a time; at most 10 batches are active; a rejected or expired request is refused for 10 minutes without asking again. Details are in docs/32.

What the gate cannot see is listed in the design (section 13): a read can still carry some data in its URL (that is what the read budget caps), and a request to your model provider carries the whole conversation.

### Trusted recipients

A send or a change whose recipients are **all** trusted passes without asking. Everything else is held. There are two sources: the `trusted` list in the config, and recipients you add from the web with "Approve and trust this recipient" (stored in `trusted.json`, at most 50, listed on the Requests page with a "Remove" button; the ones from `backtide.toml` are changed in the file).

An entry is a table with `translator` and one more key, depending on the translator. A **translator** is a small reader that understands one service's API, such as Gmail or Slack, so the gate can say "send an email to Ana" instead of "POST to some URL".

| `translator` | Second key | Value |
|---|---|---|
| `"telegram"` | `chat` | A chat id (a number) or an `@username` |
| `"gmail"`, `"graph_mail"` (Microsoft mail) | `email` | A plain address, `name@domain` |
| `"slack"` | `channel` | The channel **id** (`C…`, `G…` or `D…`), never its name |
| `"discord"` | `channel` | The channel id |

```toml
[gate]
trusted = [
  { translator = "telegram", chat = "123456789" },
  { translator = "slack", channel = "C0123456789" },
]
```

Caveats:

- **Mail trust is switched off for now.** A trusted address says who reads, not who writes: a mail from an attacker's account to the same person would pass. So a mail recipient only counts when it is sent from one of *your own* accounts, and backtide does not know your accounts yet. The service logs a warning at start, and the web does not offer to trust a mail address.
- Never trusted, whatever the list says: a forward, a deletion, an administration action, anything of risk 3, anything that carries a secret, a message that makes the platform fetch a URL, and an edit of an inline Telegram message. Every `Reply-To` address must be trusted too.
- Approval **batches** ("everything to this recipient this session", "sends of this kind for 1 hour") are created from the Telegram buttons, not from a file. A session batch lasts at most 12 hours, a kind batch 1 hour; both end when you pause or rewind the agent or restart backtide.

## `[budget]`: spending cap

backtide prices every model response from the usage the provider reports, adds it up per day and per month, and **refuses new model calls once a cap is reached**. The check is *before* sending, so a call is never cut in the middle; a burst can pass the cap by one call at most.

What backtide cannot measure it charges high, never low: an unknown model, a response with no usage, or a stream cut short is charged an estimate by excess. So the cap stops early rather than late. It is still not your provider's bill. **Keep a spending limit in the provider's console as well.**

| Key | Default | Range | Effect |
|---|---|---|---|
| `daily_usd` | `5` | greater than 0, two decimals, up to 100000 | Daily cap in dollars. A number (`5`, `7.5`) or a text (`"7.50"`) |
| `monthly_usd` | `50` | same | Monthly cap |
| `timezone` | `"local"` | an IANA name such as `"Europe/Madrid"`, or `"local"` | The time zone that decides when "a day" and "a month" start. `"local"` is the machine's (found from `TZ` or `/etc/localtime`). The day rolls over forwards only: a clock set back never opens a new day with nothing spent |
| `max_inflight` | `4` | 1 to 64 | Model calls that may be in flight at once. One more gets a "throttled" answer with `Retry-After` |
| `max_inflight_local` | `2` | 1 to 64 | The same, for local models. Apart from `max_inflight`: they cost nothing |
| `auto_prices` | `true` | true/false | Update the price table from Anthropic's public pricing page, at start and then once a day (never through the agent's proxy). `false`: only the last good table saved is used |
| `prices_url` | Anthropic's pricing page | `https://…` (or `http://127.0.0.1…` for tests) | Where to read prices from. Meant for the tests' fake page. Redirects are not followed |
| `[budget.prices."<model>"]` | none | up to 64 models | Your own prices, in dollars per million tokens: `input` and `output` (both required), and optionally `cache_read`, `cache_write_5m`, `cache_write_1h` (default 0.1×, 1.25× and 2× the input). Yours win over every other table |

```toml
[budget]
daily_usd = 5
monthly_usd = 50
timezone = "Europe/Madrid"

[budget.prices."my-model"]
input = 1.0
output = 5.0
```

**Price table, in order of priority:** your `[budget.prices]`; then the last good table read from Anthropic's page; then the prices shipped with backtide (dated, and a test fails when they are over 180 days old). New models and price drops of more than half found on the page are not applied by themselves: they wait for your OK on the Settings page ("New prices"). The reader follows the layout the page has always had; if the real page differs, nothing updates and you get at most one warning a day. The shipped prices then apply.

**Warnings.** At **50 %, 80 % and 100 %** of each window (the day and the month, separately), backtide records an event in the black box and sends an alert (Telegram, or the service log if there is no Telegram). Each threshold fires once per window; if one call jumps several, there is one alert for the highest. Totals also show in the web panel and the Settings page, and in Telegram's `/estado`.

**At the cap.** The proxy answers new model calls itself with the provider's own kind of error (HTTP 429 for Anthropic and `insufficient_quota` for OpenAI), without contacting the provider. Each refusal is recorded (risk 2; after the first, at most one record every 10 seconds). If backtide cannot count at all (its state file is unusable and the black box cannot be read), it refuses every model call (HTTP 503).

**Changing the cap without editing the file.** `backtide tope --dia 3 --mes 20`, or the Settings page. Both go through the service, are written to the black box first, and apply to the next model call. **A cap changed this way is stored in `budget.json` and wins over `[budget]` in the file from then on.** The values in `backtide.toml` are only the starting point. To go back, change them again the same way.

## `[sensor]`: processes and connections

The sensor is Tetragon (eBPF) in its own container. It watches from the kernel every command and network connection the agent makes. These options are advanced; the defaults are the measured ones.

| Key | Default | Effect |
|---|---|---|
| `required` | `false` | `false`: if the sensor cannot start or goes blind, the agent runs anyway and you get an alert and a black-box event. `true`: the agent does not start without a working sensor and is stopped when the sensor stops seeing |
| `novelty_streak_minutes` | `10` | Minimum 1. With `required = true`, how long new, unseen command lines may keep being folded into summaries, with no clear window in between, before the agent is stopped |
| `exec_rate`, `net_rate` | `20`, `20` | Commands / connections per second recorded one by one before the rest is folded into summaries. Positive number |
| `exec_burst`, `net_burst` | `500`, `200` | The burst allowed on top of the rate. Positive whole number |
| `exec_daily`, `net_daily` | `100000`, `50000` | Events recorded one by one per day. Positive whole number |
| `name`, `memory`, `cpus`, `cgroup_rate` | `"backtide-sensor"`, `"1g"`, `"1"`, `"1000,1s"` | The sensor's container, and the limit the kernel applies per cgroup (`count,window`) |

Whatever does not fit is folded into a summary event that says how many were folded and lists the distinct programs. Losses are reported, never silent. The sensor's image is pinned in code and is not a setting.

## Risk rules: `rules.toml`

Every event gets a **risk level** before it is recorded: 0 normal, 1 curious, 2 suspicious, 3 dangerous. Level 3 takes an evidence snapshot at once and sends an alert. Rules only rate events; holding requests back is the gate's job.

backtide ships a default set (`backtide/analyzer/default_rules.toml`, in the source; the comments are in Spanish). It covers mass deletes and modifications, key and credential files, hostile file names, dangerous commands (`rm -rf /`, `dd` onto a disk, download-and-run, `sudo`, `chmod -R 777`) and request floods.

To change the rules, copy that file to `<state_dir>/rules.toml` and edit it. **If that file exists it replaces the defaults entirely**, so deleting a rule turns it off. A mistake is an error that names the rule and the key, and the service does not start.

A rule is a `[[rule]]` table, at most 200 per file:

| Key | Meaning |
|---|---|
| `id` | Required. Lower-case words joined by hyphens, unique |
| `description` | Required. One line, up to 200 characters; the alert shows it |
| `risk` | Required. 1, 2 or 3 |
| `source` | One of `exec`, `file`, `net`, `llm`, `gate`, `snapshot`, or a list. Omitted: any |
| `action` | An action name or a list. Omitted: any |
| `target` | Glob patterns for the event's target; one match is enough |
| `unless` | Glob patterns that exclude events from this rule |
| `where` | Conditions on the event's details: `{ field = "nlink", op = "gt", value = 1 }`. `op` is `eq ne gt ge lt le in glob exists`. All must hold |
| `burst` | `{ count = 100, window = 60 }`: this many matching events in the last `window` seconds (up to 3600). Optional `sum` and `default` to add up a number in the details |

A rule needs at least one of `source`, `action`, `target` or `where`. There are no regular expressions, on purpose: an agent chooses the file names and commands these rules read, and a bad regex could hang the watcher. Patterns are globs (`*` any run including `/`, `?` one character, `[a-z]` a class; write a literal `*` as `[*]`). When several rules match, the highest risk wins, and the event records which rules matched.

```toml
[[rule]]
id = "touches-ssh"
description = "Touches an SSH key"
risk = 3
source = "file"
action = ["create", "modify", "delete"]
target = [".ssh/*", "*/.ssh/*"]
```

## Telegram

Telegram gives you alerts with **Pause** and **Rewind** buttons, `/pausar`, `/seguir`, `/estado`, and approval of held requests with `/retenidas` and `/lotes`. Design and safety rules: docs/28 (internal note) (in Spanish).

The bot is configured by a single file, `<state_dir>/telegram.toml`, mode `600`, not in `backtide.toml`:

```toml
token = "<the token BotFather gave you>"   # <digits>:<30 to 64 characters>
chat_id = 123456789                        # your own private chat's id, a positive number
# api_base = "https://api.telegram.org"    # optional, for tests only
```

| Key | Required | Effect |
|---|---|---|
| `token` | yes | The bot's token from @BotFather. Treat it like a password |
| `chat_id` | yes | Your **private** chat's id. Groups and channels have negative ids and are refused: only a private chat may command the bot |
| `api_base` | no | The Bot API address. `https://…`, or `http://` on this machine's loopback for a fake API. Tests only |

How to set it up:

1. In Telegram, talk to @BotFather, send `/newbot`, and follow the steps. It gives you the token.
2. Use **a bot that is only for backtide**. If the agent ever gets its own Telegram channel, give it a different bot with a different token.
3. Find your chat id (for example by asking a bot such as @userinfobot) and write `/start` to your new bot once. Telegram does not let a bot write to you before you have written to it.
4. Put the two values in the file, in the Settings page ("Ajustes" > "Avisos"), or give them to the installer: `sudo backtide instalar --telegram` asks for the token without echo and for your chat id, writes this file and restarts the service ([details](cli-reference.md#installsh-and-backtide-instalar)). By hand or in Settings, restart the service afterwards: the bot reads the file when the service starts.

Behavior:

- **No file, no bot.** Alerts go to the service log only.
- **A file that exists but is unusable** (wrong mode, a symbolic link, a malformed token) stops the service from starting. It says what is wrong without printing the token.
- If Telegram refuses the token at runtime, the service logs it and keeps watching without Telegram.
- The bot answers only your private chat. Everyone else is ignored without a reply, and each attempt is recorded.
- It uses long polling: backtide asks Telegram for news. No port is opened to the internet.
- Alert rates, the limit of commands, and the lifetime of a rewind confirmation (2 minutes) are fixed.

**Status:** all of this is tested against a fake Bot API. With a real bot, only a hold notice arriving has been seen so far; `/estado`, `/pausar`, `/seguir` and approving from the phone are not yet tried by hand. If the token leaks, send `/revoke` to @BotFather, put the new token in the file and restart.

## The web: `backtide web`

The web view is read-only unless you switch things on. Each switch is a flag of `backtide web`, and each needs a running `backtide vigilar` and either the same user as the service or, with `--socket-web`, the service's narrow socket for the web's group. The installed web uses the second way: it runs as `backtide-web` and has the three switches on ([command-line reference](cli-reference.md#backtide-web)).

| Flag | Default | Switches on |
|---|---|---|
| `--rebobinar` | off | Rewind from the Snapshots page (with the notice and a confirmation) |
| `--aprobar` | off | Approve, reject and trust from the Requests page (each behind a confirmation) |
| `--ajustes` | off | Changes on the Settings page |
| `--puerto N` | `8765` | The port, on `127.0.0.1` only (`0`: a free one) |

All details of the command are in the [command-line reference](cli-reference.md#backtide-web). The web only listens on `127.0.0.1`; it is never exposed to the network. As root it refuses to start unless a flag is given.

### The Settings page

Open it from the web's navigation ("Settings", or "Ajustes" in Spanish; the page language follows your browser, or add `?lang=en`). Start the web with `--ajustes` to change anything. It has one row for each of these:

| Row | What it sets | Where it ends up | When it applies |
|---|---|---|---|
| Anthropic key | The real key of the provider named `anthropic` | `keys/anthropic.key` | At once, no restart |
| OpenAI key | The real key of the provider named `openai` | `keys/openai.key` | At once |
| Ollama cloud key | The real key of the provider named `ollama-cloud` | `keys/ollama-cloud.key` | At once |
| Telegram bot | The token and your chat id | `telegram.toml` | When the service restarts |
| Spending cap | The daily and monthly caps, in dollars | `budget.json` | On the next model call |
| New prices | Accept new models or large price drops found on the provider's page | `prices.json` | When you accept them |

How the key rows work:

- **Keys are write-only.** The page never shows a key. For each one you see whether it is set, when it changed and, for values of 16 characters or more, its **last four characters**. That is all.
- Each change opens a confirmation page with a one-time voucher. The checks include the request's origin and a CSRF token. The black box records "secret set" or "secret cleared" with the kind and who asked, nothing about the value.
- What the page accepts: an Anthropic key shaped like `sk-ant-…` (not an `sk-ant-oat…` login token), an OpenAI key shaped like `sk-…`, an Ollama key of 20 to 240 letters, digits, dots, dashes and underscores, a Telegram token `<digits>:<30 to 64 characters>`, and a chat id that is a positive number. Anything else is refused with a fixed message that never repeats your input. One of backtide's own fake keys is refused too.
- A key row works only if `[[proxy.providers]]` has a provider with exactly that name. Otherwise the page says no provider uses it.
- Removing a key makes the provider *wait* again: the agent's model calls are refused until you set one.
- The files are written atomically, in a folder only the service's user can enter. The service writes them itself, with no `sudo`.

### Doing the same by hand

```sh
umask 077
printf '%s\n' "<your real key>" > <state_dir>/keys/anthropic.key     # then:
chmod 600 <state_dir>/keys/anthropic.key
```

A hand-written key file is read only once it has stopped changing for about half a second and was identical on two reads: this guards against half-written keys. If the service says a key "changed while it was read", write it with `mv` from a temporary file, or use the Settings page. **Never put a key in `backtide.toml`, in a chat, or in an issue.**

## What you can safely change

| Safe | Notes |
|---|---|
| `cycle_interval`, `prune_interval` | Only affect how often it checks and cleans |
| Spending caps and `timezone` | Lower caps are safer. Change them with `backtide tope` |
| `[agent]` `memory`, `cpus`, `pids_limit`, `tmp_size`, `stop_timeout`, `ready_timeout` | Resources only. Too small and the agent will be killed or will not start |
| `[gate]` `hold_s`, `wait_s`, `preapproval_s` | Only shorter is allowed |
| `[gate] unknown_hosts = "deny"` | Stricter. Expect more refusals |
| `[sensor] required = true` | Stricter |
| `rules.toml` | Adding rules is safe. **Removing** rules means events you used to rate are no longer rated |

| Widens what can leave, so think first | Why |
|---|---|
| `[proxy] allow_hosts` | The agent may read from, and open WebSockets to, those hosts without questions |
| `[proxy] allow_provider_tools` | Lets a model call carry provider-side tools that can reach anywhere |
| `[gate] trusted`, `trust_owner_chat` | Sends to those recipients pass unasked |
| `[gate] read_budget_*_kib` (raising), `read_endpoints` | More data can leave inside read requests |
| `[budget]` caps (raising), `[budget.prices]` set too low | Spending can go higher; a price that is too low makes the count too low |
| `workspace_limit` removed | Switches off the quota and the pause by space |

| Not configurable, on purpose | |
|---|---|
| Anything of the agent's container that decides security | Refused by name in `[agent]` |
| Mounting the state folder, the black box, the snapshots or the Docker socket into the agent | The service refuses to start the agent if its container would see any of them |
| Ports, DNS, extra network routes, capabilities | None are settable |
| The proxy's allowed ports and its request rates | Fixed in code |
| Secrets in `backtide.toml` | Refused |
| Snapshot retention and the space-pause thresholds | Fixed in code |

If you are not sure that a change is safe, leave the default and ask in an issue.

## Environment variables

backtide reads **no environment variable for its settings**. The ones it looks at, and why:

| Variable | Used by | Why |
|---|---|---|
| `TZ` | the service | Finds the machine's time zone when `[budget] timezone` is `"local"` |
| `TERM` | `backtide entrar` | Passed to the agent's terminal if it looks like a normal terminal name |

The `docker` commands backtide runs inherit your environment. The `make` targets take their own variables (`MODEL`, `PERFIL`, `LOCAL`, `ID`, `SI`, `RUTA`…): they are listed in the [command-line reference](cli-reference.md#make-commands).

## A complete example

This is a full config with the main sections, every key at its default or at a value you would plausibly choose. It parses with the real config reader (checked with placeholder paths). Adjust the paths, and put the keys in the state folder as described above.

```toml
state_dir = "/var/lib/backtide"
volume    = "/srv/backtide/volume"
workspace_limit = 2147483648      # 2 GiB
cycle_interval  = 120
prune_interval  = 600

[agent]
profile = "openclaw"
memory = "2g"
cpus = "2"

[proxy]
allow_hosts = []                  # e.g. ["api.github.com"]
allow_provider_tools = []

[[proxy.providers]]
name = "anthropic"
kind = "anthropic"
models = ["claude-sonnet-5-5", "claude-haiku-4-5"]

[gate]
unknown_hosts = "hold"
trust_owner_chat = true
hold_s = 300
wait_s = 90
preapproval_s = 600
read_budget_host_kib = 256
read_budget_total_kib = 2048
trusted = []

[budget]
daily_usd = 5
monthly_usd = 50
timezone = "local"
auto_prices = true

[sensor]
required = false
```

Before starting `backtide vigilar` with it, create the state folder (`chmod 700`), put `gateway.token` in it (for OpenClaw), and set the Anthropic key from the Settings page. The ready-made way to see a working config is to run `make probar` and read the file it writes, `~/backtide-demo-run/backtide.toml`, in the VM. The step-by-step guide is [real run](real-run.md) (in Spanish: docs/probar.md (internal note)).
