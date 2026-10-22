"""T17a-1: what the Claude Code profile (docs/34) assumes, checked in the VM with the pinned image
of decision 10 (``docker/sandbox-templates:claude-code`` by digest).

Each test pins one behaviour of that image, of Claude Code or of the jail that T17a-3 and T17a-4
build on, or records a figure for docs/34 ("Resultados de T17a-1"). Behaviours the design relies
on are asserted, so a new digest (a new Claude Code) that changes them stops the work. Figures go
through ``report`` (shown with ``pytest -rP``, kept in the JUnit XML).

The lab (``lab``, one per module), all of it on one ``--internal`` network with an isolated
gateway, so nothing in it can reach the internet, the VM or the Mac (invariant 8):

- ``agent``: the pinned image in backtide's real jail (AgentJail, docker_create_argv and the
  checks of verify.py and mounts.py), through a throwaway AgentProfile in the ``shell`` mode of
  docs/34 section 7 (``tini -- sleep infinity``; Claude Code runs with ``docker exec``). Its
  workspace is a SnapshotStore on the test btrfs, so it can be rewound. Like every VM test it
  runs as the Lima user (``allow_shared_ids``); ``test_p1_runs_as_the_jail_uid`` runs it once as
  61000:61000, the jail's own ids.
- ``proxy``: the pinned mitmproxy as the Lima user, read-only, without capabilities, under the
  alias ``backtide-proxy``, with the CA made by ca.py. Its addon (``ADDON`` below) answers
  EVERY request itself in the request hook, so it never opens a connection anywhere: it is the
  fake internet and the fake model at once. It logs method, host, path, header NAMES and
  whether a credential header holds the fake key, never a value. For api.anthropic.com it runs
  backtide's own provider_tools.py (copied next to it): a path that is not a model call
  (``provider_endpoint``) or a model call the filter refuses (``provider_side_tool``) gets the
  gate's 403, with the profile's ``param:diagnostics`` allowed unless a test says otherwise.

The only key is a fake one made here (``new_fake_key``); no real model API and no real service
is ever called. Containers and networks are named like conftest.py's test agents, so the cleanup
of a killed run's leftovers covers them too.
"""

import fcntl
import json
import os
import re
import shutil
import struct
import subprocess
import termios
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

import pytest

from backtide.gate import provider_tools
from backtide.gate.provider_tools import check_request, endpoint_of
from backtide.gate.providers import new_fake_key
from backtide.jail import ca, proxy_config
from backtide.jail import docker as jail_docker
from backtide.jail.agent import AgentJail
from backtide.jail.config import (
    NO_PROXY_HOSTS,
    AgentJailConfig,
    ModelProvider,
    container_env,
    create_env,
    docker_create_argv,
    token_env,
)
from backtide.jail.profile import AgentProfile, is_reserved_env
from backtide.snapshots.model import Reason
from backtide.snapshots.store import SnapshotStore

pytestmark = pytest.mark.integration

# docker/sandbox-templates:claude-code, the multi-arch index pulled on 2026-10-22 (decision 10 of
# docs/34). Built on 2026-10-21 from ubuntu:questing (26.04); its arm64 image is ARM64_MANIFEST.
# Bump the digest, CLAUDE_CODE_VERSION and docs/34 together, after running this file.
CC_REPO = "docker/sandbox-templates"
CC_DIGEST = "sha256:30ec2b1bb76e3993aff912c553a5c249ad95b595249a32fde7158eafb71bda25"
CC_IMAGE = f"{CC_REPO}@{CC_DIGEST}"
# The arm64 manifest, for docs/34 (docker keeps only the index's digest in RepoDigests).
ARM64_MANIFEST = "sha256:2eb0c9d28da36c38880cbef2f2ba1b19ba7625f4bdbe4a31029c3691f5d62536"
CLAUDE_CODE_VERSION = "2.1.306"
CLAUDE = "/home/agent/.local/bin/claude"  # a link to ~agent/.local/share/claude/versions/<v>
IMAGE_ENV_FILE = "/etc/sandbox-persistent.sh"  # the image's BASH_ENV and CLAUDE_ENV_FILE

CONTAINER_PREFIX = "backtide-test-agent-"  # conftest.TEST_CONTAINER_PREFIX
NETWORK_PREFIX = "backtide-test-net-"  # conftest.TEST_NETWORK_PREFIX
PROXY_ALIAS = "backtide-proxy"
JAIL_UID = 61000  # backtide/jail/config.py AGENT_UID and AGENT_GID

SETTINGS_FILE = "claude.json"  # in /config: the settings backtide gives Claude Code (decision 7)
SETTINGS = f"/config/{SETTINGS_FILE}"
# The variables of the Claude Code profile (docs/34, section 7). Not NPM_CONFIG_AUDIT any more:
# npm_config_* is a reserved family since the security review of the profiles, and T17a-4
# decides how npm's audit is turned off (docs/34, section 11).
PROFILE_ENV = (
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
    ("CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL", "1"),
)
CA_ENV = ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
CA_ENV_ALL = (*CA_ENV, "GIT_SSL_CAINFO")
# What P4 found left with CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 (docs/34): two reads.
ESSENTIAL_PATHS = frozenset({"/api/claude_code/settings", "/api/claude_code/policy_limits"})
MODEL_PATHS = ("/v1/messages", "/v1/messages/count_tokens")
# What docker diff may show of a jail with a read-only root: its mount points and their parents.
MOUNT_POINTS = frozenset(
    {"/config", "/etc", "/etc/backtide-ca", "/workspace", "/workspace/work", "/sys"}
)

PULL_TIMEOUT = 1800.0  # about 750 MB compressed for arm64
READY_TIMEOUT = 60.0
RUN_TIMEOUT = 180.0

# The fake internet and the fake model, as a mitmproxy addon. It never connects upstream: every
# request gets its answer in the request hook (and connection_strategy=lazy keeps mitmproxy from
# connecting before). For api.anthropic.com it applies backtide's own provider_tools.py, copied
# next to it, with the fields allowed in /data/allowed.json: a path that is not a model call, or
# a model call the filter refuses, gets the gate's 403. The model's answer follows a marker in
# the prompt (``t17:...``): a short plan of tool calls, then "listo".
ADDON = r"""
import json
import os
import re
import sys
import time

from mitmproxy import http

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import provider_tools  # backtide/gate/provider_tools.py, copied by the test

LOG = "/data/log.jsonl"
BODIES = "/data/bodies"
ALLOWED = "/data/allowed.json"
FAKE = os.environ["FAKE_ANTHROPIC"]
MARK = re.compile(r"t17:[a-z]+(?: [a-z0-9]+)?")
CRED = ("x-api-key", "authorization", "proxy-authorization", "cookie")
PAGE = (
    "<html><head><title>Fake docs</title></head><body><h1>Fake docs</h1>"
    "<p>t17 page body: nothing real here.</p></body></html>"
)
BASH = (
    "python3 -c 'print(40 + 2)' && curl -sS https://api.example.com/v1/ping; echo; "
    "printf 'bash-env=%s\\n' \"${BASH_ENV-unset}\"; echo fin"
)
REFUSED = {
    "provider_endpoint": "backtide: only the provider's model endpoints are allowed\n",
    "provider_body": "backtide: a model request must be the provider's JSON\n",
    "provider_side_tool": (
        "backtide: tools that run on the provider's side are not allowed (allow_provider_tools)\n"
    ),
}
_count = {"n": 0}


def _log(rec):
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


def tls_failed_client(data):
    _log({"ev": "tls_failed", "sni": data.context.client.sni, "t": round(time.time(), 3)})


def _texts(content):
    if isinstance(content, str):
        return [content]
    out = []
    for block in content if isinstance(content, list) else []:
        if isinstance(block, dict) and block.get("type") == "text":
            if isinstance(block.get("text"), str):
                out.append(block["text"])
    return out


def _results(content):
    out = []
    for block in content if isinstance(content, list) else []:
        if isinstance(block, dict) and block.get("type") == "tool_result":
            inner = block.get("content")
            text = inner if isinstance(inner, str) else " ".join(_texts(inner))
            out.append(text[:600])
    return out


def _plan(mark):
    if mark.startswith("t17:write "):
        word = mark.split(" ", 1)[1]
        command = f"printf '%s\\n' {word} >> /workspace/work/notes.txt"
        return [("Bash", {"command": command, "description": "t17 note"})]
    if mark == "t17:bash":
        return [("Bash", {"command": BASH, "description": "t17 check"})]
    if mark == "t17:webfetch":
        return [
            ("ToolSearch", {"query": "select:WebFetch", "max_results": 1}),
            ("WebFetch", {"url": "https://docs.example.com/page", "prompt": "Resume la pagina"}),
        ]
    if mark == "t17:websearch":
        return [
            ("ToolSearch", {"query": "select:WebSearch", "max_results": 1}),
            ("WebSearch", {"query": "t17 fake search"}),
        ]
    return []


def _sse(events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def _answer(body, tool, tool_input, text):
    model = body.get("model", "claude-fake")
    usage = {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 0,
             "cache_creation_input_tokens": 0}
    if tool:
        block = {"type": "tool_use", "id": "toolu_fake%05d" % _count["n"], "name": tool,
                 "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(tool_input)}
        stop = "tool_use"
        full = {**block, "input": tool_input}
    else:
        block = {"type": "text", "text": ""}
        delta = {"type": "text_delta", "text": text}
        stop = "end_turn"
        full = {"type": "text", "text": text}
    if not body.get("stream"):
        msg = {"id": "msg_fake", "type": "message", "role": "assistant", "model": model,
               "content": [full], "stop_reason": stop, "stop_sequence": None, "usage": usage}
        return http.Response.make(200, json.dumps(msg).encode(),
                                  {"content-type": "application/json"})
    events = [
        {"type": "message_start", "message": {
            "id": "msg_fake", "type": "message", "role": "assistant", "model": model,
            "content": [], "stop_reason": None, "stop_sequence": None, "usage": usage}},
        {"type": "content_block_start", "index": 0, "content_block": block},
        {"type": "content_block_delta", "index": 0, "delta": delta},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
         "usage": {"output_tokens": 5}},
        {"type": "message_stop"},
    ]
    return http.Response.make(200, _sse(events), {"content-type": "text/event-stream"})


def _key(value):
    return json.dumps(value, sort_keys=True)


def _model(body, rec):
    # Claude Code merges consecutive messages of one role, and puts a new prompt after the
    # tool results in the same user message: a step of the plan is done when a tool_use with
    # the same name and input is anywhere in the conversation.
    tools = [t.get("name") for t in body.get("tools") or [] if isinstance(t, dict)]
    messages = [m for m in body.get("messages") or [] if isinstance(m, dict)]
    every = []
    for m in messages:
        if m.get("role") == "user":
            every += MARK.findall(" ".join(_texts(m.get("content"))))
    mark = every[-1] if every else ""
    rec["user_markers"] = every
    rec["marker"] = mark
    plan = _plan(mark)
    calls = {}
    for m in messages:
        if m.get("role") == "assistant" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    calls[b.get("id")] = (b.get("name"), _key(b.get("input")))
    done = set(calls.values())
    mine = {i for i, call in calls.items() if any(call == (t, _key(x)) for t, x in plan)}
    results = []
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    if b.get("tool_use_id") in mine:
                        results += _results([b])
    rec["results"] = results
    for tool, tool_input in plan:
        if (tool, _key(tool_input)) in done:
            continue
        if tool == "ToolSearch" and tool_input["query"].split(":")[1] in tools:
            continue
        if tool not in tools:
            rec["missing_tool"] = tool
            break
        rec["answer"] = tool
        return _answer(body, tool, tool_input, "")
    rec["answer"] = "text"
    return _answer(body, None, None, "listo")


def request(flow):
    req = flow.request
    _count["n"] += 1
    n = _count["n"]
    host = req.pretty_host
    path = req.path.split("?")[0]
    cred = {}
    for name in CRED:
        value = req.headers.get(name)
        if value is not None:
            cred[name] = "fake" if FAKE in value else "other"
    rec = {
        "ev": "req", "n": n, "t": round(time.time(), 3), "method": req.method, "host": host,
        "path": path, "query_keys": sorted(req.query.keys()),
        "headers": sorted({k.lower() for k in req.headers.keys()}), "cred": cred,
        "size": len(req.raw_content or b""), "ua": req.headers.get("user-agent", "")[:60],
    }
    body = None
    if req.raw_content and "json" in req.headers.get("content-type", ""):
        try:
            body = json.loads(req.get_text())
        except ValueError:
            body = None
    if isinstance(body, dict):
        tools = [t for t in body.get("tools") or [] if isinstance(t, dict)]
        rec["tool_names"] = [t.get("name") for t in tools][:80]
        rec["tool_types"] = sorted({t.get("type", "<none>") for t in tools})
        rec["n_messages"] = len(body.get("messages") or [])
    if host == "api.anthropic.com":
        headers = [(k, v) for k, v in req.headers.items(multi=True)]
        endpoint = provider_tools.endpoint_of("anthropic", req.method, req.path, headers)
        rec["endpoint"] = endpoint
        reason, refused = "provider_endpoint", ()
        if endpoint is not None:
            with open(ALLOWED) as f:
                allowed = json.load(f)
            verdict = provider_tools.check_request(
                "anthropic", req.method, req.path, headers, req.content, allowed=allowed
            )
            reason, refused = verdict.reason, verdict.tools
        rec["verdict"] = reason
        rec["refused"] = list(refused) if reason else []
        if endpoint == "messages":
            os.makedirs(BODIES, exist_ok=True)
            kept = [[k, "<credential>" if k.lower() in CRED else v] for k, v in headers]
            with open(f"{BODIES}/{n:05d}.json", "w") as f:
                json.dump({"path": req.path, "headers": kept, "body": req.get_text()}, f)
        if reason is not None:
            flow.response = http.Response.make(403, REFUSED[reason].encode(),
                                               {"content-type": "text/plain"})
        elif endpoint == "messages":
            flow.response = _model(body if isinstance(body, dict) else {}, rec)
        elif endpoint == "count_tokens":
            flow.response = http.Response.make(200, b'{"input_tokens": 10}',
                                               {"content-type": "application/json"})
        else:
            flow.response = http.Response.make(404, b"fake internet\n",
                                               {"content-type": "text/plain"})
    elif host == "docs.example.com" and req.method == "GET":
        flow.response = http.Response.make(200, PAGE.encode(),
                                           {"content-type": "text/html; charset=utf-8"})
    elif host == "api.example.com" and path == "/v1/ping":
        flow.response = http.Response.make(200, b"pong", {"content-type": "text/plain"})
    else:
        flow.response = http.Response.make(404, b"fake internet\n", {"content-type": "text/plain"})
    _log(rec)
"""


def report(record_property: Callable[[str, object], None], name: str, outcome: object) -> None:
    """Shown with ``pytest -rP``, and kept in the JUnit XML, for docs/34."""
    print(f"{name}: {outcome}")  # noqa: T201
    record_property(name, str(outcome))


def unique(prefix: str) -> str:
    return f"{prefix}{os.getpid()}-{uuid4().hex[:12]}"


def docker(*args: str, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    return jail_docker.run(list(args), timeout=timeout, check=check)


# The lab


@dataclass
class Run:
    """One run of Claude Code inside the jail and what the fake internet saw meanwhile."""

    returncode: int
    stdout: str
    stderr: str
    seconds: float
    records: list[dict[str, Any]]
    written: dict[str, int] = field(default_factory=dict)  # new under /workspace, with sizes

    @property
    def requests(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r["ev"] == "req"]

    @property
    def model_calls(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if is_model_call(r)]

    @property
    def others(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if not is_model_call(r)]

    def result(self) -> dict[str, Any]:
        return json.loads(self.stdout)

    def shape(self) -> list[str]:
        """Each request that is not a model call, as ``METHOD host/path xN``."""
        counts: dict[str, int] = {}
        for r in self.others:
            key = f"{r['method']} {r['host']}{r['path']}"
            counts[key] = counts.get(key, 0) + 1
        return [f"{key} x{n}" for key, n in sorted(counts.items())]


@dataclass
class Lab:
    root: Path
    jail: AgentJail
    store: SnapshotStore
    proxy: str
    data: Path
    proxy_ca: Path
    fake_key: str = field(repr=False)
    first: "Run | None" = None  # the first claude -p, on a fresh HOME (first_run)

    @property
    def user(self) -> str:
        return f"{self.jail.config.uid}:{self.jail.config.gid}"

    @property
    def home(self) -> Path:
        return self.jail.config.agent_dir / "home"

    @property
    def work(self) -> Path:
        return self.jail.config.agent_dir / "work"

    def mark(self) -> int:
        log = self.data / "log.jsonl"
        return len(log.read_text().splitlines()) if log.exists() else 0

    def since(self, mark: int) -> list[dict[str, Any]]:
        lines = (self.data / "log.jsonl").read_text().splitlines()
        return [json.loads(line) for line in lines[mark:]]

    def allow(self, fields: tuple[str, ...]) -> None:
        """The provider fields the fake gate allows from now on (the profile's by default)."""
        (self.data / "allowed.json").write_text(json.dumps(list(fields)))

    def exec(self, *argv: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return docker("exec", "--user", self.user, self.jail.config.name, *argv, timeout=timeout,
                      check=False)  # fmt: skip

    def claude(
        self,
        prompt: str,
        *args: str,
        unset: tuple[str, ...] = (),
        settings: bool = True,
        timeout: float = RUN_TIMEOUT,
    ) -> Run:
        """``claude -p`` inside the running jail, with the profile's settings file unless
        ``settings`` is False, and without the variables of ``unset``."""
        prefix = ["env", *(item for name in unset for item in ("-u", name))] if unset else []
        argv = [
            *prefix, CLAUDE, "-p", prompt, "--output-format", "json",
            "--dangerously-skip-permissions", *(["--settings", SETTINGS] if settings else []),
            *args,
        ]  # fmt: skip
        mark = self.mark()
        start = time.monotonic()
        done = self.exec(*argv, timeout=timeout)
        seconds = time.monotonic() - start
        return Run(done.returncode, done.stdout, done.stderr, seconds, self.since(mark))


def is_model_call(record: dict[str, Any]) -> bool:
    return (
        record.get("ev") == "req"
        and record["host"] == "api.anthropic.com"
        and record["method"] == "POST"
        and record["path"] in MODEL_PATHS
    )


def _settings(config: AgentJailConfig) -> Mapping[str, str]:
    del config
    settings = {"skipWebFetchPreflight": True, "skipDangerousModePermissionPrompt": True}
    return {SETTINGS_FILE: json.dumps(settings, indent=2) + "\n"}


def lab_profile() -> AgentProfile:
    """The Claude Code profile as docs/34 sections 7 and 8 draw it, for this lab only (T17a-4
    writes the real one): shell mode, the fake key in ANTHROPIC_API_KEY, the settings in
    /config, the provider field ``diagnostics`` allowed (P5)."""
    return AgentProfile(
        name="claude-code-lab",
        version=CLAUDE_CODE_VERSION,
        image=CC_IMAGE,
        entrypoint="tini",
        command=("--", "sleep", "infinity"),
        workdir=PurePosixPath("/workspace/work"),
        env=PROFILE_ENV,
        fake_key_env=(("ANTHROPIC_API_KEY", "anthropic"),),
        config_names=(SETTINGS_FILE,),
        render_config=_settings,
        ready_probe=("/bin/true",),
        provider_params=("param:diagnostics",),
    )


def _require_image(image: str) -> None:
    if docker("image", "inspect", image, check=False).returncode == 0:
        return
    docker("pull", "--quiet", image, timeout=PULL_TIMEOUT)


def _start_proxy(name: str, network: str, root: Path, proxy_ca: Path, fake_key: str) -> Path:
    """The fake internet, under the proxy's alias on the agent's network. Returns its data
    folder (log.jsonl and the model calls' bodies)."""
    addon = root / "addon"
    data = root / "data"
    addon.mkdir()
    data.mkdir()
    (addon / "fake_internet.py").write_text(ADDON)
    shutil.copyfile(provider_tools.__file__, addon / "provider_tools.py")
    (data / "log.jsonl").touch()
    (data / "allowed.json").write_text(json.dumps(list(lab_profile().provider_params)))
    argv = [
        "run", "--detach", "--name", name, "--network", network, "--network-alias", PROXY_ALIAS,
        "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",  # noqa: S108 - in the container
        # The image's VOLUME, covered so Docker adds no anonymous volume (proxy_config.py).
        "--tmpfs", "/home/mitmproxy/.mitmproxy:ro,nosuid,nodev,noexec,size=4k,mode=0555",
        "--env", "HOME=/tmp",
        "--env", "PYTHONUNBUFFERED=1", "--env", "FAKE_ANTHROPIC",
        "--volume", f"{addon}:/addon:ro,z", "--volume", f"{proxy_ca}:/ca:ro,z",
        "--volume", f"{data}:/data:z",
        "--entrypoint", "mitmdump", proxy_config.IMAGE,
        "--set", "confdir=/ca", "-s", "/addon/fake_internet.py", "--listen-port", "8080",
        "--set", "connection_strategy=lazy", "--set", "flow_detail=0",
    ]  # fmt: skip
    jail_docker.run(argv, env={"FAKE_ANTHROPIC": fake_key})
    deadline = time.monotonic() + READY_TIMEOUT
    while "listening at" not in docker("logs", name).stdout + docker("logs", name).stderr:
        if time.monotonic() > deadline:
            raise AssertionError(f"the fake internet did not start: {docker('logs', name).stderr}")
        time.sleep(0.5)
    return data


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    _require_image(CC_IMAGE)
    _require_image(proxy_config.IMAGE)
    root = tmp_path_factory.mktemp("t17a1")
    store_root = btrfs_volume / f"t17a1-{uuid4().hex}"
    store_root.mkdir(mode=0o700)
    store = SnapshotStore(store_root)
    store.init()
    proxy_ca = root / "proxy-ca"
    agent_ca = root / "agent-ca"
    ca.ensure_ca(ca.CaPaths(proxy_dir=proxy_ca, agent_dir=agent_ca, gid=os.getgid()))
    fake_key = new_fake_key("anthropic")
    config = AgentJailConfig(
        workspace=store.workspace,
        config_dir=root / "config",
        ca_dir=agent_ca,
        model_providers=(ModelProvider("anthropic", "anthropic", "api.anthropic.com", fake_key),),
        name=unique(CONTAINER_PREFIX),
        network=unique(NETWORK_PREFIX),
        uid=os.getuid(),
        gid=os.getgid(),
        allow_shared_ids=True,
        memory="2g",
        cpus="2",
        profile=lab_profile(),
    )
    jail = AgentJail(config)
    proxy = unique(CONTAINER_PREFIX)
    try:
        jail.ensure_network()
        data = _start_proxy(proxy, config.network, root, proxy_ca, fake_key)
        jail.prepare_workspace()
        jail.write_config()
        jail.create()
        jail.start()
        jail.wait_ready(timeout=READY_TIMEOUT)
        built = Lab(root, jail, store, proxy, data, proxy_ca, fake_key)
        before = files_under(config.agent_dir)
        built.first = built.claude("t17:bash")
        after = files_under(config.agent_dir)
        built.first.written = {path: size for path, size in after.items() if path not in before}
        yield built
    finally:
        errors = []
        for step in (
            jail.remove,
            lambda: docker("rm", "--force", "--volumes", proxy, check=False),
            jail.remove_network,
        ):
            try:
                step()
            except Exception as error:  # noqa: BLE001 - every step is attempted
                errors.append(error)
        if errors:
            raise errors[0]


@pytest.fixture(scope="module")
def first_run(lab: Lab) -> Run:
    """The profile's ``claude -p`` with a Bash tool call, run by ``lab`` on a fresh HOME before
    any test: P1, P3, P4 and P5 read it."""
    assert lab.first is not None
    return lab.first


def files_under(folder: Path) -> dict[str, int]:
    """Every file and folder under ``folder``, relative, with its size (0 for a folder)."""
    found = {}
    for path in folder.rglob("*"):
        rel = str(path.relative_to(folder))
        found[rel] = 0 if path.is_dir() else path.stat().st_size
    return found


# The image (decision 10; docs/34, sections 6 and 10, R2 and R3)


def test_the_image_is_the_pinned_one_and_has_what_the_jail_needs(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    image = json.loads(docker("image", "inspect", CC_IMAGE).stdout)[0]
    assert f"{CC_REPO}@{CC_DIGEST}" in image["RepoDigests"]
    assert image["Architecture"] == "arm64"
    cfg = image["Config"]
    assert cfg["User"] == "agent"  # ignored: the jail always sets its own uid
    assert cfg["Entrypoint"] == ["tini", "--"]
    report(record_property, "image", f"{image['Size']} bytes, created {image['Created']}")
    report(record_property, "image config", {k: cfg.get(k) for k in ("User", "Cmd", "WorkingDir")})
    # The sensor's liveness probe, the battery's interpreter and curl (docs/34, section 6).
    for argv in (["/bin/true"], ["/usr/bin/true"], ["python3", "-c", "print(1)"]):
        assert lab.exec(*argv).returncode == 0, argv
    curl = lab.exec("curl", "--version")
    assert curl.returncode == 0
    version = lab.exec(CLAUDE, "--version")
    assert version.returncode == 0
    assert version.stdout.strip() == f"{CLAUDE_CODE_VERSION} (Claude Code)"
    tools = lab.exec("sh", "-c", "python3 --version; git --version; node --version; uname -m")
    report(record_property, "tools", " | ".join(tools.stdout.split("\n")) + curl.stdout[:40])


def test_the_image_user_and_its_sudo_mean_nothing_in_the_jail(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """The image gives its user ``agent`` (1000) sudo without a password. The jail's uid is not
    that user, the root is read-only and no_new_privileges stops setuid: sudo cannot work."""
    ids = lab.exec("id")
    assert ids.returncode == 0
    assert "uid=0" not in ids.stdout
    assert f"uid={lab.jail.config.uid}" in ids.stdout
    sudo = lab.exec("sudo", "-n", "true")
    assert sudo.returncode != 0
    report(record_property, "sudo -n true", f"exit {sudo.returncode}: {sudo.stderr.strip()[:160]}")
    for path in ("/etc/sandbox-persistent.sh", "/home/agent/.bashrc", "/usr/local/bin/x"):
        write = lab.exec("sh", "-c", f"echo x >> {path}")
        assert write.returncode != 0, path
    report(record_property, "id in the jail", ids.stdout.strip())


def test_the_jail_variables_override_the_image_ones(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """HOME and NO_PROXY are the jail's, not the image's. The image sets BASH_ENV and
    CLAUDE_ENV_FILE to a file of its own; since T17a-3 the jail sets both to /dev/null for every
    profile (and verify.py checks the final values), so the image's do not survive."""
    image_env = dict(
        e.split("=", 1)
        for e in json.loads(docker("image", "inspect", CC_IMAGE).stdout)[0]["Config"]["Env"]
    )
    assert image_env["NO_PROXY"] == "localhost,127.0.0.1,::1,172.17.0.0/16"
    assert image_env["BASH_ENV"] == IMAGE_ENV_FILE
    assert image_env["CLAUDE_ENV_FILE"] == IMAGE_ENV_FILE
    info = json.loads(docker("inspect", lab.jail.config.name).stdout)[0]
    env = dict(e.split("=", 1) for e in info["Config"]["Env"])
    assert env["HOME"] == "/workspace/home"
    assert env["NO_PROXY"] == env["no_proxy"] == NO_PROXY_HOSTS
    assert env["PATH"] == image_env["PATH"]  # the jail leaves PATH: `claude` is found by it
    for name, value in container_env(lab.jail.config):
        assert env[name] == value, name
    assert env["ANTHROPIC_API_KEY"] == lab.fake_key
    assert set(token_env(lab.jail.config)) == {"ANTHROPIC_API_KEY"}
    survivors = sorted(
        n for n in image_env if n in env and n not in dict(container_env(lab.jail.config))
    )
    report(record_property, "image variables left as they are", survivors)
    # The two that matter: reserved for a profile, and set by the jail itself.
    assert is_reserved_env("BASH_ENV") and is_reserved_env("CLAUDE_ENV_FILE")
    assert env["BASH_ENV"] == env["CLAUDE_ENV_FILE"] == "/dev/null"
    # A login shell still re-exports the image's file; it is empty and on the read-only root.
    size = lab.exec("stat", "-c", "%s %U %a", IMAGE_ENV_FILE)
    report(record_property, f"{IMAGE_ENV_FILE}", size.stdout.strip())
    assert size.stdout.split()[0] == "0"


def test_blank_bash_env_and_claude_env_file_keep_claude_working(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """What blanking them would do (docker exec's --env is the same as --env at create):
    Claude Code and its Bash tool still work, but the Bash tool runs a login shell, and the
    image's /etc/profile.d/sandbox-persistent.sh (and /etc/bash.bashrc) export BASH_ENV again.
    So a variable cannot take it away: what keeps it harmless is that the file it names is
    part of the pinned image, on the read-only root."""
    mark = lab.mark()
    done = docker(
        "exec", "--user", lab.user, "--env", "BASH_ENV=", "--env", "CLAUDE_ENV_FILE=",
        lab.jail.config.name, CLAUDE, "-p", "t17:bash", "--output-format", "json",
        "--dangerously-skip-permissions", "--settings", SETTINGS,
        timeout=RUN_TIMEOUT, check=False,
    )  # fmt: skip
    records = lab.since(mark)
    assert done.returncode == 0, done.stderr[-800:]
    assert json.loads(done.stdout)["result"] == "listo"
    results = [x for r in records if is_model_call(r) for x in r.get("results", [])]
    assert any(f"bash-env={IMAGE_ENV_FILE}" in x for x in results), results
    report(record_property, 'Bash tool output with BASH_ENV=""', results[:1])
    where = lab.exec("grep", "-l", "BASH_ENV=", "/etc/profile.d/sandbox-persistent.sh",
                     "/etc/bash.bashrc")  # fmt: skip
    report(record_property, "the image exports BASH_ENV in", where.stdout.split())


# P1: claude -p in the jail


def test_p1_headless_claude_runs_in_the_jail_and_writes_only_in_home(
    lab: Lab, first_run: Run, record_property: Callable[[str, object], None]
) -> None:
    run = first_run
    assert run.returncode == 0, run.stderr[-1500:]
    result = run.result()
    assert result["result"] == "listo"
    assert result["is_error"] is False
    report(record_property, "P1 claude -p", f"exit 0 in {run.seconds:.1f} s, "
           f"{len(run.model_calls)} model calls, {len(run.others)} other requests")  # fmt: skip
    new = sorted(run.written)
    outside = [p for p in new if not (p.startswith("home/") or p.startswith("work/"))]
    assert outside == []
    files = {p: size for p, size in run.written.items() if size}
    report(record_property, "P1 written in HOME", f"{len(new)} entries, {sum(files.values())} B")
    report(record_property, "P1 written in HOME (2 levels)", sorted({_top(p) for p in new}))
    report(record_property, "P1 written in work", [p for p in new if p.startswith("work/")])
    conversations = [
        p for p in new if p.startswith("home/.claude/projects/") and p.endswith(".jsonl")
    ]
    assert len(conversations) == 1
    assert not any(p.endswith(".credentials.json") for p in new)  # P11: no credential file
    assert ".claude" in {p.split("/")[1] for p in new} and "home/.claude.json" in new
    # The root is read-only: docker diff shows only the mount points and their parents.
    diff = [d for d in docker("diff", lab.jail.config.name).stdout.split("\n") if d]
    assert {d.split(" ", 1)[1] for d in diff} <= MOUNT_POINTS, diff
    report(record_property, "P1 docker diff", diff)
    tmp = lab.exec("sh", "-c", "find /tmp -maxdepth 3 | head -20")
    report(record_property, "P1 /tmp", tmp.stdout.split())
    # The Bash tool ran python3 and curl through the proxy, and saw the image's BASH_ENV.
    results = [x for r in run.model_calls for x in r.get("results", [])]
    assert any("42" in x and "pong" in x for x in results), results
    report(record_property, "P1 Bash tool output", results[:1])


def _top(path: str) -> str:
    return "/".join(path.split("/")[:3])


def test_p1_runs_as_the_jail_uid(lab: Lab, record_property: Callable[[str, object], None]) -> None:
    """The same jail as 61000:61000, the ids backtide gives the agent (not in the image's
    /etc/passwd, not the image's group 1000), with /workspace on a tmpfs of that uid: the VM
    tests cannot give a folder of the btrfs to another uid without root. Its /config is a copy
    readable by others: the lab's is 0750 with the Lima user's group (write_config), which
    61000 cannot open, and then Claude Code refuses to start ("Refusing to read a file whose
    path could not be vetted"). In production the group is the agent's gid."""
    config_dir = lab.root / "config-61000"
    config_dir.mkdir(mode=0o755, exist_ok=True)
    config_dir.chmod(0o755)
    settings = config_dir / SETTINGS_FILE
    settings.write_text((lab.jail.config.config_dir / SETTINGS_FILE).read_text())
    settings.chmod(0o644)
    config = AgentJailConfig(
        workspace=lab.jail.config.workspace,
        config_dir=config_dir,
        ca_dir=lab.jail.config.ca_dir,
        model_providers=lab.jail.config.model_providers,
        name=unique(CONTAINER_PREFIX),
        network=lab.jail.config.network,
        uid=JAIL_UID,
        gid=JAIL_UID,
        profile=lab_profile(),
    )
    argv = docker_create_argv(config)
    bind = argv.index(f"{config.agent_dir}:/workspace:z")
    argv[bind - 1 : bind + 1] = [
        "--tmpfs",
        f"/workspace:rw,nosuid,nodev,size=256m,uid={JAIL_UID},gid={JAIL_UID},mode=0700",
    ]
    try:
        jail_docker.run(argv, env=create_env(config))
        docker("start", config.name)
        user = f"{JAIL_UID}:{JAIL_UID}"
        docker("exec", "--user", user, config.name, "mkdir", "-p", "/workspace/home",
               "/workspace/work")  # fmt: skip
        mark = lab.mark()
        done = docker(
            "exec", "--user", user, config.name, CLAUDE, "-p", "t17:bash", "--output-format",
            "json", "--dangerously-skip-permissions", "--settings", SETTINGS,
            timeout=RUN_TIMEOUT, check=False,
        )  # fmt: skip
        assert done.returncode == 0, done.stderr[-800:]
        assert json.loads(done.stdout)["result"] == "listo"
        assert any(is_model_call(r) for r in lab.since(mark))
        ids = docker("exec", "--user", user, config.name, "id").stdout.strip()
        report(record_property, "P1 as the jail's uid", f"exit 0; {ids}")
    finally:
        docker("rm", "--force", "--volumes", config.name, check=False)


# P2: the proxy and the CA


@pytest.mark.parametrize(
    ("label", "unset"),
    [
        ("only SSL_CERT_FILE", ("NODE_EXTRA_CA_CERTS",)),
        ("only NODE_EXTRA_CA_CERTS", ("SSL_CERT_FILE",)),
    ],
)
def test_p2_one_ca_variable_is_enough(
    lab: Lab, label: str, unset: tuple[str, ...], record_property: Callable[[str, object], None]
) -> None:
    run = lab.claude("t17:hello", unset=unset)
    assert run.returncode == 0, run.stderr[-800:]
    assert run.result()["result"] == "listo"
    report(record_property, f"P2 {label}", f"exit 0 in {run.seconds:.1f} s")


def test_p2_without_our_ca_it_fails_closed(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    run = lab.claude("t17:hello", unset=CA_ENV_ALL)
    assert run.returncode != 0
    assert run.requests == []  # nothing reached any server
    failed = [r for r in run.records if r["ev"] == "tls_failed"]
    assert failed
    report(record_property, "P2 without the CA",
           f"exit {run.returncode} after {run.seconds:.1f} s, {len(failed)} TLS refusals, "
           f"0 requests; SNI {sorted({r['sni'] for r in failed})}")  # fmt: skip


# P3: the fake key


def test_p3_every_model_call_carries_only_the_fake_key_in_x_api_key(
    first_run: Run, record_property: Callable[[str, object], None]
) -> None:
    calls = first_run.model_calls
    assert calls
    for call in calls:
        assert call["cred"] == {"x-api-key": "fake"}, call["cred"]
    carrying = sorted({f"{r['host']}{r['path']}" for r in first_run.others if r["cred"]})
    report(record_property, "P3 model calls", f"{len(calls)}, each with x-api-key = the fake key "
           "and no other credential header")  # fmt: skip
    report(record_property, "P3 other requests with a credential", carrying)


# P4: what is not the model


def test_p4_with_the_profile_only_the_two_essential_reads_are_left(
    lab: Lab, first_run: Run, record_property: Callable[[str, object], None]
) -> None:
    run = lab.claude("t17:hello")
    assert run.returncode == 0
    for r in (*first_run.others, *run.others):
        if r["host"] == "api.anthropic.com":
            assert endpoint_of("anthropic", r["method"], r["path"]) is None  # the gate: 403
    hello = {r["path"] for r in run.others}
    assert {r["host"] for r in run.others} <= {"api.anthropic.com"}
    assert hello <= ESSENTIAL_PATHS, hello
    report(record_property, "P4 profile, hello", run.shape())
    report(record_property, "P4 profile, first run with Bash", first_run.shape())


def test_p4_by_default_it_calls_home_more_and_still_works(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    unset = ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",)
    run = lab.claude("t17:hello", unset=unset)
    assert run.returncode == 0, run.stderr[-800:]
    assert run.result()["result"] == "listo"
    extra = {r["path"] for r in run.others} - ESSENTIAL_PATHS
    assert extra  # the telemetry and the rest the profile turns off
    report(record_property, "P4 default", run.shape())
    report(record_property, "P4 default, hosts", sorted({r["host"] for r in run.others}))
    telemetry = sorted(p.name for p in (lab.home / ".claude").glob("telemetry/*"))
    report(record_property, "P4 default, telemetry kept on disk", telemetry)


# P5: the provider filter


def test_p5_the_model_calls_pass_the_filter_only_with_diagnostics_allowed(
    lab: Lab, first_run: Run, record_property: Callable[[str, object], None]
) -> None:
    numbers = {r["n"] for r in first_run.model_calls if r["path"] == "/v1/messages"}
    assert numbers
    refused: set[str] = set()
    found: set[str] = set()
    for n in sorted(numbers):
        saved = json.loads((lab.data / "bodies" / f"{n:05d}.json").read_text())
        headers = [(k, v) for k, v in saved["headers"]]
        body = saved["body"].encode()
        bare = check_request("anthropic", "POST", saved["path"], headers, body)
        allowed = check_request(
            "anthropic", "POST", saved["path"], headers, body,
            allowed=lab.jail.config.profile.provider_params,
        )  # fmt: skip
        assert allowed.reason is None, (n, allowed)
        if bare.reason is not None:
            assert bare.reason == "provider_side_tool"
            refused |= set(bare.tools)
        found |= set(allowed.tools)
    report(record_property, "P5 refused without the profile", sorted(refused))
    report(record_property, "P5 allowed by the profile", sorted(found))
    assert refused <= {"param:diagnostics"}
    # WebSearch is a provider-side tool: the gate would refuse every call that lists it.
    types = {t for r in first_run.model_calls for t in r.get("tool_types", [])}
    assert types <= {"<none>", "custom"}, types
    names = sorted({t for r in first_run.model_calls for t in r.get("tool_names") or []})
    report(record_property, "P5 tools sent", f"{len(names)}: {names}")
    assert all(r["verdict"] is None for r in first_run.model_calls)  # the live gate let them by


def test_p5_without_diagnostics_allowed_every_model_call_is_refused(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """The gate of today, without the profile's field: Claude Code cannot work at all."""
    lab.allow(())
    try:
        run = lab.claude("t17:hello")
    finally:
        lab.allow(lab.jail.config.profile.provider_params)
    assert run.returncode != 0
    calls = run.model_calls
    assert calls
    assert {r["verdict"] for r in calls} == {"provider_side_tool"}
    assert {name for r in calls for name in r["refused"]} == {"param:diagnostics"}
    report(record_property, "P5 without param:diagnostics",
           f"exit {run.returncode} after {run.seconds:.1f} s, {len(calls)} model calls, all "
           f"refused; result {run.stdout[-200:]!r}")  # fmt: skip


def test_websearch_is_refused_by_the_gate_and_the_session_goes_on(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """WebSearch is a deferred tool: the model loads it with ToolSearch, and then Claude Code
    runs the search as a call of its own with Anthropic's server-side web_search tool. The gate
    refuses that call (provider_side_tool); the conversation itself must go on."""
    run = lab.claude("t17:websearch")
    calls = run.model_calls
    refused = [r for r in calls if r["verdict"] is not None]
    shapes = [(r.get("answer"), r["verdict"], r["refused"], r.get("tool_types")) for r in calls]
    report(record_property, "WebSearch model calls", shapes)
    results = [x for r in calls for x in r.get("results", [])]
    report(record_property, "WebSearch tool result", results[-1:])
    assert run.returncode == 0, run.stderr[-800:]
    assert run.result()["result"] == "listo"
    assert refused, "no call with a server-side tool: WebSearch changed"
    assert {r["verdict"] for r in refused} == {"provider_side_tool"}


def test_websearch_denied_in_the_settings_is_not_even_offered(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """Plan B for the noise above: ``permissions.deny: ["WebSearch"]`` in the profile's settings
    (inline here; T17a-4 puts it in /config/claude.json)."""
    settings = json.dumps({"skipWebFetchPreflight": True, "permissions": {"deny": ["WebSearch"]}})
    run = lab.claude("t17:websearch", "--settings", settings, settings=False)
    assert run.returncode == 0, run.stderr[-800:]
    calls = run.model_calls
    offered = []
    for r in calls:
        saved = json.loads((lab.data / "bodies" / f"{r['n']:05d}.json").read_text())
        offered.append("WebSearch" in saved["body"])
    report(record_property, "WebSearch denied: model calls",
           [(r.get("answer"), r.get("missing_tool"), r["verdict"]) for r in calls])  # fmt: skip
    report(record_property, "WebSearch denied: named in each request", offered)
    assert all(r["verdict"] is None for r in calls)
    assert offered[0] is False  # not among the deferred tools of the first request
    assert all("WebSearch" not in (r.get("tool_names") or []) for r in calls)


# WebFetch and its preflight


@pytest.mark.parametrize("skip", [True, False], ids=["skip-preflight", "with-preflight"])
def test_webfetch_with_and_without_its_preflight(
    lab: Lab, skip: bool, record_property: Callable[[str, object], None]
) -> None:
    """WebFetch is a deferred tool (loaded with ToolSearch). Before it fetches a page it asks
    api.anthropic.com whether the domain is safe; the gate refuses that path, and then WebFetch
    gives up without fetching. ``skipWebFetchPreflight`` in the profile's settings skips it."""
    run = lab.claude("t17:webfetch", settings=skip)
    assert run.returncode == 0, run.stderr[-800:]
    assert run.result()["result"] == "listo"
    preflight = [r for r in run.others if r["path"] == "/api/web/domain_info"]
    page = [r for r in run.others if r["host"] == "docs.example.com"]
    final = run.model_calls[-1].get("results", [])
    label = "skipWebFetchPreflight" if skip else "default"
    report(record_property, f"WebFetch {label}, requests", run.shape())
    report(record_property, f"WebFetch {label}, its tool result", final[-1:])
    if skip:
        assert preflight == []
        assert len(page) == 1
    else:
        assert len(preflight) == 1, "no preflight seen: the default changed"
        assert preflight[0]["verdict"] == "provider_endpoint"
        assert page == []
        assert any("Unable to verify if domain" in x for x in final), final


# Interactive Claude Code and a rewind with the session open


_ANSI = re.compile(
    rb"\x1b\[[0-9;?<>=]*[ -/]*[@-~]"  # CSI: colours, cursor moves
    rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC: titles
    rb"|\x1b[()][A-Z0-9]|\x1b[=>78DEHMc]"
)


class Terminal:
    """A program on a pseudo-terminal of its own, as `docker exec -it` from a person's shell."""

    def __init__(self, argv: list[str]) -> None:
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
        self.master = master
        self.output = bytearray()
        self.process = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True, close_fds=True
        )
        os.close(slave)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.output += chunk

    def text(self, start: int = 0) -> str:
        return _ANSI.sub(b"", bytes(self.output[start:])).decode(errors="replace")

    def squeezed(self, start: int = 0) -> str:
        """The text without any blank: the screen moves the cursor instead of printing spaces."""
        return "".join(self.text(start).split())

    def key(self, keys: bytes) -> None:
        os.write(self.master, keys)
        time.sleep(0.4)

    def type(self, text: str) -> None:
        os.write(self.master, text.encode())
        time.sleep(0.4)
        os.write(self.master, b"\r")

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=30)
        self._reader.join(timeout=5)
        os.close(self.master)


def wait_for(check: Callable[[], bool], timeout: float, what: str, term: Terminal) -> float:
    start = time.monotonic()
    while not check():
        if time.monotonic() - start > timeout:
            raise AssertionError(
                f"{what} did not happen in {timeout} s; screen: {term.text()[-2500:]}"
            )
        time.sleep(0.3)
    return time.monotonic() - start


def seed_interactive(lab: Lab) -> None:
    """What a person answers once in the first interactive run, written beforehand in
    ~/.claude.json: UI state, not authorization (the jail and the gate are the frontier).

    - Without ``hasCompletedOnboarding`` the first screen checks ``GET api.anthropic.com/api/
      hello`` and ``platform.claude.com/v1/oauth/hello``; the gate refuses both and Claude Code
      stops at "Unable to connect to Anthropic services".
    - Without the project's ``hasTrustDialogAccepted``, it asks whether to trust /workspace/work.
    - Without ``customApiKeyResponses``, it asks whether to use ANTHROPIC_API_KEY (showing its
      last 20 characters; "No" is the default).
    - The bypass-mode warning is ``skipDangerousModePermissionPrompt`` in the settings
      (/config/claude.json here)."""
    path = lab.home / ".claude.json"
    state = json.loads(path.read_text()) if path.exists() else {}
    state |= {
        "hasCompletedOnboarding": True,
        "customApiKeyResponses": {"approved": [lab.fake_key[-20:]], "rejected": []},
    }
    projects = state.setdefault("projects", {})
    projects.setdefault("/workspace/work", {})["hasTrustDialogAccepted"] = True
    path.write_text(json.dumps(state, indent=2))


# Dialogs of the first interactive run that ~/.claude.json did not answer: what the screen
# says (without blanks) and the keys a person would press.
DIALOGS = (
    ("Yes,Iaccept", b"\x1b[B\r"),  # bypass permissions mode: "No, exit" is the default
    ("Yes,Itrustthisfolder", b"\x1b[B\r"),  # the trust dialog: "No, exit" is the default
    ("DoyouwanttousethisAPIkey?", b"\x1b[A\r"),  # "No (recommended)" is the default
)


def open_session(term: Terminal, timeout: float = 60) -> list[str]:
    """Wait for the input prompt, answering the first-run dialogs; returns the ones seen."""
    seen: list[str] = []
    since = 0
    deadline = time.monotonic() + timeout
    while "bypasspermissionson" not in term.squeezed(since):  # the footer of the input box
        screen = term.squeezed(since)
        for text, keys in DIALOGS:
            if text in screen:
                seen.append(text)
                since = len(term.output)
                term.key(keys)
                break
        if time.monotonic() > deadline:
            raise AssertionError(f"no prompt in {timeout} s; screen: {term.text()[-2500:]}")
        time.sleep(0.3)
    return seen


def model_markers(lab: Lab, mark: int) -> list[list[str]]:
    return [r.get("user_markers", []) for r in lab.since(mark) if is_model_call(r)]


def test_interactive_session_and_a_rewind_with_it_open(
    lab: Lab, first_run: Run, record_property: Callable[[str, object], None]
) -> None:
    del first_run  # HOME has Claude Code's files already, as after any first use
    seed_interactive(lab)
    notes = lab.work / "notes.txt"
    notes.unlink(missing_ok=True)
    term = Terminal([
        "docker", "exec", "--interactive", "--tty", "--user", lab.user, "--env",
        "TERM=xterm-256color", lab.jail.config.name, CLAUDE, "--dangerously-skip-permissions",
        "--settings", SETTINGS,
    ])  # fmt: skip
    try:
        before = files_under(lab.home)
        start = time.monotonic()
        dialogs = open_session(term)
        report(record_property, "interactive: prompt after",
               f"{time.monotonic() - start:.1f} s; dialogs answered: {dialogs}")  # fmt: skip
        assert dialogs == []  # the seed and the profile's settings answer them all
        changed = sorted(p for p, size in files_under(lab.home).items() if before.get(p) != size)
        report(record_property, "interactive: HOME files written on opening", changed)
        keys = [lab.home / p for p in changed if p.endswith(".key")]  # never read: sizes only
        shapes = [f"{k.stat().st_size} B, {oct(k.stat().st_mode & 0o777)}" for k in keys]
        report(record_property, "interactive: session .key files", shapes)
        mark = lab.mark()
        term.type("t17:write uno")
        wait_for(lambda: notes.exists() and notes.read_text() == "uno\n", 60, "uno", term)
        wait_for(lambda: any(r.get("results") for r in lab.since(mark) if is_model_call(r)), 30,
                 "the answer after the tool", term)  # fmt: skip
        snap = lab.store.take(Reason.MANUAL)
        term.type("t17:write dos")
        wait_for(lambda: notes.read_text() == "uno\ndos\n", 60, "dos", term)
        conversation = sorted((lab.home / ".claude" / "projects").glob("*/*.jsonl"),
                              key=lambda p: p.stat().st_mtime)[-1]  # fmt: skip
        wait_for(lambda: "t17:write dos" in conversation.read_text(), 30, "dos saved", term)
        start = time.monotonic()
        result = lab.store.restore(snap.id, quiesce=lab.jail.quiesce)
        rewind = time.monotonic() - start
        code = term.process.wait(timeout=30)
        report(record_property, "interactive: rewind", f"{rewind:.1f} s; the session ended "
               f"with exit {code}; undo {result.undo.id if result.undo else None}")  # fmt: skip
        assert lab.jail.is_running()
        assert notes.read_text() == "uno\n"
        text = conversation.read_text()
        assert "t17:write uno" in text
        assert "t17:write dos" not in text
    finally:
        term.close()
    mark = lab.mark()
    resumed = lab.claude("t17:hello", "--continue")
    assert resumed.returncode == 0, resumed.stderr[-800:]
    assert resumed.result()["result"] == "listo"
    seen = model_markers(lab, mark)
    assert seen and "t17:write uno" in seen[-1] and "t17:write dos" not in seen[-1], seen
    report(record_property, "interactive: --continue after the rewind", f"markers {seen[-1]}")
