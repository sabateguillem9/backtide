"""The fixed rule for what goes to a model provider's host. Pure: no I/O.

A request to a provider leaves with the real key (the proxy swaps the fake one in). Some provider
APIs run tools ON THE PROVIDER'S SIDE that reach any host: Anthropic's MCP connectors
(``mcp_servers``), web search and web fetch, code execution, images and documents given by URL;
OpenAI's ``web_search``, ``mcp``, ``file_search``, ``code_interpreter``, remote images and files,
stored prompts, search models. With them the agent would make the provider go anywhere for it,
past the allowed list and out of the black box's sight (docs/21, "Resultados de T06-5", the
high finding; fixed in T06-6). So a request to a provider's host only goes on when it is what a
model client does with its own tools:

- one of the provider's model endpoints (``POST .../messages`` and ``.../messages/count_tokens``
  for Anthropic; ``POST .../chat/completions``, ``.../responses``, ``.../completions`` and
  ``.../embeddings`` for OpenAI and compatible APIs; ``GET .../models[/<id>]`` for both), on a
  plain path (no dot segments, escapes, ``;`` or ``//``) and with no ``Upgrade``:
  ``provider_endpoint`` otherwise;
- a body that is the provider's JSON, read strictly whatever ``Content-Type`` says (UTF-8, one
  object, no duplicate keys, no NaN, ``Content-Type`` absent or ``application/json``), and empty
  for a ``GET``: ``provider_body`` otherwise;
- no tool that is not a plain client-side one (Anthropic: no ``type`` or ``custom``; OpenAI:
  ``function`` or ``custom``; any other type, known or not, counts as the provider's: fail
  closed), no connector outside ``tools`` and no source the provider would fetch:
  ``provider_side_tool``, with the names found (types only, never their settings).

``[proxy] allow_provider_tools`` (empty by default) names the ones that may go on anyway; they
are recorded in the ``llm/request``. Decided by default (revisable): docs/21, "Resultados de
T06-6". T10 turns the refusal into "hold for approval".

The cost is bounded: the body is 16 MiB at most (the gate's limit), read once, and the walk over
it stops at MAX_NODES values (``provider_body`` past that).

T20 (docs/35, section 6.2, step 4): for a local provider (an Ollama on the owner's machine) and
for Ollama's cloud API the endpoint is not found by the end of its path but in a closed list,
compared exactly (``exact_endpoint``): the same server has routes that download, delete or
copy models, read the owner's account or search the web. A route that is not on the list stays
out, even a new one. ``ollama_admin`` names the routes that change the owner's machine or
account: refusing one of them is risk 3 (decision 9).
"""

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from backtide.gate.policy import canonical_path
from backtide.gate.providers import is_cloud_model

MAX_NODES = 1_000_000
MAX_NAMES = 16
MAX_NAME_LENGTH = 64
ALLOW_ENTRY_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}", re.ASCII)

# Each kind's POST endpoints, by the end of their path: the first that matches names it.
_POST_ENDPOINTS = {
    "anthropic": ((("messages", "count_tokens"), "count_tokens"), (("messages",), "messages")),
    "openai": (
        (("chat", "completions"), "chat"),
        (("responses",), "responses"),
        (("completions",), "completions"),
        (("embeddings",), "embeddings"),
    ),
}
# The top-level fields each endpoint has (as the providers document them). Any other field is
# ``param:<name>``: refused unless allowed by name. A compatible API's own extras (a search
# switch, data sources, a list of fallback models) are refused that way, failing closed.
_MESSAGES_FIELDS = frozenset(
    {"model", "messages", "max_tokens", "system", "metadata", "stop_sequences", "stream",
     "temperature", "top_p", "top_k", "tools", "tool_choice", "thinking", "service_tier",
     "container", "context_management", "output_config", "output_format", "cache_control"}
)  # fmt: skip
_FIELDS = {
    "messages": _MESSAGES_FIELDS,
    "count_tokens": _MESSAGES_FIELDS,  # a client counts what it would send
    "chat": frozenset(
        {
            "model",
            "messages",
            "audio",
            "frequency_penalty",
            "function_call",
            "functions",
            "logit_bias",
            "logprobs",
            "max_completion_tokens",
            "max_tokens",
            "metadata",
            "modalities",
            "n",
            "parallel_tool_calls",
            "prediction",
            "presence_penalty",
            "prompt_cache_key",
            "prompt_cache_retention",
            "reasoning_effort",
            "response_format",
            "safety_identifier",
            "seed",
            "service_tier",
            "stop",
            "store",
            "stream",
            "stream_options",
            "temperature",
            "tool_choice",
            "tools",
            "top_logprobs",
            "top_p",
            "user",
            "verbosity",
        }
    ),  # fmt: skip
    "responses": frozenset(
        {
            "model",
            "input",
            "instructions",
            "background",
            "conversation",
            "include",
            "max_output_tokens",
            "max_tool_calls",
            "metadata",
            "parallel_tool_calls",
            "previous_response_id",
            "prompt_cache_key",
            "prompt_cache_retention",
            "reasoning",
            "safety_identifier",
            "service_tier",
            "store",
            "stream",
            "stream_options",
            "temperature",
            "text",
            "tool_choice",
            "tools",
            "top_logprobs",
            "top_p",
            "truncation",
            "user",
            "context_management",
        }
    ),  # fmt: skip
    "completions": frozenset(
        {
            "model",
            "prompt",
            "best_of",
            "echo",
            "frequency_penalty",
            "logit_bias",
            "logprobs",
            "max_tokens",
            "n",
            "presence_penalty",
            "seed",
            "stop",
            "stream",
            "stream_options",
            "suffix",
            "temperature",
            "top_p",
            "user",
        }
    ),  # fmt: skip
    "embeddings": frozenset({"model", "input", "dimensions", "encoding_format", "user"}),
}
# Headers some servers and gateways read as another method or another path.
_OVERRIDE_HEADERS = frozenset(
    {"x-http-method-override", "x-method-override", "x-http-method", "x-original-method",
     "x-original-url", "x-rewrite-url", "x-forwarded-prefix"}
)  # fmt: skip
_SEGMENT_RE = re.compile(r"[A-Za-z0-9_~:@+-][A-Za-z0-9._~:@+-]*", re.ASCII)
_ANTHROPIC_CLIENT_TYPES = frozenset({None, "custom"})
_OPENAI_CLIENT_TYPES = frozenset({"function", "custom"})
# Fields outside ``tools`` that turn on something on the provider's side (for any kind: a
# compatible API may take another's). ``prompt`` only as an object (a stored prompt).
_CONNECTORS = frozenset(
    {"mcp_servers", "web_search_options", "plugins", "tool_resources", "prompt"}
)
_URL_KEYS = frozenset({"url", "image_url", "file_url", "audio_url", "video_url", "document_url"})
# Subtrees that are never a source the provider fetches: the client's own tool inputs (they are
# the model's words, sent back), schemas, metadata, and what the provider itself answered before.
_SKIPPED_KEYS = frozenset({"tools", "functions", "mcp_servers", "metadata", "citations"})
_INPUT_BLOCKS = frozenset({"tool_use", "server_tool_use", "mcp_tool_use"})
_SEARCH_MODEL_RE = re.compile(r"search|:online\Z|\Asonar|/sonar", re.ASCII)


@dataclass(frozen=True)
class Verdict:
    """``reason`` None: it may go on, and ``tools`` are the allowed provider-side ones it uses.
    Otherwise the refusal's reason, and the provider-side tools that were not allowed."""

    reason: str | None
    tools: tuple[str, ...] = ()


class _Malformed(Exception):
    pass


def check_allow_entry(entry: object) -> str:
    """An ``allow_provider_tools`` entry: a tool type or connector name as the gate names it
    (lower case, digits, ``_.:-``). Raises ValueError, with a message that is safe to show."""
    if not isinstance(entry, str) or not ALLOW_ENTRY_RE.fullmatch(entry):
        raise ValueError(
            "an allowed provider tool is a name of 1-64 lower-case letters, digits or _.:-"
        )
    return entry


PARAM_PREFIX = "param:"
# Words of a request field that switches on something on the provider's side (review of the
# profiles, M3): a search or a retrieval (xAI's ``search_parameters``, Perplexity's
# ``search_*``, Qwen's ``enable_search``, Gemini's grounding), a tool, function, plugin or
# connector (OpenRouter's ``plugins``, MCP), code the provider runs, a file, document, vector
# store or data source it reads (Azure's ``data_sources``), a source it fetches (a URL, a
# browse), a model, route or provider other than the one asked for (OpenRouter's ``models`` and
# ``provider``: past the ``models`` list), a stored prompt, assistant or agent, a callback, and
# a client library's own pass-through of any field (``extra_body``, ``extra_headers``). Matched
# in the name without its separators, so ``searchParameters`` (which the gate folds to
# ``searchparameters``) and ``web.search`` count too. Such a field can only come from the
# owner's ``[proxy] allow_provider_tools``, where it is named on purpose; a profile is copied
# from an agent's documentation, and a field it allows silently would carry the real key to a
# provider-side search or fetch that the black box never sees.
_PROVIDER_SIDE_WORDS = (
    "search", "retriev", "grounding", "extra", "tool", "function", "plugin", "connector",
    "mcp", "file", "document", "attachment", "source", "vector", "knowledge", "interpreter",
    "execut", "sandbox", "computer", "shell", "bash", "python", "brows", "fetch", "crawl",
    "scrap", "url", "http", "web", "online", "citation", "model", "route", "routing",
    "provider", "prompt", "assistant", "agentid", "webhook", "callback",
)  # fmt: skip
_SEPARATORS_RE = re.compile(r"[_.:-]", re.ASCII)


def check_profile_param(entry: object) -> str:
    """A provider-side field an agent profile allows (decision 5 of docs/34): a top-level field
    of the request, ``param:<name>``, and nothing else. A profile can never allow a tool, a
    connector, a fetched source or a model that the gate refuses, nor a field that switches on
    a search, a retrieval or a tool at the provider (``_PROVIDER_SIDE_WORDS``): only the owner
    can, with ``allow_provider_tools``. Raises ValueError, with a message that is safe to show."""
    name = check_allow_entry(entry)
    if not name.startswith(PARAM_PREFIX) or name == PARAM_PREFIX:
        raise ValueError(f"a profile only allows request fields by name ({PARAM_PREFIX}<name>)")
    flat = _SEPARATORS_RE.sub("", name.removeprefix(PARAM_PREFIX))
    if any(word in flat for word in _PROVIDER_SIDE_WORDS):
        raise ValueError(
            f"{name} may switch on something on the provider's side (a search, a retrieval, a "
            "tool, a source it fetches, another model...): a profile never allows it; only "
            "[proxy] allow_provider_tools can, by its name"
        )
    return name


def check_request(
    kind: str,
    method: str,
    path: str,
    headers: Sequence[tuple[str, str]],
    body: bytes | None,
    *,
    allowed: Iterable[str] = frozenset(),
    models: Iterable[str] = (),
    trailers: Sequence[tuple[str, str]] = (),
    exact: bool = False,
    local: bool = False,
) -> Verdict:
    """Whether a request to a provider of ``kind`` may go on (see the module's docstring).
    ``models``: the provider's listed models (``[[proxy.providers]] models``); when there are
    any, the request's model must be one of them. ``body`` is the decoded one; a request that
    still says it is compressed, or that has trailers, is refused (``provider_body``): no
    model client sends either, and a server could read them otherwise than the gate.
    ``exact``: only the routes of ``EXACT_ROUTES`` (a local provider, Ollama's cloud: T20).
    ``local``: toward a local provider (``local_allowed``: the owner's list cannot open it)."""
    models = tuple(models)
    endpoint = (
        exact_endpoint(kind, method, path, headers, models)
        if exact
        else _endpoint(kind, method, path, headers)
    )
    if endpoint is None:
        return Verdict("provider_endpoint")
    data = body or b""
    if endpoint == "models":
        return Verdict(None) if not data and not trailers else Verdict("provider_body")
    try:
        _check_headers(headers, trailers)
        request = _strict_json(data)
        found = _provider_side(kind, endpoint, request, models)
    except _Malformed:
        return Verdict("provider_body")
    if local and is_cloud_model(request.get("model")):
        found.add(CLOUD_MODEL)  # a "local" call that Ollama would send to ollama.com
    permitted = local_allowed(allowed) if local else frozenset(allowed)
    refused = sorted(name for name in found if name not in permitted)
    if refused:
        return Verdict("provider_side_tool", tuple(refused[:MAX_NAMES]))
    return Verdict(None, tuple(sorted(found)[:MAX_NAMES]))


# T20 (review of T20-2/3, M1): ``allow_provider_tools`` is one list for every provider, written
# for the public ones. Toward a local provider only a plain request field may be allowed by it
# (one a profile could declare: ``check_profile_param``), never a model off the list, a search
# model, a fetched source, a provider-side tool, nor Ollama's own fields that reach the owner's
# machine (design 6.2, step 5). A cloud model (``cloud_model``) is refused whatever the lists say.
CLOUD_MODEL = "cloud_model"
LOCAL_NEVER = frozenset(
    {f"{PARAM_PREFIX}{name}" for name in ("options", "keep_alive", "think", "format")}
)


def local_allowed(allowed: Iterable[str]) -> frozenset[str]:
    """What of ``allowed`` may still go to a local provider: request fields by name that switch
    on nothing on the provider's side, and none of LOCAL_NEVER."""
    kept = set()
    for name in allowed:
        if not isinstance(name, str) or name in LOCAL_NEVER:
            continue
        try:
            kept.add(check_profile_param(name))
        except ValueError:
            continue  # a tool, a model, a source, or a field that switches something on
    return frozenset(kept)


# --- the endpoint ---------------------------------------------------------------------------------

# T20: the exact routes of a local provider (and of Ollama's cloud API), by kind: (method, path)
# -> endpoint. ``GET /v1/models/<id>`` too, for an id of its ``models`` only.
EXACT_ROUTES = {
    "openai": {
        ("POST", "/v1/chat/completions"): "chat",
        ("POST", "/v1/completions"): "completions",
        ("POST", "/v1/embeddings"): "embeddings",
        ("POST", "/v1/responses"): "responses",
        ("GET", "/v1/models"): "models",
    },
    "anthropic": {
        ("POST", "/v1/messages"): "messages",
        # Ollama answers 404: Claude Code sees an ordinary error (docs/35, section 6.2).
        ("POST", "/v1/messages/count_tokens"): "count_tokens",
    },
}
_MODEL_PREFIX = "/v1/models/"
# The routes of Ollama that change the owner's machine or account (docs/35, section 3, P8),
# matched on whole segments of the path as a lenient server could read it.
OLLAMA_ADMIN = (
    "/api/pull", "/api/push", "/api/create", "/api/copy", "/api/delete", "/api/blobs",
    "/api/experimental", "/api/me", "/api/signout", "/api/user",
)  # fmt: skip


def exact_endpoint(
    kind: str,
    method: str,
    path: str,
    headers: Sequence[tuple[str, str]] = (),
    models: Iterable[str] = (),
) -> str | None:
    """Which model endpoint a request to a local provider (or Ollama's cloud) is, from the closed
    list ``EXACT_ROUTES``: method and path (without the query) compared exactly, no ``Upgrade``
    and no header that names another method or path. None otherwise (``provider_endpoint``)."""
    routes = EXACT_ROUTES.get(kind)
    if routes is None or not isinstance(method, str) or not isinstance(path, str):
        return None
    if any(name.lower() == "upgrade" or name.lower() in _OVERRIDE_HEADERS for name, _ in headers):
        return None
    raw = path.split("?", 1)[0]
    found = routes.get((method, raw))
    if found is not None:
        return found
    if kind == "openai" and method == "GET" and raw.startswith(_MODEL_PREFIX):
        model = raw[len(_MODEL_PREFIX) :]
        if model and model in tuple(models):
            return "models"
    return None


def ollama_admin(path: object) -> bool:
    """Whether ``path`` reaches one of Ollama's routes that change the owner's machine or account
    (``/api/pull``, ``/v1/../api/delete``, ``//API/Pull;x``...), read as a lenient server would."""
    if not isinstance(path, str):
        return False
    canonical = canonical_path(path)
    return any(canonical == route or canonical.startswith(route + "/") for route in OLLAMA_ADMIN)


# The endpoints the providers do not bill (T11, security review M4): the list of models and
# Anthropic's token count. They still hold a place among the calls in flight.
FREE_ENDPOINTS = frozenset({"models", "count_tokens"})


def endpoint_of(
    kind: str,
    method: str,
    path: str,
    headers: Sequence[tuple[str, str]] = (),
    *,
    exact: bool = False,
    models: Iterable[str] = (),
) -> str | None:
    """Which model endpoint a request is (``messages``, ``count_tokens``, ``chat``,
    ``responses``, ``completions``, ``embeddings`` or ``models``), or None. ``exact``: from the
    closed list of a local provider or Ollama's cloud (``exact_endpoint``)."""
    if exact:
        return exact_endpoint(kind, method, path, headers, models)
    return _endpoint(kind, method, path, headers)


def _endpoint(kind: str, method: str, path: str, headers: Sequence[tuple[str, str]]) -> str | None:
    """Which model endpoint this is, or None."""
    if kind not in _POST_ENDPOINTS:
        return None
    if any(name.lower() == "upgrade" or name.lower() in _OVERRIDE_HEADERS for name, _ in headers):
        return None
    raw = path.split("?", 1)[0]
    if not raw.startswith("/"):
        return None
    segments = raw[1:].split("/")
    if not all(_SEGMENT_RE.fullmatch(segment) for segment in segments):
        return None  # "", ".", "..", escapes, ";", "\\" and anything odd
    lowered = tuple(segment.lower() for segment in segments)
    verb = method.upper()
    if verb == "GET":
        listing = lowered[-1:] == ("models",) or lowered[-2:-1] == ("models",)
        return "models" if listing else None
    if verb != "POST":
        return None
    for end, name in _POST_ENDPOINTS[kind]:
        if lowered[-len(end) :] == end:
            return name
    return None


# --- the body -------------------------------------------------------------------------------------


def _check_headers(headers: Sequence[tuple[str, str]], trailers: Sequence[tuple[str, str]]) -> None:
    if trailers:
        raise _Malformed
    types = [value for name, value in headers if name.lower() == "content-type"]
    if len(types) > 1:
        raise _Malformed
    if types and types[0].split(";", 1)[0].strip().lower() != "application/json":
        raise _Malformed
    for name, value in headers:
        if name.lower() == "content-encoding" and value.strip().lower() not in ("", "identity"):
            raise _Malformed


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Keys case-folded: some servers' JSON readers match keys without case (Go folds "Tools",
    "ſ" and "K" too), so the gate reads them as those would, and two keys that fold the same
    are refused (two readers could each keep a different one)."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        folded = key.casefold()
        if folded in result:
            raise _Malformed
        result[folded] = value
    return result


def _no_constant(name: str) -> Any:
    raise _Malformed  # NaN and Infinity are not JSON


def _strict_json(data: bytes) -> dict[str, Any]:
    # Bounded before parsing: every object, list and value past the first starts at one of these
    # (a count that is never lower than the real one), so the tree json.loads would build fits.
    if data.count(b"{") + data.count(b"[") + data.count(b",") > MAX_NODES:
        raise _Malformed
    try:
        text = data.decode("utf-8")  # strict: no other encoding, and a BOM is refused below
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _Malformed from None
    if not isinstance(value, dict):
        raise _Malformed
    return value


# --- what runs on the provider's side ------------------------------------------------------------


def _name(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "untyped"
    printable = "".join(c if c.isprintable() and c.isascii() else "?" for c in value)
    return printable[:MAX_NAME_LENGTH]


def _provider_side(
    kind: str, endpoint: str, request: dict[str, Any], models: tuple[str, ...]
) -> set[str]:
    found: set[str] = set()
    tools = request.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            raise _Malformed
        client_types = _ANTHROPIC_CLIENT_TYPES if kind == "anthropic" else _OPENAI_CLIENT_TYPES
        for tool in tools:
            if not isinstance(tool, dict):
                raise _Malformed
            kind_of = tool.get("type")
            if not (kind_of is None or isinstance(kind_of, str)) or kind_of not in client_types:
                found.add(_name(kind_of))
    for key in _CONNECTORS:
        value = request.get(key)
        if key == "prompt":
            if isinstance(value, dict):
                found.add("stored_prompt")  # a prompt kept by the provider, with its own tools
        elif key == "web_search_options":
            if value is not None:
                found.add(key)  # Chat Completions' web search, even with {}
        elif value not in (None, [], {}):
            found.add(key)
    for key in request:
        if key not in _FIELDS[endpoint] and key not in _CONNECTORS:
            found.add(_name(f"{PARAM_PREFIX}{key}"))
    model = request.get("model")
    if models:
        if not isinstance(model, str):
            raise _Malformed
        if model not in models:
            found.add("model_not_listed")
    if isinstance(model, str) and _SEARCH_MODEL_RE.search(model.lower()):
        found.add("search_model")  # a model that searches the web on its own
    if _fetches_sources(request):
        found.add("url_source")
    return found


def _fetches_sources(request: dict[str, Any]) -> bool:
    """Whether anything the provider would fetch by URL is in the request (an image or a
    document by URL, a remote file), outside the client's own tool inputs. Bounded."""
    stack: list[object] = [request]
    nodes = 0
    found = False
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise _Malformed
        if isinstance(item, list):
            stack.extend(item)
            continue
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if isinstance(kind, str) and kind.lower() == "url":
            found = True
        if isinstance(kind, str) and kind.endswith("_tool_result") and kind != "tool_result":
            continue  # what a server tool answered before: the provider never fetches it again
        skip_input = kind in _INPUT_BLOCKS
        for key, value in item.items():
            if key in _SKIPPED_KEYS or (skip_input and key == "input"):
                continue
            if key in _URL_KEYS and isinstance(value, str):
                if not value.strip().lower().startswith("data:"):
                    found = True
                continue
            if isinstance(value, dict | list):
                stack.append(value)
    return found
