"""The fixed rule for requests to a model provider's host (backtide/gate/provider_tools.py, T06-6).

A request to a provider leaves with the real key, so it may only be what a model client does with
its own tools: one of the provider's model endpoints, a body that is the provider's JSON, and no
tool or connector that runs on the provider's side and reaches the network (web search and
fetch, MCP connectors, code execution, remote files). Anything else is refused, and the
``allow_provider_tools`` of ``[proxy]`` can let named ones through.
"""

import json

import pytest

from backtide.gate import provider_tools
from backtide.gate.provider_tools import Verdict, check_allow_entry, check_request

JSON = [("content-type", "application/json")]


def anthropic(body: object, path: str = "/v1/messages", **options: object) -> Verdict:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return check_request("anthropic", "POST", path, options.pop("headers", JSON), raw, **options)  # type: ignore[arg-type]


def openai(body: object, path: str = "/v1/chat/completions", **options: object) -> Verdict:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return check_request("openai", "POST", path, options.pop("headers", JSON), raw, **options)  # type: ignore[arg-type]


def message(**extra: object) -> dict[str, object]:
    base = {"model": "claude-x", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]}
    return base | extra


def chat(**extra: object) -> dict[str, object]:
    return {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]} | extra


def refused(verdict: Verdict) -> tuple[str | None, tuple[str, ...]]:
    return verdict.reason, verdict.tools


# --- what a model client does goes on ------------------------------------------------------------


def test_a_plain_anthropic_request_with_its_own_tools_goes_on() -> None:
    tools = [
        {"name": "exec", "description": "run", "input_schema": {"type": "object"}},
        {"type": "custom", "name": "read", "input_schema": {"type": "object"}},
        {"type": None, "name": "write", "input_schema": {"type": "object"}},
    ]
    assert anthropic(message(tools=tools, stream=True)) == Verdict(None)
    assert anthropic(message(tools=tools), path="/v1/messages/count_tokens") == Verdict(None)


def test_a_plain_openai_request_with_its_own_tools_goes_on() -> None:
    function = {"type": "function", "function": {"name": "exec", "parameters": {}}}
    assert openai(chat(tools=[function, {"type": "custom", "name": "c"}])) == Verdict(None)
    responses = {"model": "gpt-x", "input": "hi", "tools": [{"type": "function", "name": "f"}]}
    assert openai(responses, path="/v1/responses") == Verdict(None)
    assert openai({"model": "gpt-x", "prompt": "say hi"}, path="/v1/completions") == Verdict(None)
    assert openai({"model": "e", "input": "hi"}, path="/v1/embeddings") == Verdict(None)


def test_an_openai_compatible_base_path_is_accepted() -> None:
    assert openai(chat(), path="/api/v1/chat/completions?x=1") == Verdict(None)
    assert openai(chat(), path="/openai/v1/chat/completions") == Verdict(None)


def test_listing_the_models_goes_on_without_a_body() -> None:
    for kind in ("anthropic", "openai"):
        assert check_request(kind, "GET", "/v1/models", [], b"") == Verdict(None)
        assert check_request(kind, "GET", "/v1/models/some-model:1", [], None) == Verdict(None)


def test_a_body_without_content_type_is_still_parsed_and_may_go_on() -> None:
    assert anthropic(message(), headers=[]) == Verdict(None)
    assert anthropic(message(), headers=[("Content-Type", "application/json; charset=utf-8")]) == (
        Verdict(None)
    )


def test_the_agents_own_tool_inputs_and_schemas_are_not_mistaken_for_sources() -> None:
    history = [
        {"role": "user", "content": "fetch it"},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "t",
                    "name": "browser",
                    "input": {
                        "url": "https://example.com",
                        "image_url": "https://example.com/a.png",
                        "source": {"type": "url", "url": "https://example.com"},
                    },
                },
            ],
        },  # fmt: skip
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "ok"}]},
    ]
    schema = {"type": "object", "properties": {"url": {"type": "string"}}}
    tools = [{"name": "browser", "input_schema": schema}]
    body = message(messages=history, tools=tools, metadata={"url": "https://example.com"})
    assert anthropic(body) == Verdict(None)
    arguments = '{"url": "https://x.example"}'
    calls = [{"id": "c", "type": "function", "function": {"name": "b", "arguments": arguments}}]
    chat_history = [{"role": "assistant", "content": None, "tool_calls": calls}]
    assert openai(chat(messages=chat_history)) == Verdict(None)


def test_inline_images_go_on() -> None:
    data = "data:image/png;base64,iVBORw0KGgo="
    block = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "x"}}
    assert anthropic(message(messages=[{"role": "user", "content": [block]}])) == Verdict(None)
    part = {"type": "image_url", "image_url": {"url": data}}
    assert openai(chat(messages=[{"role": "user", "content": [part]}])) == Verdict(None)
    item = {"role": "user", "content": [{"type": "input_image", "image_url": data.upper()}]}
    assert openai({"model": "m", "input": [item]}, path="/v1/responses") == Verdict(None)


# --- provider-side tools and connectors are refused ----------------------------------------------


@pytest.mark.parametrize(
    "tool",
    [
        "web_fetch_20250910",
        "web_search_20250305",
        "code_execution_20250825",
        "mcp_toolset",
        "tool_search_tool_regex_20251119",
        "bash_20250124",  # not a plain client-side tool: refused unless allowed
        "some_tool_of_the_future_20300101",
    ],
)
def test_an_anthropic_tool_that_is_not_the_clients_own_is_refused(tool: str) -> None:
    tools = [{"name": "exec", "input_schema": {}}, {"type": tool, "name": "x"}]
    assert refused(anthropic(message(tools=tools))) == ("provider_side_tool", (tool,))


def test_anthropic_mcp_servers_are_refused() -> None:
    servers = [{"type": "url", "url": "https://mcp.example/sse", "name": "evil"}]
    assert refused(anthropic(message(mcp_servers=servers))) == (
        "provider_side_tool",
        ("mcp_servers",),
    )
    assert anthropic(message(mcp_servers=[])) == Verdict(None)
    assert anthropic(message(mcp_servers=None)) == Verdict(None)


@pytest.mark.parametrize(
    "tool",
    ["web_search", "web_search_preview", "mcp", "file_search", "code_interpreter",
     "image_generation", "computer_use_preview", "local_shell", "shell"],
)  # fmt: skip
def test_an_openai_tool_that_is_not_a_function_is_refused(tool: str) -> None:
    body = {"model": "gpt-x", "input": "hi", "tools": [{"type": tool}]}
    assert refused(openai(body, path="/v1/responses")) == ("provider_side_tool", (tool,))
    assert refused(openai(chat(tools=[{"type": tool}]))) == ("provider_side_tool", (tool,))


def test_a_tool_without_a_type_is_refused_on_openai() -> None:
    assert refused(openai(chat(tools=[{"name": "f"}]))) == ("provider_side_tool", ("untyped",))
    assert refused(openai(chat(tools=[{"type": 7}]))) == ("provider_side_tool", ("untyped",))


@pytest.mark.parametrize(
    ("extra", "name"),
    [
        ({"web_search_options": {}}, "web_search_options"),
        ({"plugins": [{"id": "web"}]}, "plugins"),
        ({"prompt": {"id": "pmpt_1"}}, "stored_prompt"),
        ({"tool_resources": {"file_search": {}}}, "tool_resources"),
        ({"model": "gpt-4o-search-preview"}, "search_model"),
        ({"model": "some/model:online"}, "search_model"),
        ({"model": "sonar-pro"}, "search_model"),
    ],
)
def test_openai_connectors_outside_tools_are_refused(extra: dict[str, object], name: str) -> None:
    assert refused(openai(chat(**extra))) == ("provider_side_tool", (name,))


@pytest.mark.parametrize(
    "content",
    [
        [{"type": "image", "source": {"type": "url", "url": "https://evil.example/?d=1"}}],
        [{"type": "document", "source": {"type": "URL", "url": "https://evil.example/doc.pdf"}}],
        [{"type": "tool_result", "tool_use_id": "t",
          "content": [{"type": "image", "source": {"type": "url", "url": "http://10.0.0.1/"}}]}],
    ],
)  # fmt: skip
def test_an_anthropic_source_the_provider_would_fetch_is_refused(content: list[object]) -> None:
    body = message(messages=[{"role": "user", "content": content}])
    assert refused(anthropic(body)) == ("provider_side_tool", ("url_source",))


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("/v1/chat/completions",
         [{"type": "image_url", "image_url": {"url": "https://evil.example/a.png"}}]),
        ("/v1/responses", [{"type": "input_image", "image_url": "https://evil.example/a.png"}]),
        ("/v1/responses", [{"type": "input_file", "file_url": "https://evil.example/f.pdf"}]),
    ],
)  # fmt: skip
def test_an_openai_url_the_provider_would_fetch_is_refused(path: str, content: object) -> None:
    item = {"role": "user", "content": content}
    body = chat(messages=[item]) if "chat" in path else {"model": "m", "input": [item]}
    assert refused(openai(body, path=path)) == ("provider_side_tool", ("url_source",))


def test_several_provider_tools_are_named_once_each_sorted_and_bounded() -> None:
    tools = [{"type": f"tool_{n:03}"} for n in range(40)] + [{"type": "tool_000"}]
    tools.append({"type": "x" * 500})
    verdict = openai(chat(tools=tools))
    assert verdict.reason == "provider_side_tool"
    assert len(verdict.tools) == provider_tools.MAX_NAMES
    assert verdict.tools == tuple(sorted(verdict.tools))
    assert all(len(name) <= provider_tools.MAX_NAME_LENGTH for name in verdict.tools)


# --- allow_provider_tools ------------------------------------------------------------------------


def test_an_allowed_provider_tool_goes_on_and_is_named() -> None:
    tools = [{"type": "web_search_20250305", "name": "web_search"}]
    allowed = frozenset({"web_search_20250305"})
    assert anthropic(message(tools=tools), allowed=allowed) == Verdict(
        None, ("web_search_20250305",)
    )


def test_only_the_allowed_ones_go_on() -> None:
    tools = [{"type": "web_search_20250305"}]
    verdict = anthropic(
        message(tools=tools, mcp_servers=[{"url": "https://x"}]),
        allowed=frozenset({"web_search_20250305"}),
    )
    assert refused(verdict) == ("provider_side_tool", ("mcp_servers",))


@pytest.mark.parametrize("entry", ["web_search", "mcp_servers", "web_fetch_20250910", "a.b:c-d"])
def test_allow_entries_are_plain_names(entry: str) -> None:
    assert check_allow_entry(entry) == entry


@pytest.mark.parametrize("entry", ["", "Web", "*", "web search", "x" * 65, 7, None, "-a"])
def test_bad_allow_entries_are_refused(entry: object) -> None:
    with pytest.raises(ValueError):
        check_allow_entry(entry)


# --- the body must be the provider's JSON --------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[1, 2]",
        b'"text"',
        b"",
        b'{"model": "m", "tools": [], "tools": [{"type": "web_search"}]}',  # a duplicate key
        b'{"model": "m", "max_tokens": NaN}',
        b'\xef\xbb\xbf{"model": "m"}',  # a BOM
        '{"model": "m"}'.encode("utf-16"),
        b'{"model": "\xff"}',  # not UTF-8
        b"[" * 100_000 + b"]" * 100_000,  # nested too deep
        b'{"model": "m", "tools": {"type": "web_search"}}',  # tools not a list
        b'{"model": "m", "tools": ["web_search"]}',  # a tool that is not an object
    ],
)
def test_a_body_that_is_not_the_providers_json_is_refused(raw: bytes) -> None:
    assert refused(openai(raw)) == ("provider_body", ())
    assert refused(anthropic(raw)) == ("provider_body", ())


@pytest.mark.parametrize(
    "headers",
    [
        [("content-type", "text/plain")],
        [("content-type", "multipart/form-data; boundary=x")],
        [("content-type", "application/json"), ("Content-Type", "application/json")],
    ],
)
def test_a_body_sent_as_something_else_than_json_is_refused(headers: list[tuple[str, str]]) -> None:
    assert refused(anthropic(message(), headers=headers)) == ("provider_body", ())


def test_a_get_with_a_body_is_refused() -> None:
    verdict = check_request("openai", "GET", "/v1/models", [], b'{"tools": []}')
    assert refused(verdict) == ("provider_body", ())


def test_the_walk_over_a_body_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provider_tools, "MAX_NODES", 50)
    messages = [{"role": "user", "content": "hi"}] * 60
    assert refused(anthropic(message(messages=messages))) == ("provider_body", ())


# --- only the model endpoints ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "method", "path"),
    [
        ("anthropic", "POST", "/v1/messages/batches"),
        ("anthropic", "POST", "/v1/files"),
        ("anthropic", "POST", "/v1/skills"),
        ("anthropic", "POST", "/v1/chat/completions"),  # not this kind's endpoint
        ("anthropic", "POST", "/v1/agents"),
        ("anthropic", "POST", "/v1/files/../messages"),
        ("anthropic", "POST", "/v1/./messages"),
        ("anthropic", "POST", "/v1//messages"),
        ("anthropic", "POST", "/v1/messages;x"),
        ("anthropic", "POST", "/v1/messages%2fbatches"),
        ("anthropic", "POST", "/v1\\messages"),
        ("anthropic", "PUT", "/v1/messages"),
        ("anthropic", "DELETE", "/v1/models/m"),
        ("anthropic", "GET", "/v1/messages"),
        ("anthropic", "POST", "/v1/models"),
        ("openai", "POST", "/v1/assistants"),
        ("openai", "POST", "/v1/batches"),
        ("openai", "POST", "/v1/vector_stores"),
        ("openai", "POST", "/v1/realtime/sessions"),
        ("openai", "GET", "/v1/realtime"),
        ("openai", "GET", "/v1/responses/resp_1"),
        ("openai", "POST", "/v1/responses/resp_1/cancel"),
        ("openai", "POST", "/v1/messages"),
        ("openai", "HEAD", "/v1/models"),
        ("openai", "CONNECT", "/v1/chat/completions"),
    ],
)
def test_anything_but_a_model_endpoint_is_refused(kind: str, method: str, path: str) -> None:
    body = json.dumps(chat()).encode() if method == "POST" else b""
    verdict = check_request(kind, method, path, JSON, body)
    assert refused(verdict) == ("provider_endpoint", ())


def test_an_upgrade_to_another_protocol_is_refused() -> None:
    headers = [("Upgrade", "websocket"), ("Connection", "Upgrade")]
    verdict = check_request("openai", "GET", "/v1/models", headers, b"")
    assert refused(verdict) == ("provider_endpoint", ())


def test_an_unknown_kind_is_refused() -> None:
    assert refused(check_request("gemini", "POST", "/v1/messages", JSON, b"{}")) == (
        "provider_endpoint",
        (),
    )


# --- after the review of T06-6 --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "path", "body", "name"),
    [
        (
            "anthropic",
            "/v1/messages",
            message(surprise_option={"on": True}),
            "param:surprise_option",
        ),
        (
            "openai",
            "/v1/chat/completions",
            chat(data_sources=[{"type": "x"}]),
            "param:data_sources",
        ),
        ("openai", "/v1/chat/completions", chat(models=["a", "b"]), "param:models"),
        ("openai", "/v1/responses", {"model": "m", "input": "hi", "extra": 1}, "param:extra"),
        ("openai", "/v1/embeddings", {"model": "m", "input": "hi", "tools": []}, "param:tools"),
    ],
)
def test_a_field_the_endpoint_does_not_have_is_refused_by_name(
    kind: str, path: str, body: dict[str, object], name: str
) -> None:
    verdict = check_request(kind, "POST", path, JSON, json.dumps(body).encode())
    assert refused(verdict) == ("provider_side_tool", (name,))


def test_an_unknown_field_can_be_allowed_by_name() -> None:
    body = json.dumps(chat(custom_flag=True)).encode()
    allowed = frozenset({"param:custom_flag"})
    verdict = check_request("openai", "POST", "/v1/chat/completions", JSON, body, allowed=allowed)
    assert verdict == Verdict(None, ("param:custom_flag",))


def test_connectors_are_refused_whatever_the_kind() -> None:
    assert refused(anthropic(message(plugins=[{"id": "web"}]))) == (
        "provider_side_tool",
        ("plugins",),
    )
    assert refused(openai(chat(mcp_servers=[{"url": "x"}]))) == (
        "provider_side_tool",
        ("mcp_servers",),
    )
    assert refused(anthropic(message(model="x/y:online"))) == (
        "provider_side_tool",
        ("search_model",),
    )


def test_only_a_listed_model_goes_on_when_the_provider_lists_them() -> None:
    models = ("claude-x",)
    assert anthropic(message(), models=models) == Verdict(None)
    verdict = anthropic(message(model="another-model"), models=models)
    assert refused(verdict) == ("provider_side_tool", ("model_not_listed",))
    assert refused(anthropic(message(model=7), models=models)) == ("provider_body", ())
    assert anthropic(message(model="anything"), models=()) == Verdict(None)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"model": "m", "messages": [], "tools": [], "Tools": [{"type": "web_search"}]}',
        b'{"model": "m", "messages": [], "tools": [{"type": "function", "Type": "mcp"}]}',
        '{"model": "m", "messages": [], "tooſs": []}'.encode(),  # folds to "tools"
    ],
)
def test_keys_that_differ_only_in_case_are_refused(raw: bytes) -> None:
    assert refused(openai(raw))[0] in {"provider_body", "provider_side_tool"}
    assert openai(raw).reason is not None


def test_a_url_key_in_another_case_is_still_a_url() -> None:
    part = {"type": "image_url", "Image_URL": {"URL": "https://evil.example/a.png"}}
    assert refused(openai(chat(messages=[{"role": "user", "content": [part]}]))) == (
        "provider_side_tool",
        ("url_source",),
    )


def test_a_compressed_body_or_trailers_towards_a_provider_are_refused() -> None:
    gz = [*JSON, ("Content-Encoding", "gzip")]
    assert refused(anthropic(message(), headers=gz)) == ("provider_body", ())
    identity = [*JSON, ("Content-Encoding", "identity")]
    assert anthropic(message(), headers=identity) == Verdict(None)
    with_trailers = anthropic(message(), trailers=[("x-extra", "1")])
    assert refused(with_trailers) == ("provider_body", ())


@pytest.mark.parametrize(
    "header", ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "X-Original-URL",
               "X-Rewrite-URL", "X-Forwarded-Prefix"],
)  # fmt: skip
def test_headers_that_could_change_the_endpoint_are_refused(header: str) -> None:
    headers = [*JSON, (header, "DELETE")]
    assert refused(anthropic(message(), headers=headers)) == ("provider_endpoint", ())


def test_the_node_budget_is_checked_before_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provider_tools, "MAX_NODES", 50)
    raw = b'{"model": "m", "messages": [' + b",".join([b"{}"] * 100) + b"]}"
    assert refused(anthropic(raw)) == ("provider_body", ())


# --- what an agent profile may allow (decision 5 of docs/34; review of the profiles, M3) ---------

# Fields that switch on something on the provider's side (search, retrieval, grounding, a tool,
# a connector, code that runs there, a source it fetches, another model or route): a profile can
# never allow them, whatever their case or spelling. Only the owner can, with
# ``[proxy] allow_provider_tools``.
PROVIDER_SIDE_PARAMS = (
    "search_parameters", "extra_body", "extra_headers", "extra_query", "web_search_options",
    "web_search", "websearch", "search_domain_filter", "search_recency_filter", "enable_search",
    "searchparameters", "retrieval", "retrieval_config", "grounding", "google_search",
    "googlesearchretrieval", "tools", "tool_config", "tool_resources", "functions", "plugins",
    "connectors", "mcp_servers", "mcp", "file_search", "file_ids", "documents", "attachments",
    "data_sources", "datasources", "vector_store_ids", "knowledge_base", "code_execution",
    "code_interpreter", "sandbox", "browse", "browsing", "fetch", "urls", "image_url",
    "citations", "return_citations", "sources", "models", "fallback_models", "route",
    "provider", "prompt_id", "assistant_id", "agent_id", "webhook", "callback_url",
    "live_search", "online", "context_files", "web.search", "x-search", "search:mode",
)  # fmt: skip


@pytest.mark.parametrize("name", PROVIDER_SIDE_PARAMS)
def test_a_profile_never_allows_a_field_that_works_on_the_providers_side(name: str) -> None:
    with pytest.raises(ValueError, match="provider's side") as caught:
        provider_tools.check_profile_param(f"param:{name}")
    assert "allow_provider_tools" in str(caught.value)  # it says who can allow it
    # The owner still can, by its name as the gate reports it.
    assert check_allow_entry(f"param:{name}") == f"param:{name}"


@pytest.mark.parametrize(
    "name", ["diagnostics", "client_metadata", "betas", "anthropic_version", "safety_settings"]
)
def test_a_profile_may_still_allow_a_plain_request_field(name: str) -> None:
    assert provider_tools.check_profile_param(f"param:{name}") == f"param:{name}"
