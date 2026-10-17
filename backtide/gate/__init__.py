"""The proxy's gate: what the agent may send out, and what gets recorded of it.

The modules here are pure (policy, providers, record, sse, protocol) and never import
mitmproxy, so they are tested with plain dicts. The mitmproxy addon (T06-4) is a thin layer
on top of them. Design and rationale: docs/21-diseno-t06-proxy.md.
"""
