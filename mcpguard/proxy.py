"""Proxy gateway (DESIGN + STUB, not a live proxy).

Intended deployment: a gateway sits inline between an MCP client (the agent)
and an MCP server. Every `tools/call` JSON-RPC message is intercepted; the
gateway looks up the called tool's declared capabilities and runs the same
policy decision used by the CI linter. ALLOW -> forward the call unchanged.
DENY -> never reach the server; return a JSON-RPC error to the client.

    client --call--> [ gateway: gate_call() ] --allow--> server
                              |
                              +--deny--> error back to client

ponytail: this is the decision core only. A production gateway also needs the
stdio/SSE transport bridge, streaming passthrough, per-session auth and audit
logging. Those are the integration layer, not security logic, so they are left
as the documented upgrade path rather than built here.
"""
try:
    from .policy import decide_tool
except ImportError:  # allow running this file directly as a self-check
    from policy import decide_tool

# capabilities the gateway knows for each tool name; in a real deployment this
# is loaded from the scanned manifest at startup.
def gate_call(policy, tool_call, tool_capabilities=None):
    """Decide a single intercepted MCP tool call.

    tool_call: {"name": <tool>, "arguments": {...}} (MCP tools/call params shape)
    tool_capabilities: {tool_name: [capabilities]} known from the manifest.
    Returns (forward: bool, reason: str).
    """
    name = (tool_call or {}).get("name", "")
    caps = (tool_capabilities or {}).get(name, [])
    decision, reason = decide_tool(policy, name, caps)
    return decision == "ALLOW", reason


if __name__ == "__main__":  # tiny self-check
    pol = {"default": "deny", "allow_tools": ["read_file"], "deny_capabilities": ["shell"]}
    assert gate_call(pol, {"name": "read_file", "arguments": {}})[0] is True
    assert gate_call(pol, {"name": "run_shell"}, {"run_shell": ["shell:exec"]})[0] is False
    assert gate_call(pol, {"name": "unknown"})[0] is False
    print("proxy self-check ok")
