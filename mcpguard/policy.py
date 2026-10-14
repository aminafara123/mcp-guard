"""Allow/deny policy linter for MCP manifests, plus the proxy gate function.

Policy file (YAML):

    default: deny            # decision for tools not matched by a rule
    allow_tools:            # explicit allowlist of tool names
      - read_file
      - search_docs
    deny_capabilities:      # any tool declaring one of these is denied
      - shell
      - exec
      - filesystem:write

The same pure `decide_tool` function backs both the CI linter and the
documented proxy gateway (see proxy design in README).
"""
import yaml


def load_policy(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def decide_tool(policy, tool_name, capabilities=None):
    """Pure allow/deny decision for one tool / one tool call.

    Returns (decision, reason) where decision is "ALLOW" or "DENY".
    This is the exact function a proxy gateway would call per invocation.
    """
    caps = [str(c).lower() for c in (capabilities or [])]
    deny_caps = [str(c).lower() for c in policy.get("deny_capabilities", [])]
    for c in caps:
        for d in deny_caps:
            if d in c:  # substring: "shell" matches "shell:exec"
                return "DENY", "capability '%s' matches deny rule '%s'" % (c, d)
    if tool_name in (policy.get("allow_tools") or []):
        return "ALLOW", "tool in allowlist"
    if str(policy.get("default", "deny")).lower() == "allow":
        return "ALLOW", "default allow"
    return "DENY", "not in allowlist (default deny)"


def lint_manifest(policy, manifest):
    """Decide every tool in a manifest on its OWN declared capabilities.

    This matches what the proxy gate sees per call, so linter and gateway
    agree. Server-wide capabilities are surfaced by the scanner instead.
    """
    decisions = []
    for tool in manifest.get("tools", []):
        caps = tool.get("capabilities") or []
        decision, reason = decide_tool(policy, tool.get("name", ""), caps)
        decisions.append({"tool": tool.get("name", ""), "decision": decision, "reason": reason})
    return decisions


def has_denial(decisions):
    return any(d["decision"] == "DENY" for d in decisions)


if __name__ == "__main__":  # tiny self-check
    pol = {"default": "deny", "allow_tools": ["read_file"], "deny_capabilities": ["shell"]}
    assert decide_tool(pol, "read_file", [])[0] == "ALLOW"
    assert decide_tool(pol, "whatever", [])[0] == "DENY"
    assert decide_tool(pol, "read_file", ["shell:exec"])[0] == "DENY"  # deny-cap wins
    assert decide_tool({"default": "allow"}, "x", [])[0] == "ALLOW"
    print("policy self-check ok")
