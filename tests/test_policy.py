from pathlib import Path

from mcpguard.cli import main
from mcpguard.policy import decide_tool, has_denial, lint_manifest, load_policy
from mcpguard.proxy import gate_call
from mcpguard.scanner import load_manifest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
POL = {"default": "deny", "allow_tools": ["read_file"], "deny_capabilities": ["shell", "env"]}


def test_allowlisted_tool_allowed():
    assert decide_tool(POL, "read_file", [])[0] == "ALLOW"


def test_unknown_tool_denied_by_default():
    assert decide_tool(POL, "mystery", [])[0] == "DENY"


def test_deny_capability_overrides_allowlist():
    assert decide_tool(POL, "read_file", ["shell:exec"])[0] == "DENY"


def test_default_allow():
    assert decide_tool({"default": "allow"}, "anything", [])[0] == "ALLOW"


def test_lint_risky_manifest_has_denial():
    pol = load_policy(SAMPLES / "policy.yaml")
    decisions = lint_manifest(pol, load_manifest(SAMPLES / "manifest_risky.json"))
    assert has_denial(decisions)


def test_lint_safe_manifest_passes():
    pol = load_policy(SAMPLES / "policy.yaml")
    decisions = lint_manifest(pol, load_manifest(SAMPLES / "manifest_safe.json"))
    assert not has_denial(decisions)


# --- exit-code gating via CLI -------------------------------------------
def test_cli_lint_exit_nonzero_on_deny(capsys):
    rc = main(["lint", str(SAMPLES / "manifest_risky.json"),
               "--policy", str(SAMPLES / "policy.yaml")])
    assert rc == 1


def test_cli_lint_exit_zero_when_clean(capsys):
    rc = main(["lint", str(SAMPLES / "manifest_safe.json"),
               "--policy", str(SAMPLES / "policy.yaml")])
    assert rc == 0


def test_cli_scan_exit_nonzero_on_critical(capsys):
    rc = main(["scan", str(SAMPLES / "manifest_risky.json")])
    assert rc == 1


# --- proxy gate ----------------------------------------------------------
def test_proxy_gate_forwards_allowed():
    forward, _ = gate_call(POL, {"name": "read_file", "arguments": {}})
    assert forward is True


def test_proxy_gate_drops_denied_capability():
    forward, _ = gate_call(POL, {"name": "run"}, {"run": ["shell:exec"]})
    assert forward is False
