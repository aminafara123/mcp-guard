import json
from pathlib import Path

from mcpguard.report import to_json, to_markdown
from mcpguard.scanner import load_manifest, scan_manifest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _result():
    return scan_manifest(load_manifest(SAMPLES / "manifest_risky.json"))


def test_json_is_valid_and_roundtrips():
    parsed = json.loads(to_json(_result()))
    assert parsed["risk_rating"] == "critical"
    assert isinstance(parsed["findings"], list) and parsed["findings"]


def test_markdown_contains_key_sections():
    md = to_markdown(_result())
    assert "# MCP-Guard scan report" in md
    assert "Overall risk rating" in md
    assert "run_shell" in md  # a risky tool appears in the findings table
    assert "human must review" in md  # honesty footer


def test_markdown_labels_ai_summary():
    md = to_markdown(_result(), ai_summary="Looks risky.")
    assert "AI-GENERATED" in md
    assert "Looks risky." in md


def test_safe_manifest_markdown_says_no_findings():
    result = scan_manifest(load_manifest(SAMPLES / "manifest_safe.json"))
    assert "No risky tools" in to_markdown(result)
