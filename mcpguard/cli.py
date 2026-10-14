"""mcp-guard CLI.

    mcpguard scan   <manifest.json> [--json OUT] [--md OUT] [--summarize]
    mcpguard lint   <manifest.json> --policy policy.yaml   # exit 1 on any DENY
"""
import argparse
import sys

from . import report
from .policy import decide_tool, has_denial, lint_manifest, load_policy
from .scanner import ManifestError, load_manifest, scan_manifest


def _cmd_scan(args):
    try:
        manifest = load_manifest(args.manifest)
    except (ManifestError, OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    result = scan_manifest(manifest)
    ai_summary = None
    if args.summarize:
        from . import llm  # imported lazily so the scanner never needs it
        ai_summary = llm.summarize_findings(result)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(report.to_json(result))
        print("wrote %s" % args.json)
    md = report.to_markdown(result, ai_summary)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(md)
        print("wrote %s" % args.md)
    if not args.json and not args.md:
        print(md)
    # non-zero exit if anything critical/high so `scan` is also CI-usable
    return 1 if result["risk_rating"] in ("critical", "high") else 0


def _cmd_lint(args):
    try:
        manifest = load_manifest(args.manifest)
    except (ManifestError, OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    policy = load_policy(args.policy)
    decisions = lint_manifest(policy, manifest)
    for d in decisions:
        print("%-6s %-24s %s" % (d["decision"], d["tool"], d["reason"]))
    if has_denial(decisions):
        print("\nPOLICY GATE: DENY (one or more tools violate policy)")
        return 1
    print("\nPOLICY GATE: PASS")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="mcpguard", description="Security scanner + policy linter for MCP servers.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a manifest for risky tools")
    s.add_argument("manifest")
    s.add_argument("--json", help="write JSON findings to this path")
    s.add_argument("--md", help="write Markdown report to this path")
    s.add_argument("--summarize", action="store_true", help="add an AI summary (needs a local LLM)")
    s.set_defaults(func=_cmd_scan)

    l = sub.add_parser("lint", help="check a manifest against an allow/deny policy (CI gate)")
    l.add_argument("manifest")
    l.add_argument("--policy", required=True, help="YAML policy file")
    l.set_defaults(func=_cmd_lint)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
