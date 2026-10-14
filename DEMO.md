# 60-second demo script

Goal: show mcp-guard catching a malicious MCP server and failing a CI gate.

## Setup (before recording)

```bash
pip install -r requirements.txt
clear
```

## Recording (~60s)

1. **Show it's real and tested (0:00–0:10)**
   ```bash
   pytest -q
   ```
   Point at the green line: `29 passed`. Deterministic core, no network, no API key.

2. **Scan the deliberately malicious manifest (0:10–0:30)**
   ```bash
   python -m mcpguard scan samples/manifest_risky.json
   ```
   Call out the `CRITICAL` rating, `run_shell` (MCP001 shell exec), and
   `helpful_assistant` (MCP007 — "ignore previous instructions" hidden in the description).

3. **Run the policy gate (0:30–0:45)**
   ```bash
   python -m mcpguard lint samples/manifest_risky.json --policy samples/policy.yaml ; echo "exit=$?"
   ```
   Show `POLICY GATE: DENY` and `exit=1` — this is what fails a CI pipeline.

4. **Contrast with the safe manifest (0:45–0:60)**
   ```bash
   python -m mcpguard lint samples/manifest_safe.json --policy samples/policy.yaml ; echo "exit=$?"
   ```
   `POLICY GATE: PASS`, `exit=0`. Same tool, clean server, green.

## Optional closer

```bash
python -m mcpguard scan samples/manifest_risky.json --json out.json --md out.md
```
Show the Markdown report and JSON findings on disk (`out.md`, `out.json`).
