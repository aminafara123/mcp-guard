# override with: make PY=python  (if `python3` is not your interpreter name)
PY ?= python3

.PHONY: install test run lint demo

install:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest -q

# scan the deliberately risky sample manifest
run:
	$(PY) -m mcpguard scan samples/manifest_risky.json

# policy gate (exits non-zero because the risky manifest violates policy)
lint:
	$(PY) -m mcpguard lint samples/manifest_risky.json --policy samples/policy.yaml

# write both report formats for the risky sample
demo:
	$(PY) -m mcpguard scan samples/manifest_risky.json --json risky.report.json --md risky.report.md
