"""Thin LLM client. Optional: only used by `scan --summarize`.

Calls an OpenAI-compatible /chat/completions endpoint. Defaults to a local
ollama server. Configured by env only; never hardcode a key. If the endpoint
is unreachable, returns None so callers degrade gracefully (the scanner itself
is pure and needs no LLM).

ponytail: stdlib urllib, no SDK dependency — one POST is all this needs.
"""
import json
import os
import urllib.error
import urllib.request

BASE_URL = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434/v1")
MODEL = os.environ.get("LLM_MODEL", "qwen3:30b-a3b-instruct-2507-q4_K_M")
API_KEY = os.environ.get("LLM_API_KEY", "ollama")


def chat(prompt, system=None, timeout=30):
    """Return the model's text reply, or None if the LLM is unreachable."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = json.dumps({"model": MODEL, "messages": messages, "stream": False}).encode()
    req = urllib.request.Request(
        BASE_URL.rstrip("/") + "/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
        print("[llm] unreachable (%s); skipping AI summary." % e.__class__.__name__)
        return None


def summarize_findings(result):
    """Best-effort plain-language summary of a scan result. None if LLM is down."""
    brief = json.dumps({"risk_rating": result["risk_rating"],
                        "severity_counts": result["severity_counts"],
                        "findings": result["findings"][:20]}, indent=2)
    return chat(
        "Summarize this MCP server security scan for a reviewer in 3-5 sentences. "
        "State the overall risk and the top concerns. Do not invent findings.\n\n" + brief,
        system="You are a security analyst. Be concise and factual.")
