# Renders docs/demo.gif with charmbracelet/vhs (needs vhs, ttyd and ffmpeg on PATH).
# Run from the repo root, with the deps installed in .venv:  vhs docs/demo.tape
# Follows DEMO.md: tests -> scan the malicious manifest -> policy gate DENY (exit 1) -> safe manifest PASS (exit 0).
Output docs/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms

Hide
Type "VIRTUAL_ENV_DISABLE_PROMPT=1 source .venv/bin/activate"
Enter
Wait@120s
Type "clear"
Enter
Wait@120s
Show
Sleep 500ms

Type "pytest -q"
Sleep 400ms
Enter
Wait@120s
Sleep 2s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "python -m mcpguard scan samples/manifest_risky.json | head -24 | cut -c1-100"
Sleep 400ms
Enter
Wait@120s
Sleep 4.5s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type 'python -m mcpguard lint samples/manifest_risky.json --policy samples/policy.yaml ; echo "exit=$?"'
Sleep 400ms
Enter
Wait@120s
Sleep 3s

Type 'python -m mcpguard lint samples/manifest_safe.json --policy samples/policy.yaml ; echo "exit=$?"'
Sleep 400ms
Enter
Wait@120s
Sleep 3s

Sleep 1s
