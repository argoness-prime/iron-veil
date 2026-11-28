# LLM / Autonomous Agent Installation Guide (`iron-veil` v1.3.0)

This guide enables autonomous coding agents (such as **Cline**, **Claude Code**, **Cursor**, and **Google Antigravity**) to install and verify the `iron-veil` local `stdio` MCP server in one step with **zero external runtime dependencies** and **zero API keys required**.

## Prerequisites

- **Python `>= 3.10`** (`python` or `python3` on `PATH`, or `uvx` if `uv` is installed).
- **API Keys / Secrets Required:** None (`100%` local execution, zero network calls at runtime).

## Option A — Zero-Clone `uvx` Configuration (Recommended if `uvx` is installed)

If `uvx` is available (`uvx --version`), no installation step is needed. Add the following entry directly to the MCP client settings JSON (`cline_mcp_settings.json`, `.mcp.json`, or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "iron-veil": {
      "command": "uvx",
      "args": [
        "--from",
        "https://github.com/argoness-prime/iron-veil/releases/download/v1.3.0/iron_veil_core-1.3.0-py3-none-any.whl",
        "iron-veil-core",
        "mcp"
      ]
    }
  }
}
```

## Option B — Pure-Python Wheel Installation via `pip` (Works Everywhere)

1. Install the deterministic pure-Python PEP 427 wheel directly from the official GitHub Release:

```bash
python -m pip install --no-deps https://github.com/argoness-prime/iron-veil/releases/download/v1.3.0/iron_veil_core-1.3.0-py3-none-any.whl
```

2. Verify the installation (`11/11` offline security vector self-test):

```bash
python -m iron_veil_core selftest
```

3. Register the MCP server using `python -m iron_veil_core mcp` (using `python -m` avoids `Scripts`/`bin` PATH issues on Windows, macOS, and Linux):

```json
{
  "mcpServers": {
    "iron-veil": {
      "command": "python",
      "args": ["-u", "-m", "iron_veil_core", "mcp"]
    }
  }
}
```

## Exposed MCP Tools (`stdio` JSON-RPC 2.0)

1. `sanitize_untrusted_text` — Strips invisible Unicode Tag blocks (`U+E0000`–`U+E007F`), Trojan-Source bidi overrides (`CVE-2021-42574`), zero-width characters, and hidden HTML/CSS DOM lures in `<2 ms`, wrapping output in randomized per-call XML nonces.
2. `quarantine_repo_traps` — Audits and optionally quarantines Priority-1 untrusted repository hook/config traps (`.agents/hooks.json`, `.claude/settings.json`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.mcp.json`, `.git/hooks/*`).
3. `xray_transcripts` — Offline local Claude Code JSONL session auditor reporting unwindowed file reads (`>350` lines), prompt-cache idle cliffs (`>5 min`), and top tool-output bloat basenames without reading or transmitting file contents.
