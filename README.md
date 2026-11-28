# Iron Veil (Open-Core)

**Zero-dependency indirect prompt-injection sanitizer, Priority-1 untrusted repository trap quarantiner, offline Claude Code transcript `xray` auditor, and local `stdio` MCP server.**

When you open an untrusted repository, GitHub issue, or scraped webpage inside **Claude Code**, **Google Antigravity**, **Cursor**, or any **Model Context Protocol (MCP)** client, hidden delivery vectors can hijack your agent before you read a single line of code:
- **Priority-1 Repo Traps:** `.agents/hooks.json`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and executable `.git/hooks/*` load at higher priority than global user settings.
- **Invisible Unicode Smuggling:** Unicode Tag ASCII blocks (`U+E0000`–`U+E007F`), Trojan-Source bidirectional overrides (`CVE-2021-42574`), and zero-width steganography.
- **Hidden DOM Lures:** `display:none`, `opacity:0`, `font-size:0`, `aria-hidden="true"`, HTML comments, and `<script type="application/ld+json">` payloads.

`iron-veil-core` strips these delivery vectors in `<2 ms` using pure Python 3.10+ stdlib and wraps untrusted text in randomized per-call XML nonces.

## Quickstart

```bash
# Run instantly via uvx (zero clone required):
uvx --from https://github.com/argoness-prime/iron-veil/releases/download/v1.3.0/iron_veil_core-1.3.0-py3-none-any.whl iron-veil-core selftest

# Install as an Agent Skill (Claude Code, Cursor, Codex, Antigravity):
npx skills add argoness-prime/iron-veil

# Or install via Claude Code Plugin Marketplace:
/plugin marketplace add argoness-prime/iron-veil

# Or install directly via pip:
pip install git+https://github.com/argoness-prime/iron-veil.git
iron-veil-core selftest
```

### Run as a Local MCP Server (`stdio`, Zero Dependencies)

`iron-veil-core mcp` (or `iron-veil-mcp`) exposes `sanitize_untrusted_text`, `quarantine_repo_traps`, and `xray_transcripts` over standard JSON-RPC 2.0 `stdio` with zero external runtime packages:

```bash
# Register in Claude Code:
claude mcp add iron-veil -- iron-veil-core mcp
```

Or add to `.mcp.json` / `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "iron-veil": {
      "command": "iron-veil-core",
      "args": ["mcp"]
    }
  }
}
```

### Quarantine an External Repo Before Opening It in Your Agent
```bash
git -c core.hooksPath=/dev/null -c protocol.file.allow=never clone --depth 1 <repo_url> ./sandbox
iron-veil-core quarantine-repo ./sandbox
```

### Sanitize Untrusted Issues, Diffs, or Scraped HTML
```bash
iron-veil-core scan-file issue.html --strip-html
```

### X-Ray Your Local Claude Code Transcripts (10-second, 100% offline)
Find out where your context actually goes, without uploading anything. `xray` reads the JSONL transcripts Claude Code already keeps in `~/.claude/projects` and reports:
- **Unwindowed file reads:** `Read` calls with no `limit` that pulled in more than 350 lines.
- **Prompt-cache idle cliffs:** gaps longer than 5 minutes that were followed by a full cache-prefix re-write (more tokens written to the cache than read from it).
- **Top 5 tool-output bloat offenders:** the largest tool results pushed into context. Only file basenames are shown; contents, shell commands, and full paths are never printed.
- **Illustrative client-side waste** at configurable public list-price assumptions.

```bash
iron-veil-core xray                       # last 7 days of ~/.claude/projects
iron-veil-core xray --days 30 --top 10    # wider window
iron-veil-core xray path/to/session.jsonl --json --no-upsell
```

> `xray` is a client-side diagnostic only; it is **not a billing cap**. It cannot see server-side usage accounting or plan limits. Subscription plans are not billed per token, so the dollar figure is illustrative.

## Verification

Run the built-in 11-vector sanitizer and repo-trap self-test or the full `pytest` suite locally with zero network calls:

```bash
iron-veil-core selftest
pytest -q
```

## Architecture & Companion Tools

Maintained by **Veristrux Inc.** ([veristrux.com](https://veristrux.com/)).

- **MIT License:** Pure Python 3.10+ stdlib, zero external dependencies, zero network calls.
- **MCP Registry Identifier:** `mcp-name: io.github.argoness-prime/iron-veil`
- **Official MCP Registry (`io.github.argoness-prime/iron-veil`):** [Live Registry Entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.argoness-prime%2Firon-veil/versions/latest) · [HOL Plugin Registry](https://hol.org/registry/plugins)
- **Interactive Browser AST Symbol-Map & Cache-Curve Lab (0-signup, client-side):** https://veristrux.com/tokenczar-demo.html
- **AST Symbol-Map Benchmark Reference:** [Standalone Python AST Mapper Gist](https://gist.github.com/argoness-prime/7a1a08eaaf97d0db4964b431fac3d878) · [1080p AST Windowing Demo](https://youtu.be/Zr55UqFz7aw) · [9:16 Short](https://www.youtube.com/shorts/rlzhbMHmoQ0)
- **Full Veristrux Systems Catalog (ViewDrift UE 5.9, Token Czar v2.0 & Toolkits):** https://veristrux.com/
- **Contact:** `argoness@veristrux.com`
