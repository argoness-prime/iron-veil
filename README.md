# Iron Veil (Open-Core)

**Zero-dependency indirect prompt-injection sanitizer & Priority-1 untrusted repository trap quarantiner for AI coding agents.**

<p align="center">
  <img src="https://veristrux.com/media/tokenczar_v2_showcase.gif" alt="Token Czar & Iron Veil AST Windowing Demo" width="100%" />
</p>

> *Demo: Token Czar / Iron Veil AST Symbol-Map windowing (`2.92–3.97 ms`, `77.6%–92.2%` context reduction on 426–1,295 line test files). Local context-hygiene guard — not a provider spend cap. [Watch 1080p Demo](https://youtu.be/NMqtSxDWUho) · [YouTube Short](https://youtube.com/shorts/NjCFj6FedDU) · [Reproducible AST Benchmark Gist](https://gist.github.com/argoness-prime/7a1a08eaaf97d0db4964b431fac3d878)*

When you open an untrusted repository, GitHub issue, or scraped webpage inside **Claude Code**, **Google Antigravity**, or **Cursor**, hidden delivery vectors can hijack your agent before you read a single line of code:
- **Priority-1 Repo Traps:** `.agents/hooks.json`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and executable `.git/hooks/*` load at higher priority than global user settings.
- **Invisible Unicode Smuggling:** Unicode Tag ASCII blocks (`U+E0000`–`U+E007F`), Trojan-Source bidirectional overrides (`CVE-2021-42574`), and zero-width steganography.
- **Hidden DOM Lures:** `display:none`, `opacity:0`, `font-size:0`, `aria-hidden="true"`, HTML comments, and `<script type="application/ld+json">` payloads.

`iron-veil-core` strips these delivery vectors in `<2 ms` using pure Python 3.10+ stdlib and wraps untrusted text in randomized per-call XML nonces.

## Quickstart

```bash
# Install via Claude Code Plugin Marketplace:
/plugin marketplace add argoness-prime/iron-veil

# Or install directly via pip:
pip install git+https://github.com/argoness-prime/iron-veil.git
iron-veil-core selftest
```

### Quarantine an External Repo Before Opening It in Your Agent
```bash
git -c core.hooksPath=/dev/null -c protocol.file.allow=never clone --depth 1 <repo_url> ./sandbox
iron-veil-core quarantine-repo ./sandbox
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

---

## Open-Core vs. Veristrux Pro Kits

| Capability | `iron-veil-core` (MIT Free) | **Iron Veil + Token Miser Pro Kit ($5)** | **All-Access Agent & Silicon Bundle ($12)** |
| :--- | :---: | :---: | :---: |
| Unicode Tag / Bidi / Hidden-HTML Sanitizer | Yes | Yes | Yes |
| Priority-1 Repo & Git-Hook Quarantiner | Yes | Yes | Yes |
| Offline Claude Code Transcript X-Ray (`xray`: read bloat + cache idle cliffs) | Yes | Yes | Yes |
| **Real-Time `<5 ms` `PreToolUse` Firewall** (`Claude Code` + `Antigravity`) | — | **Yes** | **Yes** |
| **Secret/Cookie Airgap + Exfil & `curl\|sh` RCE Block + Write Confinement** | — | **Yes** | **Yes** |
| **Token Miser AST Symbol-Map Read Guard** (`Lstart-Lend` + 80L `[CHUNK]`) | — | **Yes** | **Yes** |
| **Full 19-Vector Firewall + Sanitizer Benchmark (`selftest`)** | 11 Core | **19/19 Full** | **19/19 Full** |
| **Hybrid Silicon Local-AI Tuner** (GPU VRAM + DDR5 `--n-cpu-moe` + TTFT/TPS bench) | — | — | **Yes** |

Get the instant commercial packages & free desktop utility:
- **Iron Veil + Token Miser Pro Kit (`$5` one-time, instant ZIP via `itch.io` MoR):** https://argoness-prime.itch.io/iron-veil-token-miser-pro
- **Free Token Czar v2.0 Lite Desktop Utility (`.exe`, 0 Pro bytes):** https://github.com/argoness-prime/veristrux/releases/tag/tokenczar-v2.0.0
- **Storefront, Hybrid Silicon Tuner ($9) & All-Access Bundle ($12):** https://veristrux.com/
- **Contact:** `argoness@veristrux.com`
