# Iron Veil (Open-Core)

**Zero-dependency indirect prompt-injection sanitizer & Priority-1 untrusted repository trap quarantiner for AI coding agents.**

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

---

## Open-Core vs. Veristrux Pro Kits

| Capability | `iron-veil-core` (MIT Free) | **Iron Veil + Token Miser Pro Kit ($5)** | **All-Access Agent & Silicon Bundle ($12)** |
| :--- | :---: | :---: | :---: |
| Unicode Tag / Bidi / Hidden-HTML Sanitizer | Yes | Yes | Yes |
| Priority-1 Repo & Git-Hook Quarantiner | Yes | Yes | Yes |
| **Real-Time `<5 ms` `PreToolUse` Firewall** (`Claude Code` + `Antigravity`) | — | **Yes** | **Yes** |
| **Secret/Cookie Airgap + Exfil & `curl\|sh` RCE Block + Write Confinement** | — | **Yes** | **Yes** |
| **Token Miser AST Symbol-Map Read Guard** (40–70% prompt-cache savings) | — | **Yes** | **Yes** |
| **Full 19-Vector Firewall + Sanitizer Benchmark (`iron-veil selftest`)** | 11 Core | **19/19 Full** | **19/19 Full** |
| **Hybrid Silicon Local-AI Tuner** (GPU VRAM + DDR5 `--n-cpu-moe` + TTFT/TPS bench) | — | — | **Yes** |

Get the commercial Pro packages & same-day engineering rescue:
- **Storefront & Same-Day $5 Express Bugfix Desk:** https://argoness-prime.github.io/veristrux/
- **Iron Veil + Token Miser Pro Kit ($5):** https://www.paypal.com/ncp/payment/BCJT85K2YHUYS
- **Hybrid Silicon Local-AI Tuner ($9):** https://www.paypal.com/ncp/payment/X9AGQCZUJF7R6
- **All-Access Agent & Silicon Bundle ($12):** https://www.paypal.com/ncp/payment/FTR3BGX8V6LEJ
- **Contact:** `argoness@veristrux.com`
