"""Portable Multi-Layer Indirect Prompt-Injection Sanitizer & Repo Trap Quarantiner.

Zero external dependencies (Python 3.10+ stdlib only). Neutralizes:
  1. Invisible Unicode Tag ASCII smuggling (U+E0000..U+E007F)
  2. Trojan-Source Bidi overrides (CVE-2021-42574: U+202A..U+202E, U+2066..U+2069)
  3. Zero-width steganography (U+200B..U+200F, U+2060..U+2064, U+FEFF)
  4. Hidden HTML/CSS/SVG/comment payloads (`display:none`, `opacity:0`, `font-size:0`, `aria-hidden`, etc.)
  5. Closing-tag breakout attacks via randomized per-call boundary nonces
  6. Priority-1 untrusted repo rule/hook hijacks (`.agents/`, `.claude/`, `.cursor/`, `AGENTS.md`, `.git/hooks`)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import html
from pathlib import Path
import re
import secrets
import shutil
import stat
from typing import Any

INVISIBLE_SMUGGLE_RE = re.compile(
    "["
    "\u200b-\u200f"
    "\u202a-\u202e"
    "\u2060-\u2064"
    "\u2066-\u2069"
    "\ufeff"
    "\U000e0000-\U000e007f"
    "]"
)
BIDI_OVERRIDE_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
UNICODE_TAG_RE = re.compile("[\U000e0000-\U000e007f]")

HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?(?:-->|$)", re.IGNORECASE)
HTML_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript|template|svg)\b[^>]*>[\s\S]*?(?:</\1\s*>|$)",
    re.IGNORECASE,
)
HIDDEN_STYLE_OPEN_RE = re.compile(
    r"<([a-z][a-z0-9:-]*)\b[^>]*\bstyle\s*=\s*(['\"])[^'\"]*?"
    r"(?:display\s*:\s*none\b|"
    r"visibility\s*:\s*hidden\b|"
    r"opacity\s*:\s*0(?:\.0+)?(?=\s*(?:;|!important|['\"]|$))|"
    r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?(?=\s*(?:;|!important|['\"]|$))|"
    r"color\s*:\s*transparent\b|"
    r"clip-path\s*:\s*inset\(\s*100%\s*\)|"
    r"(?:left|top|text-indent)\s*:\s*-\d{4,}px)"
    r"[^'\"]*?\2[^>]*>",
    re.IGNORECASE,
)
HIDDEN_ATTR_OPEN_RE = re.compile(
    r"<([a-z][a-z0-9:-]*)\b[^>]*"
    r"(?:\bhidden(?:\s*=\s*(?:['\"][^'\"]*['\"]|[^\s>]+))?(?=[\s/>])|"
    r"\baria-hidden\s*=\s*(?:['\"]true['\"]|true(?=[\s/>])))"
    r"[^>]*>",
    re.IGNORECASE,
)
GENERIC_TAG_RE = re.compile(r"<[^>]+>")
CLOSING_BOUNDARY_RE = re.compile(r"<\s*/\s*untrusted_external_data", re.IGNORECASE)

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:(?:all|any|the|your|these|those)\s+)?"
            r"(?:(?:previous|prior|above|preceding|earlier|existing|original|initial|system|developer|safety|security)\s+){1,3}"
            r"(?:instructions?|prompts?|rules?|directives?|guardrails?|constraints?|policies?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_tag_spoof",
        re.compile(
            r"</?(?:system_message|user_request|system_instruction|tool_call|function_call|antml:thinking)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_header_spoof",
        re.compile(
            r"(?:^|\n)\s*(?:SYSTEM\s*OVERRIDE|NEW\s+SYSTEM\s+PROMPT|ADMIN\s+DIRECTIVE|IMPORTANT\s+AI\s+INSTRUCTION)\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_harvest",
        re.compile(
            r"\b(?:sk_live_[0-9a-zA-Z]+|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{20,}|id_rsa|id_ed25519|Login\s+Data)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "exfil_directive",
        re.compile(
            r"\b(?:webhook\.site|requestbin|pipedream\.(?:com|net)|oastify\.com|interact\.sh|transfer\.sh|0x0\.st)\b|"
            r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]{0,120}\b(?:-d|--data|-Body)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "memory_laundering",
        re.compile(
            r"\b(?:permanently\s+remember\s+to\s+always|write\s+to\s+memory\s+forever|save\s+global\s+override)\b",
            re.IGNORECASE,
        ),
    ),
)

REPO_TRAP_NAMES: tuple[str, ...] = (
    ".agents",
    ".agent",
    "_agents",
    "_agent",
    ".claude",
    ".cursor",
    "AGENTS.md",
    "GEMINI.md",
    "CLAUDE.md",
    ".cursorrules",
    ".windsurfrules",
)
REPO_TRAP_NAMES_LOWER: frozenset[str] = frozenset(name.lower() for name in REPO_TRAP_NAMES)


def _strip_balanced_elements(text: str, open_re: re.Pattern[str]) -> tuple[str, int]:
    """Removes elements whose opening tag matches `open_re`, tracking nested same-name tags."""
    stripped = 0
    out: list[str] = []
    pos = 0
    n = len(text)

    while pos < n:
        match = open_re.search(text, pos)
        if not match:
            out.append(text[pos:])
            break

        out.append(text[pos : match.start()])
        out.append(" ")
        stripped += 1

        open_tag = match.group(0)
        if open_tag.rstrip().endswith("/>"):
            pos = match.end()
            continue

        tag_name = re.escape(match.group(1))
        tag_token_re = re.compile(rf"<(/?){tag_name}\b[^>]*>", re.IGNORECASE)
        depth = 1
        cursor = match.end()
        while depth > 0:
            tok = tag_token_re.search(text, cursor)
            if not tok:
                cursor = n
                break
            is_close = bool(tok.group(1))
            is_self_close = tok.group(0).rstrip().endswith("/>")
            if is_close:
                depth -= 1
            elif not is_self_close:
                depth += 1
            cursor = tok.end()
        pos = cursor

    return "".join(out), stripped


@dataclass
class SanitizeResult:
    cleaned_text: str
    wrapped_text: str
    nonce: str
    invisible_chars_stripped: int = 0
    hidden_html_blocks_stripped: int = 0
    signals: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals) or self.invisible_chars_stripped >= 8

    def to_dict(self) -> dict[str, Any]:
        return {
            "suspicious": self.suspicious,
            "signals": list(self.signals),
            "invisibleCharsStripped": self.invisible_chars_stripped,
            "hiddenHtmlBlocksStripped": self.hidden_html_blocks_stripped,
            "nonce": self.nonce,
            "wrappedText": self.wrapped_text,
        }


def detect_injection_signals(text: str) -> list[str]:
    return [name for name, rx in INJECTION_PATTERNS if rx.search(text or "")]


def scrub_untrusted_text(
    raw: str,
    *,
    source_label: str = "external",
    strip_html: bool = False,
) -> SanitizeResult:
    text = raw or ""
    has_bidi = bool(BIDI_OVERRIDE_RE.search(text))
    unicode_tag_count = len(UNICODE_TAG_RE.findall(text))
    signals_raw = detect_injection_signals(text)

    invisible_matches = INVISIBLE_SMUGGLE_RE.findall(text)
    invisible_count = len(invisible_matches)
    if invisible_count:
        text = INVISIBLE_SMUGGLE_RE.sub("", text)

    # Re-scan after invisible-char stripping (and entity decode if HTML entities appear)
    # before hidden DOM blocks are removed so split-word stego inside comments/divs is flagged.
    signals_pre = list(dict.fromkeys([*signals_raw, *detect_injection_signals(text)]))
    if "&" in text and ";" in text:
        signals_pre = list(dict.fromkeys([*signals_pre, *detect_injection_signals(html.unescape(text))]))

    hidden_blocks = 0
    if strip_html or ("<" in text and ">" in text):
        for rx in (HTML_COMMENT_RE, HTML_SCRIPT_STYLE_RE):
            matches = rx.findall(text)
            if matches:
                hidden_blocks += len(matches)
                text = rx.sub(" ", text)
        for open_rx in (HIDDEN_STYLE_OPEN_RE, HIDDEN_ATTR_OPEN_RE):
            text, count = _strip_balanced_elements(text, open_rx)
            hidden_blocks += count
        if strip_html:
            text = GENERIC_TAG_RE.sub(" ", text)
            text = html.unescape(text)
            text = re.sub(r"[ \t]{2,}", " ", text)
            text = re.sub(r"\n{3,}", "\n\n", text)

    signals_post = detect_injection_signals(text)
    merged_signals = list(dict.fromkeys([*signals_pre, *signals_post]))
    if has_bidi and "bidi_override" not in merged_signals:
        merged_signals.append("bidi_override")
    if (invisible_count >= 8 or unicode_tag_count >= 4) and "unicode_tag_smuggling" not in merged_signals:
        merged_signals.append("unicode_tag_smuggling")
    if hidden_blocks > 0 and signals_pre and not signals_post:
        merged_signals.append("hidden_dom_injection_stripped")

    nonce = secrets.token_hex(8)
    safe_body = CLOSING_BOUNDARY_RE.sub("< /untrusted_external_data", text)
    safe_source = re.sub(r"[^a-zA-Z0-9_.:/@-]+", "_", source_label)[:80]
    alert_attr = f' warning="SUSPICIOUS:{",".join(merged_signals)}"' if merged_signals else ""
    wrapped = (
        f'<untrusted_external_data nonce="{nonce}" source="{safe_source}"{alert_attr}>\n'
        f"{safe_body.strip()}\n"
        f"</untrusted_external_data_{nonce}>"
    )

    return SanitizeResult(
        cleaned_text=safe_body.strip(),
        wrapped_text=wrapped,
        nonce=nonce,
        invisible_chars_stripped=invisible_count,
        hidden_html_blocks_stripped=hidden_blocks,
        signals=merged_signals,
    )


def quarantine_untrusted_repo(repo_dir: str | Path) -> dict[str, Any]:
    """Moves Priority-1 agent customization traps and active git hooks into `_iron_veil_quarantine/`."""
    root = Path(repo_dir).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Repository directory does not exist: {root}")

    q_dir = root / "_iron_veil_quarantine"
    quarantined: list[dict[str, str]] = []
    candidates: list[Path] = []
    seen: set[Path] = set()

    for rel in REPO_TRAP_NAMES:
        p = root / rel
        if (p.exists() or p.is_symlink()) and p not in seen:
            candidates.append(p)
            seen.add(p)

    for sub in root.rglob("*"):
        try:
            rel_parts = sub.relative_to(root).parts
        except ValueError:
            continue
        if not rel_parts or rel_parts[0] in (".git", "_iron_veil_quarantine", "node_modules", ".venv"):
            continue
        if sub.name.lower() in REPO_TRAP_NAMES_LOWER and sub not in seen:
            candidates.append(sub)
            seen.add(sub)

    for item in candidates:
        if not item.exists() and not item.is_symlink():
            continue
        rel_str = str(item.relative_to(root))
        safe_dest_name = rel_str.replace("\\", "__").replace("/", "__").lstrip(".")
        dest = q_dir / f"trap_{safe_dest_name}.quarantined"
        q_dir.mkdir(parents=True, exist_ok=True)
        if dest.exists() or dest.is_symlink():
            if dest.is_dir() and not dest.is_symlink():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        shutil.move(str(item), str(dest))
        quarantined.append({"original": rel_str, "quarantinedTo": str(dest.relative_to(root)), "kind": "agent_config"})

    git_hooks_dir = root / ".git" / "hooks"
    if git_hooks_dir.is_dir():
        for hook in git_hooks_dir.iterdir():
            if (hook.is_file() or hook.is_symlink()) and not hook.name.endswith(".sample"):
                q_dir.mkdir(parents=True, exist_ok=True)
                dest = q_dir / f"githook_{hook.name}.quarantined"
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                shutil.move(str(hook), str(dest))
                if not dest.is_symlink():
                    try:
                        dest.chmod(stat.S_IREAD | stat.S_IWRITE)
                    except OSError:
                        pass
                quarantined.append(
                    {"original": f".git/hooks/{hook.name}", "quarantinedTo": str(dest.relative_to(root)), "kind": "git_hook"}
                )

    return {
        "ok": True,
        "repo": str(root),
        "quarantinedCount": len(quarantined),
        "quarantined": quarantined,
    }
