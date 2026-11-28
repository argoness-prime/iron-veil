"""Iron Veil X-Ray: offline audit of local Claude Code transcripts for client-side token waste.

Read-only and zero-dependency (stdlib only). It never prints file contents, shell commands or
full paths. It reports:

1. Unwindowed file reads: ``Read`` calls with no ``limit`` that returned more than N lines.
2. Prompt-cache idle cliffs: gaps of more than 5 minutes between consecutive API calls in one
   transcript, where the next call re-wrote the cache prefix (``cache_creation_input_tokens``).
3. The five largest tool outputs that were pushed into context.
4. An illustrative dollar estimate based on configurable public list-price assumptions.

This is a client-side diagnostic only. It is not a billing cap and cannot see server-side usage
accounting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
import os
from pathlib import Path
import time
from typing import Any, Iterable, Iterator

DEFAULT_READ_LINE_THRESHOLD = 350
DEFAULT_IDLE_CLIFF_SECONDS = 300
CHARS_PER_TOKEN = 4.0

UPSELL_LINES = (
    "Local engineering tools & docs: https://veristrux.com/",
    "Client-side diagnostic only; not a billing cap.",
)
DISCLAIMER_LINE = "Client-side diagnostic only; not a billing cap."


@dataclass
class Offender:
    tool: str
    label: str
    chars: int
    lines: int
    session: str

    @property
    def tokens(self) -> int:
        return int(round(self.chars / CHARS_PER_TOKEN))


@dataclass
class XrayReport:
    root_label: str
    days: int
    files_scanned: int = 0
    files_skipped: int = 0
    lines_parsed: int = 0
    api_calls: int = 0
    input_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0
    reads_total: int = 0
    reads_unwindowed: int = 0
    unwindowed_read_tokens: int = 0
    avoidable_read_tokens: int = 0
    idle_gaps: int = 0
    idle_cliffs: int = 0
    cliff_rewrite_tokens: int = 0
    worst_gap_seconds: float = 0.0
    tool_result_tokens: int = 0
    offenders: list[Offender] = field(default_factory=list)
    read_line_threshold: int = DEFAULT_READ_LINE_THRESHOLD
    idle_cliff_seconds: int = DEFAULT_IDLE_CLIFF_SECONDS
    input_usd_per_mtok: float = 3.0
    cache_write_usd_per_mtok: float = 3.75
    cache_read_usd_per_mtok: float = 0.30

    def illustrative_waste_usd(self) -> dict[str, float]:
        reads = self.avoidable_read_tokens / 1e6 * self.input_usd_per_mtok
        cliff_premium = max(0.0, self.cache_write_usd_per_mtok - self.cache_read_usd_per_mtok)
        cliffs = self.cliff_rewrite_tokens / 1e6 * cliff_premium
        return {
            "unwindowedReadsUsd": round(reads, 2),
            "cacheCliffPremiumUsd": round(cliffs, 2),
            "totalUsd": round(reads + cliffs, 2),
        }

    def to_dict(self, *, upsell: bool = True) -> dict[str, Any]:
        return {
            "root": self.root_label,
            "days": self.days,
            "filesScanned": self.files_scanned,
            "filesSkipped": self.files_skipped,
            "linesParsed": self.lines_parsed,
            "apiCalls": self.api_calls,
            "tokens": {
                "input": self.input_tokens,
                "cacheWrite": self.cache_write_tokens,
                "cacheRead": self.cache_read_tokens,
                "output": self.output_tokens,
                "toolResultsEstimated": self.tool_result_tokens,
            },
            "unwindowedReads": {
                "thresholdLines": self.read_line_threshold,
                "readsTotal": self.reads_total,
                "readsUnwindowed": self.reads_unwindowed,
                "tokensReturnedEstimated": self.unwindowed_read_tokens,
                "tokensAvoidableEstimated": self.avoidable_read_tokens,
            },
            "cacheIdleCliffs": {
                "thresholdSeconds": self.idle_cliff_seconds,
                "idleGaps": self.idle_gaps,
                "count": self.idle_cliffs,
                "cacheWriteTokensAfterCliffs": self.cliff_rewrite_tokens,
                "worstGapSeconds": round(self.worst_gap_seconds, 1),
            },
            "topOffenders": [
                {
                    "tool": o.tool,
                    "label": o.label,
                    "lines": o.lines,
                    "tokensEstimated": o.tokens,
                    "session": o.session,
                }
                for o in self.offenders
            ],
            "illustrativeWaste": {
                **self.illustrative_waste_usd(),
                "assumptions": {
                    "inputUsdPerMTok": self.input_usd_per_mtok,
                    "cacheWriteUsdPerMTok": self.cache_write_usd_per_mtok,
                    "cacheReadUsdPerMTok": self.cache_read_usd_per_mtok,
                    "charsPerToken": CHARS_PER_TOKEN,
                },
                "note": "Illustrative only; subscription plans are not billed per token and actual billing differs.",
            },
            "disclaimer": DISCLAIMER_LINE,
            "upgrade": list(UPSELL_LINES[:1]) if upsell else [],
        }


def default_root() -> Path:
    return Path.home() / ".claude" / "projects"


def _long_path(p: str) -> str:
    """Return a Windows extended-length path so deep Claude Code subagent dirs stay readable."""
    if os.name != "nt":
        return p
    ap = os.path.abspath(p)
    if ap.startswith("\\\\?\\"):
        return ap
    if ap.startswith("\\\\"):
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap


def iter_transcripts(root: Path, *, days: int, max_files: int, now: float | None = None) -> tuple[list[str], int]:
    """Return (newest-first .jsonl paths within the window, count of unreadable entries)."""
    now = time.time() if now is None else now
    cutoff = now - days * 86400 if days > 0 else None
    skipped = 0
    found: list[tuple[float, str]] = []
    root_s = str(root)
    if os.path.isfile(_long_path(root_s)):
        return [_long_path(root_s)], 0

    def _onerror(_exc: OSError) -> None:
        nonlocal skipped
        skipped += 1

    for dirpath, _dirnames, filenames in os.walk(_long_path(root_s), onerror=_onerror):
        for fn in filenames:
            if not fn.endswith(".jsonl"):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                mt = os.path.getmtime(fp)
            except OSError:
                skipped += 1
                continue
            if cutoff is not None and mt < cutoff:
                continue
            found.append((mt, fp))
    found.sort(reverse=True)
    if max_files > 0:
        found = found[:max_files]
    return [fp for _, fp in found], skipped


def _parse_ts(raw: Any) -> float | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _content_chars_lines(content: Any) -> tuple[int, int]:
    if isinstance(content, str):
        return len(content), content.count("\n") + (1 if content else 0)
    if isinstance(content, list):
        chars = lines = 0
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                txt = str(block.get("text") or "")
                chars += len(txt)
                lines += txt.count("\n") + (1 if txt else 0)
        return chars, lines
    return 0, 0


def _safe_label(tool: str, tool_input: dict[str, Any]) -> str:
    """Describe a tool call without leaking contents, commands, or full paths."""
    if tool in ("Read", "Edit", "Write", "NotebookEdit"):
        fp = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        name = fp.replace("\\", "/").rstrip("/").split("/")[-1]
        return name[:60] or "(file)"
    if tool == "Bash":
        return "(shell output)"
    if tool in ("Grep", "Glob"):
        return "(search results)"
    return "(tool output)"


def _iter_lines(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line


def scan_transcripts(
    paths: Iterable[str],
    *,
    root_label: str = "",
    days: int = 7,
    read_line_threshold: int = DEFAULT_READ_LINE_THRESHOLD,
    idle_cliff_seconds: int = DEFAULT_IDLE_CLIFF_SECONDS,
    top_n: int = 5,
    input_usd_per_mtok: float = 3.0,
    cache_write_usd_per_mtok: float = 3.75,
    cache_read_usd_per_mtok: float = 0.30,
) -> XrayReport:
    rep = XrayReport(
        root_label=root_label,
        days=days,
        read_line_threshold=read_line_threshold,
        idle_cliff_seconds=idle_cliff_seconds,
        input_usd_per_mtok=input_usd_per_mtok,
        cache_write_usd_per_mtok=cache_write_usd_per_mtok,
        cache_read_usd_per_mtok=cache_read_usd_per_mtok,
    )
    offenders: list[Offender] = []

    for path in paths:
        try:
            lines = _iter_lines(path)
            seen_msg_ids: set[str] = set()
            seen_results: set[str] = set()
            tool_uses: dict[str, tuple[str, dict[str, Any]]] = {}
            last_call_ts: float | None = None
            for line in lines:
                # Cheap pre-filter: only assistant usage records and tool_use/tool_result traffic matter.
                if '"usage"' not in line and '"tool_use' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                if not isinstance(rec, dict):
                    continue
                rtype = rec.get("type")
                if rtype not in ("assistant", "user"):
                    continue  # skip api-request blobs and metadata (they duplicate content)
                rep.lines_parsed += 1
                msg = rec.get("message")
                if not isinstance(msg, dict):
                    continue
                session = str(rec.get("sessionId") or "")[:8] or "unknown"
                content = msg.get("content")

                if rtype == "assistant":
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_use":
                                tid = str(block.get("id") or "")
                                tin = block.get("input") if isinstance(block.get("input"), dict) else {}
                                if tid:
                                    tool_uses[tid] = (str(block.get("name") or "tool"), tin)
                    mid = str(msg.get("id") or rec.get("requestId") or rec.get("uuid") or "")
                    usage = msg.get("usage")
                    if not isinstance(usage, dict) or (mid and mid in seen_msg_ids):
                        continue
                    if mid:
                        seen_msg_ids.add(mid)
                    rep.api_calls += 1
                    cw = int(usage.get("cache_creation_input_tokens") or 0)
                    cr = int(usage.get("cache_read_input_tokens") or 0)
                    rep.input_tokens += int(usage.get("input_tokens") or 0)
                    rep.cache_write_tokens += cw
                    rep.cache_read_tokens += cr
                    rep.output_tokens += int(usage.get("output_tokens") or 0)
                    ts = _parse_ts(rec.get("timestamp"))
                    if ts is not None:
                        if last_call_ts is not None:
                            gap = ts - last_call_ts
                            if gap > idle_cliff_seconds:
                                rep.idle_gaps += 1
                            # A cliff is an idle gap followed by a prefix re-write: more tokens written
                            # to cache than read from it, so the cached prefix was not reused.
                            if gap > idle_cliff_seconds and cw > 0 and cw > cr:
                                rep.idle_cliffs += 1
                                rep.cliff_rewrite_tokens += cw
                                rep.worst_gap_seconds = max(rep.worst_gap_seconds, gap)
                        last_call_ts = ts
                    continue

                # user records: tool results
                if not isinstance(content, list):
                    continue
                tur = rec.get("toolUseResult") if isinstance(rec.get("toolUseResult"), dict) else {}
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    tid = str(block.get("tool_use_id") or "")
                    if tid:
                        if tid in seen_results:
                            continue  # resumed/forked sessions can replay the same tool_result record
                        seen_results.add(tid)
                    tool, tin = tool_uses.get(tid, ("tool", {}))
                    chars, nlines = _content_chars_lines(block.get("content"))
                    rep.tool_result_tokens += int(round(chars / CHARS_PER_TOKEN))
                    if tool == "Read":
                        rep.reads_total += 1
                        fmeta = tur.get("file") if isinstance(tur.get("file"), dict) else {}
                        num_lines = fmeta.get("numLines")
                        if isinstance(num_lines, int) and num_lines > 0:
                            nlines = num_lines
                        windowed = tin.get("limit") is not None
                        if not windowed and nlines > read_line_threshold:
                            rep.reads_unwindowed += 1
                            toks = int(round(chars / CHARS_PER_TOKEN))
                            rep.unwindowed_read_tokens += toks
                            keep_ratio = read_line_threshold / float(nlines)
                            rep.avoidable_read_tokens += int(round(toks * (1.0 - keep_ratio)))
                    if chars > 0:
                        offenders.append(Offender(tool, _safe_label(tool, tin), chars, nlines, session))
            rep.files_scanned += 1
        except OSError:
            rep.files_skipped += 1

    offenders.sort(key=lambda o: o.chars, reverse=True)
    rep.offenders = offenders[: max(0, top_n)]
    return rep


def _fmt_tok(n: float) -> str:
    n = float(n)
    if n >= 1e9:
        return f"{n / 1e9:.2f}B"
    if n >= 1e6:
        return f"{n / 1e6:.2f}M"
    if n >= 1e3:
        return f"{n / 1e3:.1f}K"
    return f"{int(n)}"


def _fmt_gap(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 60:.0f}m"


def render_text(rep: XrayReport, *, upsell: bool = True) -> str:
    w = rep.illustrative_waste_usd()
    window = f"last {rep.days} days" if rep.days > 0 else "all time"
    out = [
        "Iron Veil X-Ray: local Claude Code transcript audit (offline, read-only)",
        f"Scanned: {rep.files_scanned} transcripts ({window}) | {rep.api_calls:,} API calls"
        + (f" | {rep.files_skipped} unreadable skipped" if rep.files_skipped else ""),
        f"Tokens recorded in transcripts: input {_fmt_tok(rep.input_tokens)} | cache write "
        f"{_fmt_tok(rep.cache_write_tokens)} | cache read {_fmt_tok(rep.cache_read_tokens)} | output "
        f"{_fmt_tok(rep.output_tokens)}",
        "",
        f"[1] Unwindowed file reads (>{rep.read_line_threshold} lines, no limit): "
        f"{rep.reads_unwindowed} of {rep.reads_total} reads",
        f"    ~{_fmt_tok(rep.unwindowed_read_tokens)} tokens returned; "
        f"~{_fmt_tok(rep.avoidable_read_tokens)} avoidable with {rep.read_line_threshold}-line windowing",
        f"[2] Prompt-cache idle cliffs (>{rep.idle_cliff_seconds // 60} min gap, then cache re-write): "
        f"{rep.idle_cliffs} of {rep.idle_gaps} idle gaps",
        f"    ~{_fmt_tok(rep.cliff_rewrite_tokens)} cache-write tokens after cliffs"
        + (f" (worst gap {_fmt_gap(rep.worst_gap_seconds)})" if rep.idle_cliffs else ""),
        f"[3] Top {len(rep.offenders)} tool-output bloat offenders:",
    ]
    if not rep.offenders:
        out.append("    (none found)")
    for i, o in enumerate(rep.offenders, 1):
        out.append(
            f"    {i}. {o.tool:<6} {o.label:<32} {o.lines:>7,} lines  ~{_fmt_tok(o.tokens):>7} tok  (session {o.session})"
        )
    out += [
        f"[4] Illustrative client-side waste: ~${w['totalUsd']:.2f} "
        f"(reads ${w['unwindowedReadsUsd']:.2f} + cache cliffs ${w['cacheCliffPremiumUsd']:.2f})",
        f"    Assumes ${rep.input_usd_per_mtok:.2f}/MTok input, ${rep.cache_write_usd_per_mtok:.2f}/MTok cache write, "
        f"${rep.cache_read_usd_per_mtok:.2f}/MTok cache read. Subscription plans are not billed per token.",
        "",
    ]
    out += list(UPSELL_LINES) if upsell else [DISCLAIMER_LINE]
    return "\n".join(out)


def run_xray(
    path: str | None = None,
    *,
    days: int = 7,
    max_files: int = 500,
    **scan_kwargs: Any,
) -> XrayReport:
    root = Path(path).expanduser() if path else default_root()
    if not os.path.exists(_long_path(str(root))):
        raise FileNotFoundError(f"transcript path not found: {root.name or root}")
    files, walk_skipped = iter_transcripts(root, days=days, max_files=max_files)
    rep = scan_transcripts(files, root_label=root.name or str(root), days=days, **scan_kwargs)
    rep.files_skipped += walk_skipped
    return rep
