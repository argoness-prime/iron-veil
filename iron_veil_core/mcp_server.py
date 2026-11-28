"""Zero-dependency Model Context Protocol (MCP) stdio server for Iron Veil.

Implements JSON-RPC 2.0 over stdio using Python 3.10+ stdlib only, supporting both
standard MCP newline-delimited UTF-8 JSON framing (`2024-11-05` / `2025-03-26` /
`2025-06-18`) and `Content-Length` header framing automatically.

Exposed MCP Tools:
  1. `sanitize_untrusted_text` — Strip Unicode Tags, Trojan-Source bidi overrides,
     zero-width steganography, and hidden HTML/CSS prompt-injection blocks.
  2. `quarantine_repo_traps` — Inspect (`dry_run=True`) or quarantine Priority-1
     agent config files and executable `.git/hooks/*` in an untrusted repo clone.
  3. `xray_transcripts` — Offline read-only audit of local Claude Code JSONL
     transcripts for unwindowed file reads and >5-minute prompt-cache idle cliffs.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
from typing import Any, BinaryIO

from . import __version__
from .sanitizer import REPO_TRAP_NAMES, REPO_TRAP_NAMES_LOWER, quarantine_untrusted_repo, scrub_untrusted_text
from .xray import render_text, run_xray

SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB ceiling for file-backed sanitize calls
PACKAGE_ROOT = Path(__file__).resolve().parent.parent

TOOLS_SPEC: tuple[dict[str, Any], ...] = (
    {
        "name": "sanitize_untrusted_text",
        "description": (
            "Strip hidden Unicode Tag ASCII blocks (U+E0000..U+E007F), Trojan-Source bidi overrides, "
            "zero-width steganography, and hidden HTML/CSS prompt-injection payloads from untrusted text "
            "or a local file (<= 2 MiB), returning cleaned text, injection signals, and a nonce-wrapped envelope."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Raw untrusted text or HTML to sanitize. Provide either `text` or `path`.",
                },
                "path": {
                    "type": "string",
                    "description": "Path to a local untrusted file (<= 2 MiB) to read and sanitize when `text` is omitted.",
                },
                "source_label": {
                    "type": "string",
                    "description": "Short provenance label recorded in the XML nonce wrapper (default: 'external').",
                    "default": "external",
                },
                "strip_html": {
                    "type": "boolean",
                    "description": "Strip HTML tags and decode entities after removing hidden DOM injection blocks.",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "title": "Sanitize Untrusted Text",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "quarantine_repo_traps",
        "description": (
            "Inspect or disarm Priority-1 coding-agent configuration traps (.agents/, .claude/, .cursor/, "
            "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .windsurfrules) and active .git/hooks/* inside "
            "an untrusted local repository clone."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_dir": {
                    "type": "string",
                    "description": "Path to the cloned untrusted repository directory.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "When true, list detected trap paths without moving any files.",
                    "default": False,
                },
            },
            "required": ["repo_dir"],
            "additionalProperties": False,
        },
        "annotations": {
            "title": "Quarantine Untrusted Repo Traps",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "xray_transcripts",
        "description": (
            "Run a 100% offline, read-only diagnostic on local Claude Code JSONL transcripts to quantify "
            "unwindowed file reads (>350 lines), >5-minute prompt-cache idle cliffs, and largest tool-output "
            "context offenders without exposing file contents, shell commands, or full paths."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Transcript directory or .jsonl file path (defaults to ~/.claude/projects).",
                },
                "days": {
                    "type": "integer",
                    "description": "Only scan transcripts modified within the last N days (0 = all).",
                    "default": 7,
                    "minimum": 0,
                },
                "max_files": {
                    "type": "integer",
                    "description": "Maximum number of newest transcript files to scan (0 = unlimited).",
                    "default": 500,
                    "minimum": 0,
                },
                "read_threshold": {
                    "type": "integer",
                    "description": "Line count above which an unwindowed Read call is counted as bloat.",
                    "default": 350,
                    "minimum": 1,
                },
                "idle_seconds": {
                    "type": "integer",
                    "description": "Idle gap in seconds above which a subsequent cache rewrite counts as an idle cliff.",
                    "default": 300,
                    "minimum": 1,
                },
                "top": {
                    "type": "integer",
                    "description": "Number of largest tool-output offenders to return (1..50).",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 50,
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "text"],
                    "description": "Output representation ('json' or human-readable 'text').",
                    "default": "json",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "title": "X-Ray Claude Code Transcripts",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
)


class _ToolParamError(ValueError):
    """Raised when tool arguments fail schema/type validation."""


def _is_protected_directory(target: Path) -> str | None:
    """Prevent accidental quarantine of filesystem roots, user home, or Iron Veil itself."""
    resolved = target.resolve()
    if resolved == resolved.anchor or str(resolved) == resolved.drive + "\\":
        return "Refusing to quarantine filesystem root directory."
    if resolved.parent == resolved:
        return "Refusing to quarantine filesystem root directory."
    try:
        home = Path.home().resolve()
        if resolved == home:
            return "Refusing to quarantine the user home directory directly; pass a specific cloned repo subdirectory."
    except Exception:
        pass
    if resolved == PACKAGE_ROOT:
        return "Refusing to quarantine Iron Veil's own package directory."
    return None


def _inspect_repo_traps_dry_run(repo_dir: Path) -> dict[str, Any]:
    root = repo_dir.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Repository directory does not exist: {root.name or 'target'}")
    found: list[dict[str, str]] = []
    seen: set[Path] = set()

    for rel in REPO_TRAP_NAMES:
        p = root / rel
        if (p.exists() or p.is_symlink()) and p not in seen:
            seen.add(p)
            found.append({"path": str(p.relative_to(root)), "kind": "agent_config"})

    for sub in root.rglob("*"):
        try:
            rel_parts = sub.relative_to(root).parts
        except ValueError:
            continue
        if not rel_parts or rel_parts[0] in (".git", "_iron_veil_quarantine", "node_modules", ".venv"):
            continue
        if sub.name.lower() in REPO_TRAP_NAMES_LOWER and sub not in seen:
            seen.add(sub)
            found.append({"path": str(sub.relative_to(root)), "kind": "agent_config"})

    git_hooks_dir = root / ".git" / "hooks"
    if git_hooks_dir.is_dir():
        for hook in git_hooks_dir.iterdir():
            if (hook.is_file() or hook.is_symlink()) and not hook.name.endswith(".sample"):
                found.append({"path": str(hook.relative_to(root)), "kind": "git_hook"})

    return {
        "ok": True,
        "dryRun": True,
        "detectedCount": len(found),
        "items": found,
    }


def _call_sanitize(args: dict[str, Any]) -> dict[str, Any]:
    has_text = "text" in args and args["text"] is not None
    has_path = "path" in args and args["path"] is not None
    if not has_text and not has_path:
        raise _ToolParamError("Either `text` or `path` must be provided.")
    if has_text and not isinstance(args["text"], str):
        raise _ToolParamError("`text` must be a string.")
    if has_path and not isinstance(args["path"], str):
        raise _ToolParamError("`path` must be a string.")

    strip_html = bool(args.get("strip_html", False))
    source_label = str(args.get("source_label") or "external")

    if has_text:
        raw = args["text"]
    else:
        fp = Path(args["path"]).expanduser().resolve()
        if not fp.is_file():
            raise FileNotFoundError(f"File not found: {fp.name}")
        size = fp.stat().st_size
        if size > MAX_SCAN_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_SCAN_FILE_BYTES} byte limit ({size} bytes).")
        raw = fp.read_text(encoding="utf-8", errors="replace")
        if args.get("source_label") is None:
            source_label = fp.name
        if "strip_html" not in args and fp.suffix.lower() in (".html", ".htm", ".xhtml", ".svg"):
            strip_html = True

    res = scrub_untrusted_text(raw, source_label=source_label, strip_html=strip_html)
    payload = {
        "ok": True,
        "cleanedText": res.cleaned_text,
        **res.to_dict(),
    }
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "structuredContent": payload,
        "isError": False,
    }


def _call_quarantine(args: dict[str, Any]) -> dict[str, Any]:
    repo_dir_raw = args.get("repo_dir")
    if not isinstance(repo_dir_raw, str) or not repo_dir_raw.strip():
        raise _ToolParamError("`repo_dir` must be a non-empty string.")
    target = Path(repo_dir_raw).expanduser().resolve()
    guard_err = _is_protected_directory(target)
    if guard_err:
        raise PermissionError(guard_err)

    dry_run = bool(args.get("dry_run", False))
    if dry_run:
        payload = _inspect_repo_traps_dry_run(target)
    else:
        if not target.is_dir():
            raise FileNotFoundError(f"Repository directory does not exist: {target.name or 'target'}")
        raw_res = quarantine_untrusted_repo(target)
        # Omit full machine-specific path from MCP output; return directory basename + relative items
        payload = {
            "ok": bool(raw_res.get("ok", True)),
            "dryRun": False,
            "repoName": target.name,
            "quarantinedCount": raw_res.get("quarantinedCount", 0),
            "items": raw_res.get("items", []),
        }
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "structuredContent": payload,
        "isError": False,
    }


def _call_xray(args: dict[str, Any]) -> dict[str, Any]:
    path_arg = args.get("path")
    if path_arg is not None and not isinstance(path_arg, str):
        raise _ToolParamError("`path` must be a string when provided.")

    def _int_param(key: str, default: int, minimum: int, maximum: int | None = None) -> int:
        val = args.get(key, default)
        if isinstance(val, bool) or not isinstance(val, int):
            raise _ToolParamError(f"`{key}` must be an integer.")
        if val < minimum or (maximum is not None and val > maximum):
            raise _ToolParamError(f"`{key}` out of allowed range.")
        return val

    days = _int_param("days", 7, 0)
    max_files = _int_param("max_files", 500, 0)
    read_threshold = _int_param("read_threshold", 350, 1)
    idle_seconds = _int_param("idle_seconds", 300, 1)
    top_n = _int_param("top", 5, 1, 50)
    fmt = str(args.get("format", "json"))
    if fmt not in ("json", "text"):
        raise _ToolParamError("`format` must be 'json' or 'text'.")

    rep = run_xray(
        path_arg,
        days=days,
        max_files=max_files,
        read_line_threshold=read_threshold,
        idle_cliff_seconds=idle_seconds,
        top_n=top_n,
    )
    structured = {"ok": True, **rep.to_dict(upsell=False)}
    text_out = render_text(rep, upsell=False) if fmt == "text" else json.dumps(structured, indent=2)
    return {
        "content": [{"type": "text", "text": text_out}],
        "structuredContent": structured,
        "isError": False,
    }


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_rpc_message(msg: Any) -> dict[str, Any] | None:
    """Process a single parsed JSON-RPC 2.0 object. Returns None for notifications."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        req_id = msg.get("id") if isinstance(msg, dict) and "id" in msg else None
        return _jsonrpc_error(req_id, -32600, "Invalid JSON-RPC 2.0 request.")

    method = msg.get("method")
    if not isinstance(method, str) or not method:
        return _jsonrpc_error(msg.get("id"), -32600, "Missing string `method` in request.")

    is_notification = "id" not in msg
    req_id = msg.get("id")
    params = msg.get("params")
    if params is None:
        params = {}
    elif not isinstance(params, dict):
        if is_notification:
            return None
        return _jsonrpc_error(req_id, -32602, "`params` must be a JSON object.")

    if is_notification:
        # Notifications (e.g., notifications/initialized, notifications/cancelled) never emit a response.
        return None

    if method == "initialize":
        requested_ver = str(params.get("protocolVersion") or "")
        negotiated = requested_ver if requested_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "iron-veil", "version": __version__},
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": list(TOOLS_SPEC)})

    if method == "resources/list":
        return _jsonrpc_result(req_id, {"resources": []})

    if method == "prompts/list":
        return _jsonrpc_result(req_id, {"prompts": []})

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments") or {}
        if not isinstance(tool_name, str) or not tool_name:
            return _jsonrpc_error(req_id, -32602, "Missing string tool `name`.")
        if not isinstance(tool_args, dict):
            return _jsonrpc_error(req_id, -32602, "Tool `arguments` must be an object.")

        dispatch = {
            "sanitize_untrusted_text": _call_sanitize,
            "quarantine_repo_traps": _call_quarantine,
            "xray_transcripts": _call_xray,
        }
        handler = dispatch.get(tool_name)
        if handler is None:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")

        try:
            res = handler(tool_args)
            return _jsonrpc_result(req_id, res)
        except _ToolParamError as exc:
            return _jsonrpc_error(req_id, -32602, str(exc))
        except Exception as exc:
            err_payload = {"ok": False, "error": str(exc)}
            return _jsonrpc_result(
                req_id,
                {
                    "content": [{"type": "text", "text": json.dumps(err_payload)}],
                    "structuredContent": err_payload,
                    "isError": True,
                },
            )

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def process_payload(raw_bytes: bytes) -> bytes | None:
    """Parse raw UTF-8 JSON-RPC request/batch bytes and return serialized UTF-8 response bytes (or None)."""
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        err = _jsonrpc_error(None, -32700, "Parse error: invalid JSON.")
        return json.dumps(err, separators=(",", ":")).encode("utf-8")

    if isinstance(parsed, list):
        if not parsed:
            err = _jsonrpc_error(None, -32600, "Empty JSON-RPC batch.")
            return json.dumps(err, separators=(",", ":")).encode("utf-8")
        responses = [r for item in parsed if (r := handle_rpc_message(item)) is not None]
        if not responses:
            return None
        return json.dumps(responses, separators=(",", ":")).encode("utf-8")

    resp = handle_rpc_message(parsed)
    if resp is None:
        return None
    return json.dumps(resp, separators=(",", ":")).encode("utf-8")


def serve_stdio(stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    """Run the stdio MCP message loop supporting newline-delimited JSON and Content-Length headers."""
    in_stream = stdin if stdin is not None else sys.stdin.buffer
    out_stream = stdout if stdout is not None else sys.stdout.buffer

    while True:
        line = in_stream.readline()
        if not line:
            break

        stripped = line.strip()
        if not stripped:
            continue

        # Detect LSP/legacy Content-Length header framing
        if stripped.lower().startswith(b"content-length:"):
            try:
                length = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                err_bytes = json.dumps(_jsonrpc_error(None, -32700, "Invalid Content-Length header.")).encode("utf-8")
                out_stream.write(f"Content-Length: {len(err_bytes)}\r\n\r\n".encode("ascii") + err_bytes)
                out_stream.flush()
                continue

            # Consume remaining headers up to blank line
            while True:
                hdr_line = in_stream.readline()
                if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                    break

            if length < 0 or length > 16 * 1024 * 1024:
                err_bytes = json.dumps(_jsonrpc_error(None, -32600, "Content-Length out of bounds.")).encode("utf-8")
                out_stream.write(f"Content-Length: {len(err_bytes)}\r\n\r\n".encode("ascii") + err_bytes)
                out_stream.flush()
                continue

            body = in_stream.read(length)
            if not body:
                break
            resp_bytes = process_payload(body)
            if resp_bytes is not None:
                header = f"Content-Length: {len(resp_bytes)}\r\n\r\n".encode("ascii")
                out_stream.write(header + resp_bytes)
                out_stream.flush()
        else:
            # Standard MCP stdio framing: one UTF-8 JSON message per newline
            resp_bytes = process_payload(stripped)
            if resp_bytes is not None:
                out_stream.write(resp_bytes + b"\n")
                out_stream.flush()

    return 0


def main() -> int:
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
