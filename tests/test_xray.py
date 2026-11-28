"""Tests for `iron-veil-core xray` (offline Claude Code transcript audit)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time

import pytest

from iron_veil_core import cli
from iron_veil_core.xray import (
    UPSELL_LINES,
    iter_transcripts,
    render_text,
    run_xray,
    scan_transcripts,
)

SECRET_MARKER = "SUPER_SECRET_TOKEN_abc123"


def _assistant(msg_id: str, ts: str, *, cw: int = 0, cr: int = 0, inp: int = 10, out: int = 5, tool_uses=None, session="sess-aaaa-1111"):
    content = []
    for tid, name, tin in tool_uses or []:
        content.append({"type": "tool_use", "id": tid, "name": name, "input": tin})
    return {
        "type": "assistant",
        "sessionId": session,
        "timestamp": ts,
        "requestId": "req_" + msg_id,
        "message": {
            "id": msg_id,
            "role": "assistant",
            "content": content,
            "usage": {
                "input_tokens": inp,
                "cache_creation_input_tokens": cw,
                "cache_read_input_tokens": cr,
                "output_tokens": out,
            },
        },
    }


def _tool_result(tid: str, text: str, *, num_lines: int | None = None, session="sess-aaaa-1111"):
    rec = {
        "type": "user",
        "sessionId": session,
        "timestamp": "2026-11-27T10:00:00Z",
        "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid, "content": text}]},
    }
    if num_lines is not None:
        rec["toolUseResult"] = {"type": "text", "file": {"numLines": num_lines, "startLine": 1, "totalLines": num_lines}}
    return rec


def _write_jsonl(path: Path, records) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
    return path


@pytest.fixture()
def transcript(tmp_path: Path) -> Path:
    big_file = "\n".join(f"line {i} {SECRET_MARKER}" for i in range(800))
    small_file = "\n".join(f"ok {i}" for i in range(40))
    windowed = "\n".join(f"w {i}" for i in range(600))
    bash_out = "x" * 20000 + SECRET_MARKER
    recs = [
        _assistant("m1", "2026-11-27T10:00:00Z", cw=5000, cr=0,
                   tool_uses=[("t1", "Read", {"file_path": "D:/work/someone/proj/big_module.py"})]),
        # Same message id repeated (Claude Code splits content blocks): must not double count usage.
        _assistant("m1", "2026-11-27T10:00:00Z", cw=5000, cr=0),
        _tool_result("t1", big_file, num_lines=800),
        # Replayed tool_result (resumed session): must not double count.
        _tool_result("t1", big_file, num_lines=800),
        _assistant("m2", "2026-11-27T10:01:00Z", cw=200, cr=5000,
                   tool_uses=[("t2", "Read", {"file_path": "/srv/someone/proj/small.py"})]),
        _tool_result("t2", small_file, num_lines=40),
        _assistant("m3", "2026-11-27T10:02:00Z", cw=100, cr=5200,
                   tool_uses=[("t3", "Read", {"file_path": "/x/windowed.py", "offset": 1, "limit": 600})]),
        _tool_result("t3", windowed, num_lines=600),
        # 10-minute idle gap, then the prefix is re-written (cw > cr): a cache cliff.
        _assistant("m4", "2026-11-27T10:12:00Z", cw=6000, cr=0,
                   tool_uses=[("t4", "Bash", {"command": f"echo {SECRET_MARKER}"})]),
        _tool_result("t4", bash_out),
        # 7-minute idle gap but the cache was reused (cr > cw): not a cliff.
        _assistant("m5", "2026-11-27T10:19:00Z", cw=50, cr=6000),
        # Noise: api-request blob duplicates content and must be ignored; malformed line skipped.
        {"type": "api-request-blob", "message": {"content": [{"type": "tool_use", "id": "zz", "name": "Read", "input": {}}]},
         "usage": {}},
        '{"type": "assistant", "message": {"usage": BROKEN',
    ]
    return _write_jsonl(tmp_path / "projects" / "proj-a" / "s1.jsonl", recs)


def test_scan_counts_usage_reads_cliffs_and_offenders(transcript: Path) -> None:
    rep = scan_transcripts([str(transcript)], root_label="projects", days=0)
    assert rep.files_scanned == 1
    assert rep.api_calls == 5  # m1 deduplicated
    assert rep.cache_write_tokens == 5000 + 200 + 100 + 6000 + 50
    assert rep.cache_read_tokens == 5000 + 5200 + 6000
    assert rep.reads_total == 3
    assert rep.reads_unwindowed == 1  # big_module only; small is under threshold, windowed has limit
    assert rep.unwindowed_read_tokens > 0
    assert 0 < rep.avoidable_read_tokens < rep.unwindowed_read_tokens
    # avoidable fraction == 1 - 350/800
    assert rep.avoidable_read_tokens == pytest.approx(rep.unwindowed_read_tokens * (1 - 350 / 800), abs=2)
    assert rep.idle_gaps == 2
    assert rep.idle_cliffs == 1
    assert rep.cliff_rewrite_tokens == 6000
    assert rep.worst_gap_seconds == pytest.approx(600.0)
    assert [o.tool for o in rep.offenders][:2] == ["Read", "Bash"] or [o.tool for o in rep.offenders][:2] == ["Bash", "Read"]
    assert len(rep.offenders) <= 5


def test_output_never_leaks_contents_commands_or_full_paths(transcript: Path) -> None:
    rep = scan_transcripts([str(transcript)], root_label="projects", days=0)
    text = render_text(rep)
    blob = json.dumps(rep.to_dict())
    for out in (text, blob):
        assert SECRET_MARKER not in out
        assert "someone" not in out
        assert "D:/work" not in out and "/srv/" not in out
        assert "echo" not in out
    assert "big_module.py" in text  # basename only
    assert "(shell output)" in text


def test_render_has_upsell_and_disclaimer_and_no_upsell_flag(transcript: Path) -> None:
    rep = scan_transcripts([str(transcript)], days=0)
    text = render_text(rep)
    assert text.rstrip().endswith("Client-side diagnostic only; not a billing cap.")
    assert UPSELL_LINES[0] in text
    assert "https://veristrux.com/" in text
    assert "$5" not in text
    assert "itch.io" not in text
    quiet = render_text(rep, upsell=False)
    assert "veristrux.com" not in quiet
    assert "not a billing cap" in quiet


def test_illustrative_waste_math(transcript: Path) -> None:
    rep = scan_transcripts([str(transcript)], days=0, input_usd_per_mtok=3.0,
                           cache_write_usd_per_mtok=3.75, cache_read_usd_per_mtok=0.30)
    w = rep.illustrative_waste_usd()
    expected_reads = rep.avoidable_read_tokens / 1e6 * 3.0
    expected_cliffs = 6000 / 1e6 * (3.75 - 0.30)
    assert w["unwindowedReadsUsd"] == round(expected_reads, 2)
    assert w["cacheCliffPremiumUsd"] == round(expected_cliffs, 2)
    assert w["totalUsd"] == round(expected_reads + expected_cliffs, 2)


def test_iter_transcripts_days_filter_and_max_files(tmp_path: Path) -> None:
    root = tmp_path / "projects"
    now = time.time()
    for i in range(4):
        p = _write_jsonl(root / f"p{i}" / f"s{i}.jsonl", [_assistant(f"m{i}", "2026-11-27T10:00:00Z")])
        age_days = [0, 1, 10, 30][i]
        os.utime(p, (now - age_days * 86400, now - age_days * 86400))
    (root / "notes.txt").write_text("ignore me", encoding="utf-8")
    files, skipped = iter_transcripts(root, days=7, max_files=0, now=now)
    assert len(files) == 2 and skipped == 0
    files_all, _ = iter_transcripts(root, days=0, max_files=3, now=now)
    assert len(files_all) == 3
    assert files_all[0].endswith("s0.jsonl")  # newest first


def test_run_xray_single_file_and_missing_path(transcript: Path, tmp_path: Path) -> None:
    rep = run_xray(str(transcript), days=0)
    assert rep.files_scanned == 1 and rep.api_calls == 5
    with pytest.raises(FileNotFoundError):
        run_xray(str(tmp_path / "nope"), days=0)


def test_empty_directory_reports_zero(tmp_path: Path) -> None:
    (tmp_path / "projects").mkdir()
    rep = run_xray(str(tmp_path / "projects"), days=0)
    assert rep.files_scanned == 0 and rep.api_calls == 0
    assert "(none found)" in render_text(rep)


def test_cli_text_and_json(transcript: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["xray", str(transcript.parent.parent), "--days", "0"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Iron Veil X-Ray" in out and "[3] Top" in out
    rc = cli.main(["xray", str(transcript), "--days", "0", "--json", "--no-upsell"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0 and data["ok"] is True
    assert data["cacheIdleCliffs"]["count"] == 1
    assert data["unwindowedReads"]["readsUnwindowed"] == 1
    assert data["upgrade"] == []
    assert data["disclaimer"] == "Client-side diagnostic only; not a billing cap."


def test_cli_missing_path_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["xray", str(tmp_path / "missing"), "--days", "0"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 2 and data["ok"] is False
    assert str(tmp_path) not in data["error"]  # only the final path component is echoed


def test_selftest_still_passes() -> None:
    res = cli.run_core_selftest()
    assert res["ok"] is True and res["score"] == "11/11"
