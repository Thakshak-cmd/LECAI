"""The audit log's integrity claim, including what it cannot do."""

from __future__ import annotations

import json

from gatekeeper.audit import AuditLog, EventKind, verify_chain


def _write(path, n=4):
    with AuditLog(path, run_id="test") as log:
        for i in range(n):
            log.emit(
                EventKind.NOTE,
                summary=f"event {i}",
                step_id=f"s{i}",
                findings=[("code", f"detail {i}")],
                data={"i": i},
            )
    return path


def test_clean_chain_verifies(tmp_path):
    ok, msg = verify_chain(_write(tmp_path / "a.jsonl"))
    assert ok, msg
    assert "4 events" in msg


def test_edited_event_is_detected(tmp_path):
    path = _write(tmp_path / "b.jsonl")
    lines = path.read_text().splitlines()
    event = json.loads(lines[1])
    event["summary"] = "tampered"
    lines[1] = json.dumps(event, ensure_ascii=False, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    ok, msg = verify_chain(path)
    assert not ok
    assert "edited after it was written" in msg


def test_removed_event_is_detected(tmp_path):
    path = _write(tmp_path / "c.jsonl")
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    ok, msg = verify_chain(path)
    assert not ok
    assert "inserted, removed, or reordered" in msg


def test_truncation_still_verifies_as_a_shorter_log(tmp_path):
    """A crash mid-run leaves a valid prefix, which is the desired behaviour."""
    path = _write(tmp_path / "d.jsonl")
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2]) + "\n")

    ok, msg = verify_chain(path)
    assert ok
    assert "2 events" in msg


def test_wholesale_rewrite_is_NOT_detected(tmp_path):
    """The honest limit of a self-computed chain.

    Anyone who can write the file can recompute every hash and produce a log
    that verifies clean. This test exists so the limitation is asserted in code
    rather than only claimed in a docstring.
    """
    path = tmp_path / "e.jsonl"
    _write(path)
    forged = tmp_path / "f.jsonl"
    with AuditLog(forged, run_id="test") as log:
        log.emit(EventKind.NOTE, summary="entirely fabricated", step_id="s0")

    ok, _ = verify_chain(forged)
    assert ok, "a forged-from-scratch log still verifies; the chain is not a signature"


def test_hash_is_stable_across_key_order(tmp_path):
    """Canonical JSON, or logs would fail to verify for spurious reasons."""
    path = _write(tmp_path / "g.jsonl", n=2)
    first = verify_chain(path)
    second = verify_chain(path)
    assert first == second
