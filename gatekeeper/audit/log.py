"""The audit trail: append-only JSONL, one event per line, hash-chained.

This file is the actual deliverable. The agent's behaviour is only as good as a
reviewer's ability to reconstruct *why* it did what it did, so every event
carries the evidence the decision was made from -- not just the outcome.

Two conventions make the log readable rather than merely complete:

1. **Every event names its step and its parent step.** That turns a flat file
   into a tree: you can see that this SCREEN happened because of that FETCH,
   and that DECIDE rests on those two CONSISTENCY checks.

2. **Reasoning is a list of discrete findings, not a sentence.** Each finding
   is `(code, detail)`. Codes are greppable and countable; details are for the
   human. A reviewer disagreeing with one finding can point at exactly which.

## On the hash chain -- what it does and does not do

Each line commits to the one before it, so editing or deleting an event in the
middle of a finished log breaks `verify` at that point. That is genuinely
useful: it catches truncation, accidental corruption, and a careless edit.

It is **not** tamper-proof. Anyone who can write the file can recompute the
whole chain from the edit forward and produce a log that verifies clean. Making
that impossible needs a key the writer does not hold, or an external witness --
neither of which is here. The chain is an integrity check, not a signature, and
this docstring exists so nobody mistakes it for one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


class EventKind(str, Enum):
    """The vocabulary of the log. Kept small so it stays skimmable."""

    RUN_START = "RUN_START"
    RUN_END = "RUN_END"

    #: An HTTP request left the process (or was served from a cassette).
    FETCH = "FETCH"
    #: A candidate item was extracted from a response and normalised.
    OBSERVE = "OBSERVE"
    #: An item was classified as data / instruction / ambiguous.
    SCREEN = "SCREEN"
    #: A claim was checked against another field or another source.
    CONSISTENCY = "CONSISTENCY"
    #: The planner chose what to do next, and why.
    PLAN = "PLAN"
    #: A final verdict was reached for one item.
    DECIDE = "DECIDE"
    #: Model budget spent, or a strategy downgrade forced by budget.
    BUDGET = "BUDGET"
    #: Anything else worth recording, including things that went wrong.
    NOTE = "NOTE"


@dataclass
class Event:
    seq: int
    ts: str
    run_id: str
    kind: str
    step_id: str
    parent_step_id: str | None
    summary: str
    findings: list[dict[str, str]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    hash: str = ""

    def payload(self) -> dict[str, Any]:
        """Everything the hash commits to -- i.e. the event minus its own hash."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "run_id": self.run_id,
            "kind": self.kind,
            "step_id": self.step_id,
            "parent_step_id": self.parent_step_id,
            "summary": self.summary,
            "findings": self.findings,
            "data": self.data,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return compute_hash(self.payload())

    def to_json(self) -> str:
        record = self.payload()
        record["hash"] = self.hash
        return json.dumps(record, ensure_ascii=False, sort_keys=True)


def compute_hash(payload: dict[str, Any]) -> str:
    """Hash of an event payload.

    `sort_keys` and a fixed separator make this stable across Python versions
    and dict insertion order -- otherwise a log written today would fail to
    verify tomorrow for reasons that have nothing to do with tampering.
    """
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only writer. Flushes every line, so a crash still leaves a
    readable, verifiable prefix rather than an empty file."""

    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        self._seq = 0
        self._prev = GENESIS
        self._fh = None
        path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> "AuditLog":
        self._fh = self.path.open("w", encoding="utf-8")
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def emit(
        self,
        kind: EventKind | str,
        summary: str,
        *,
        step_id: str,
        parent_step_id: str | None = None,
        findings: list[tuple[str, str]] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Event:
        if self._fh is None:
            raise RuntimeError("AuditLog used outside its context manager")

        self._seq += 1
        event = Event(
            seq=self._seq,
            ts=datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            run_id=self.run_id,
            kind=kind.value if isinstance(kind, EventKind) else str(kind),
            step_id=step_id,
            parent_step_id=parent_step_id,
            summary=summary,
            findings=[{"code": c, "detail": d} for c, d in (findings or [])],
            data=data or {},
            prev_hash=self._prev,
        )
        event.hash = event.compute_hash()
        self._prev = event.hash

        self._fh.write(event.to_json() + "\n")
        self._fh.flush()
        return event


def read_events(path: Path) -> Iterator[Event]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        yield Event(
            seq=raw["seq"],
            ts=raw["ts"],
            run_id=raw["run_id"],
            kind=raw["kind"],
            step_id=raw["step_id"],
            parent_step_id=raw.get("parent_step_id"),
            summary=raw["summary"],
            findings=raw.get("findings", []),
            data=raw.get("data", {}),
            prev_hash=raw["prev_hash"],
            hash=raw.get("hash", ""),
        )


def verify_chain(path: Path) -> tuple[bool, str]:
    """Re-hash every event and confirm each links to the one before it.

    Returns the first breakage rather than a count, because the first is the
    one that tells you where the file stopped being trustworthy.
    """
    prev = GENESIS
    count = 0

    for event in read_events(path):
        count += 1

        if event.prev_hash != prev:
            return False, (
                f"event {event.seq} ({event.kind}) claims prev_hash "
                f"{event.prev_hash[:12]}… but the previous event hashed to {prev[:12]}… "
                f"-- an event was inserted, removed, or reordered here"
            )

        recomputed = event.compute_hash()
        if recomputed != event.hash:
            return False, (
                f"event {event.seq} ({event.kind}) does not match its own hash "
                f"-- stored {event.hash[:12]}…, recomputed {recomputed[:12]}… "
                f"-- this event's contents were edited after it was written"
            )

        prev = event.hash

    if count == 0:
        return False, "log is empty"

    return True, f"{count} events, chain intact, head {prev[:12]}…"
