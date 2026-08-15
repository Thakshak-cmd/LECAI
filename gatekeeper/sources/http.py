"""Audited HTTP, with record/replay cassettes.

Two jobs, both about making the run inspectable:

1. **Every request is logged before it is used.** A FETCH event records the
   URL, status, byte count and a digest of the body. If a decision later rests
   on that response, a reviewer can tie the two together by digest.

2. **Responses are recorded to disk.** A reviewer can replay a complete run
   with no API key and no network, and get byte-identical inputs to the ones I
   ran against. Public job boards change hourly; without this, "it worked on my
   machine" is unfalsifiable and the eval numbers in the README would be
   unreproducible.

Cassettes are gzipped because the two boards together are ~1.8 MB of JSON, and
a repo a reviewer has to clone should not carry that uncompressed.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

import httpx

from gatekeeper.audit import AuditLog, EventKind

USER_AGENT = (
    "gatekeeper/0.1 (job-board triage agent; "
    "https://github.com/Thakshak-cmd/LECAI)"
)


class Mode(str, Enum):
    #: Replay when a cassette exists, otherwise fetch and record it.
    AUTO = "auto"
    #: Never touch the network. A missing cassette is an error.
    REPLAY = "replay"
    #: Always fetch, always overwrite the cassette.
    RECORD = "record"


class CassetteMiss(RuntimeError):
    """Replay was requested but nothing was recorded for this URL."""


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    body: str
    fetched_at: str
    from_cassette: bool

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body.encode("utf-8")).hexdigest()

    def json(self):
        return json.loads(self.body)


def _slug(url: str) -> str:
    """A filename that is both human-recognisable and collision-free."""
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    host = url.split("//", 1)[-1].split("/", 1)[0].replace(".", "-")
    return f"{host}-{digest}.json.gz"


class Fetcher:
    """HTTP client that logs what it did and can run entirely from disk."""

    def __init__(self, cassette_dir: Path, mode: Mode, audit: AuditLog) -> None:
        self.cassette_dir = cassette_dir
        self.mode = mode
        self.audit = audit
        cassette_dir.mkdir(parents=True, exist_ok=True)

    def get(self, url: str, *, step_id: str, parent_step_id: str | None = None) -> Response:
        path = self.cassette_dir / _slug(url)

        if self.mode is not Mode.RECORD and path.exists():
            response = self._replay(path)
        elif self.mode is Mode.REPLAY:
            raise CassetteMiss(
                f"No cassette for {url}\n"
                f"  expected at: {path}\n"
                f"  run `make record` (needs network) to create it."
            )
        else:
            response = self._live(url, path)

        self.audit.emit(
            EventKind.FETCH,
            summary=(
                f"{'replayed' if response.from_cassette else 'fetched'} "
                f"{url} -> HTTP {response.status}, {len(response.body)} bytes"
            ),
            step_id=step_id,
            parent_step_id=parent_step_id,
            findings=[
                (
                    "source_offline" if response.from_cassette else "source_live",
                    f"served from {'committed cassette' if response.from_cassette else 'the live network'}",
                )
            ],
            data={
                "url": url,
                "status": response.status,
                "bytes": len(response.body),
                "body_sha256": response.sha256,
                "recorded_at": response.fetched_at,
                "from_cassette": response.from_cassette,
            },
        )
        return response

    # -- internals -----------------------------------------------------------

    def _replay(self, path: Path) -> Response:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            raw = json.load(fh)
        return Response(
            url=raw["url"],
            status=raw["status"],
            body=raw["body"],
            fetched_at=raw["fetched_at"],
            from_cassette=True,
        )

    def _live(self, url: str, path: Path) -> Response:
        fetched_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        reply = httpx.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/*"},
            timeout=30.0,
            follow_redirects=True,
        )
        response = Response(
            url=url,
            status=reply.status_code,
            body=reply.text,
            fetched_at=fetched_at,
            from_cassette=False,
        )
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            json.dump(
                {
                    "url": url,
                    "status": response.status,
                    "body": response.body,
                    "fetched_at": fetched_at,
                },
                fh,
                ensure_ascii=False,
            )
        return response
