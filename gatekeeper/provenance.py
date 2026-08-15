"""Trust boundaries, enforced by the type system rather than by discipline.

The claim this project is built on: text fetched from the internet is *data*,
never *instruction*. That is easy to say and easy to violate by accident. One
f-string is all it takes to paste an attacker's prose into a prompt:

    prompt = f"Summarise this job: {posting.description}"   # game over

So untrusted text is wrapped in `Tainted`, whose `__str__`, `__format__` and
`__add__` raise. The line above becomes a runtime error instead of a silent
vulnerability. Getting the characters out requires naming your reason:

    tainted.for_classifier()  # to be judged -- the one path to a model
    tainted.redacted()        # a safe stand-in for any other prompt
    tainted.for_human()       # audit report / terminal, never a model

Trust is a property of a *field*, not of a source. A single Arbeitnow response
carries a schema-constrained `remote` boolean and a free-text `description`
written by whoever posted the job. Treating those two the same way is the bug
this module exists to prevent.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, NoReturn


class Trust(str, Enum):
    """How much weight one field may carry on its own."""

    #: Machine-generated and schema-constrained: booleans, timestamps, IDs,
    #: enum-valued fields. Safe to branch on directly.
    STRUCTURED = "structured"

    #: Human-authored but short, bounded, and rendered as a label rather than
    #: prose: job titles, company names, tags. Shown to a model, never obeyed.
    LABEL = "label"

    #: Free text of arbitrary length from an open submission form: job
    #: descriptions, API preamble blobs, web page bodies. Quarantined.
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Origin:
    """Where a value came from, precisely enough to re-fetch and re-check it."""

    source_id: str  # "remoteok" | "arbeitnow" | "hackernews"
    url: str
    field_path: str  # e.g. "data[3].description"
    trust: Trust
    fetched_at: str  # ISO 8601 UTC
    response_sha256: str  # digest of the enclosing response body

    def describe(self) -> str:
        return f"{self.source_id}:{self.field_path} <{self.trust.value}> from {self.url}"


class TaintError(RuntimeError):
    """Raised when untrusted text is used where trusted text was expected."""


class Tainted:
    """Untrusted text that cannot be interpolated into a prompt by accident.

    `repr()` is deliberately safe, so logging, debugging and pytest output all
    keep working. Only the actual characters are guarded.
    """

    __slots__ = ("_value", "origin")

    def __init__(self, value: str, origin: Origin) -> None:
        self._value = value
        self.origin = origin

    # -- guarded conversions -------------------------------------------------

    def _refuse(self, how: str) -> NoReturn:
        raise TaintError(
            f"Refusing to {how} untrusted text from {self.origin.describe()}. "
            f"Call .for_classifier(), .redacted() or .for_human() and say why."
        )

    def __str__(self) -> str:
        self._refuse("str()")

    def __format__(self, spec: str) -> str:
        self._refuse("format")

    def __add__(self, other: Any) -> NoReturn:
        self._refuse("concatenate")

    __radd__ = __add__

    # -- safe surface --------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<Tainted {len(self._value)} chars "
            f"from {self.origin.source_id}:{self.origin.field_path}>"
        )

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self._value.encode("utf-8")).hexdigest()

    # -- explicit unwrapping -------------------------------------------------

    def for_classifier(self) -> str:
        """Raw text bound for the screening model.

        The single path by which untrusted characters reach an LLM. The
        classifier prompt frames them as quoted evidence and is the one
        component in this codebase written to expect hostility.
        """
        return self._value

    def for_rules(self) -> str:
        """Raw text bound for the deterministic detectors.

        Regexes cannot be socially engineered, so this is not a trust
        decision -- but it is still named, so a reader can grep for every
        place untrusted characters escape the wrapper.
        """
        return self._value

    def for_human(self) -> str:
        """Raw text for a person reading the audit trail. Never for a model."""
        return self._value

    def redacted(self, limit: int = 96) -> str:
        """A description of the text, safe to place in any prompt or log.

        Carries shape and digest so a reviewer can tie it back to the full
        value in the audit trail, without reproducing the payload itself.
        """
        return (
            f"[redacted {len(self._value)} chars, sha256={self.sha256[:12]}, "
            f"from {self.origin.field_path}]"
        )[:limit]

    def excerpt(self, limit: int = 240) -> str:
        """A truncated, whitespace-collapsed copy for human-facing summaries.

        Used in the decision log so a reviewer can see *what* was judged
        without opening the raw cassette. Still never handed to a model as
        instruction.
        """
        flat = " ".join(self._value.split())
        return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def taint(value: str, origin: Origin) -> Tainted:
    return Tainted(value, origin)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
