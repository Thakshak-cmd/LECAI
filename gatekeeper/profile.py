"""The task the agent is actually performing: finding jobs worth applying to.

Screening answers "is this content safe to act on". This module answers the
separate question "do I want it" -- and keeping the two apart matters. A
posting can be perfectly legitimate and irrelevant (IGNORE), or highly relevant
and hostile (REJECT). Collapsing safety and relevance into one score is how an
agent talks itself into acting on an attractive-looking attack.

Relevance is scored with plain keyword weighting, deliberately. It is the least
interesting part of the system and I would rather it be obviously correct than
clever: a reviewer reading the log should never have to wonder whether a
relevance number is doing something subtle.

Note that matching reads *tainted* text through `.for_rules()`. Keyword scoring
cannot be socially engineered -- a regex has no instructions to override -- but
the unwrapping is still explicit so every escape from the wrapper is greppable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from gatekeeper.sources.base import Posting


@dataclass
class Profile:
    """What a good result looks like for this run."""

    name: str = "AI engineering (junior / intern)"

    #: Terms that make a posting relevant, and how much each is worth.
    must_any: dict[str, int] = field(
        default_factory=lambda: {
            r"\bai\b": 12,
            r"\bml\b|machine learning": 14,
            r"\bllm|large language model": 18,
            r"\bagent(ic)?\b": 14,
            r"\bnlp\b": 10,
            r"data scien": 8,
            r"\bpython\b": 8,
        }
    )

    #: Terms that raise a posting's value once it is already relevant.
    nice_to_have: dict[str, int] = field(
        default_factory=lambda: {
            r"\bintern(ship)?\b": 15,
            r"\bjunior\b|\bgraduate\b|\bentry.level\b|\bworking student\b": 15,
            r"\bremote\b": 8,
            r"\bpytorch\b|\btensorflow\b": 6,
        }
    )

    #: Terms that disqualify regardless of everything else.
    exclude: dict[str, int] = field(
        default_factory=lambda: {
            r"\b(?:10|[7-9])\+?\s*years": -25,
            r"\bprincipal\b|\bstaff engineer\b|\bhead of\b|\bdirector\b|\bvp\b": -20,
            r"\bunpaid\b": -30,
            r"\bcommission[- ]only\b": -30,
        }
    )

    #: A posting must reach this to be worth a human's attention.
    threshold: int = 25

    @classmethod
    def load(cls, path: Path | None) -> "Profile":
        if path is None:
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            name=raw.get("name", cls.name),
            must_any=raw.get("must_any") or cls().must_any,
            nice_to_have=raw.get("nice_to_have") or cls().nice_to_have,
            exclude=raw.get("exclude") or cls().exclude,
            threshold=int(raw.get("threshold", cls.threshold)),
        )


@dataclass
class Match:
    score: int
    relevant: bool
    reasons: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return f"relevance {self.score} vs threshold ({'match' if self.relevant else 'no match'})"


def evaluate(posting: Posting, profile: Profile) -> Match:
    """Score one posting against the profile, recording why."""
    haystack = " ".join(
        [
            posting.title.for_rules(),
            " ".join(posting.tags),
            posting.description.for_rules(),
        ]
    ).lower()

    score = 0
    reasons: list[tuple[str, str]] = []

    core_hit = False
    for pattern, weight in profile.must_any.items():
        if re.search(pattern, haystack, re.I):
            score += weight
            core_hit = True
            reasons.append(("relevance_core", f"matched /{pattern}/ (+{weight})"))

    if not core_hit:
        return Match(
            score=0,
            relevant=False,
            reasons=[("relevance_none", "no core skill term matched; not this profile's area")],
        )

    for pattern, weight in profile.nice_to_have.items():
        if re.search(pattern, haystack, re.I):
            score += weight
            reasons.append(("relevance_bonus", f"matched /{pattern}/ (+{weight})"))

    for pattern, weight in profile.exclude.items():
        if re.search(pattern, haystack, re.I):
            score += weight
            reasons.append(("relevance_penalty", f"matched /{pattern}/ ({weight})"))

    score = max(0, score)
    return Match(
        score=score,
        relevant=score >= profile.threshold,
        reasons=reasons,
    )
