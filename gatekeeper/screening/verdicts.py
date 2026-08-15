"""The vocabulary of judgement, kept in one place so the log stays consistent."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """What the agent concluded a piece of retrieved content *is*."""

    #: A legitimate data point. Safe to act on.
    DATA = "DATA"

    #: Content that carries an instruction aimed at whoever/whatever is
    #: reading the feed. Never acted on; never forwarded to a model as text.
    INSTRUCTION = "INSTRUCTION"

    #: Not provably an instruction, but wrong in a way that should stop an
    #: automated decision: concealed text, impossible claims, contradictions.
    SUSPICIOUS = "SUSPICIOUS"

    #: The rules tier genuinely cannot call it. This is a *routing* state, not
    #: a final answer -- it means "ask the model" or, if there is no model,
    #: "fail closed and tell a human".
    AMBIGUOUS = "AMBIGUOUS"


class Action(str, Enum):
    """What the agent decided to *do*, which is not the same as what it thinks.

    Kept separate from `Verdict` on purpose. "This is probably fine" and "I am
    going to act on it" are different claims, and collapsing them is how an
    agent ends up acting on things it was unsure about.
    """

    ACT = "ACT"          # process it: score it against the profile, shortlist it
    IGNORE = "IGNORE"    # legitimate, but not relevant to the task
    FLAG = "FLAG"        # hold for a human; do not act
    REJECT = "REJECT"    # actively hostile; quarantine


@dataclass
class Finding:
    """One discrete piece of evidence, greppable by code, readable by detail."""

    code: str
    detail: str
    weight: int = 0
    #: Which channel it was found in: visible | hidden | title | company | structured
    where: str = "visible"

    def as_tuple(self) -> tuple[str, str]:
        loc = f" [{self.where}]" if self.where != "visible" else ""
        w = f" (+{self.weight})" if self.weight else ""
        return (self.code, f"{self.detail}{loc}{w}")


@dataclass
class Screening:
    """The full record of how one item was judged."""

    ref: str
    verdict: Verdict
    action: Action
    score: int
    findings: list[Finding] = field(default_factory=list)
    #: "rules" | "rules+llm" | "rules (llm unavailable)" | "rules (budget spent)"
    decided_by: str = "rules"
    rationale: str = ""

    def as_log_findings(self) -> list[tuple[str, str]]:
        return [f.as_tuple() for f in self.findings]
