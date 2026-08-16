"""Settings, and the model budget the planner spends against.

The LLM tier is optional by design. Everything in this project runs without a
key: the rules tier needs no model, and `--mode replay` serves every HTTP
request from committed cassettes. A key buys you the tier-2 adjudicator, which
resolves the ambiguous middle that rules alone get wrong.

The budget below is not a rate limiter. It is a resource the *planner* spends
deliberately: when it runs low, the agent changes strategy rather than failing,
and it says so in the log. That behaviour is the point, so the cap is small
enough by default that you can actually watch it happen.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Verified against the live API on 2026-08-16 with a free-tier key.
#:
#: The previous default, `gemini-2.5-flash-lite`, still appears in the
#: ListModels response but returns HTTP 404 for new keys: "no longer available
#: to new users". That combination is nastier than a plain removal, because
#: discovery says the model exists and only the call fails -- so the failure
#: surfaces at adjudication time, one item at a time, rather than at startup.
#: `gatekeeper eval --llm` will say so plainly if this ever goes stale again.
DEFAULT_MODEL = "gemini-3.5-flash-lite"

GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)


@dataclass
class Budget:
    """Model calls the agent may spend on one run.

    Deliberately mutable and deliberately small. The planner reads `remaining`
    before choosing to adjudicate, and when it hits zero it falls back to the
    rules verdict and logs the downgrade instead of crashing.
    """

    limit: int
    spent: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def charge(self, n: int = 1) -> None:
        self.spent += n


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    model: str
    cassette_dir: Path
    run_dir: Path
    corpus_dir: Path
    budget: Budget = field(default_factory=lambda: Budget(limit=25))

    @property
    def llm_available(self) -> bool:
        return bool(self.api_key)


def load_settings(budget_limit: int | None = None) -> Settings:
    return Settings(
        api_key=os.environ.get("GEMINI_API_KEY") or None,
        model=os.environ.get("GATEKEEPER_MODEL", DEFAULT_MODEL),
        cassette_dir=REPO_ROOT / "cassettes",
        run_dir=REPO_ROOT / "runs",
        corpus_dir=REPO_ROOT / "corpus",
        budget=Budget(limit=budget_limit if budget_limit is not None else 25),
    )
