"""Hacker News via the public Algolia index — the third source, fetched on demand.

This one is different in kind from the two boards, and that is the point. The
boards are *the thing being audited*; HN is the agent's way of getting a second
opinion about a company from somewhere the company does not control.

It is never fetched for every posting. Searching HN for all 275 listings would
be slow, rude, and pointless -- most postings are unremarkable and need no
corroboration. The planner reaches for it only when the run so far has produced
a specific unanswered question, e.g. "this listing claims to be a well-known
company but nothing else about it checks out". Which postings trigger that, and
how many calls the run makes, depends entirely on the content fetched earlier.

What it can and cannot tell you: a company with HN discussion is *probably* not
invented. A company with no HN presence is not thereby suspicious -- most real
employers have never been discussed on Hacker News. So absence is logged as
weak evidence and explicitly not treated as proof of anything. Getting that
asymmetry wrong would make the agent confidently unfair to small companies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote_plus

from gatekeeper.sources.http import Response

SOURCE_ID = "hackernews"
SEARCH_URL = "https://hn.algolia.com/api/v1/search?query={q}&tags=story&hitsPerPage=5"


def search_url(company: str) -> str:
    return SEARCH_URL.format(q=quote_plus(company.strip()[:80]))


@dataclass
class Corroboration:
    """What HN could say about a company name."""

    company: str
    hit_count: int
    top_points: int
    titles: list[str] = field(default_factory=list)
    #: True only when we found enough to call it a real, discussed entity.
    supports_existence: bool = False
    note: str = ""


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def parse(response: Response, company: str) -> Corroboration:
    try:
        payload = response.json()
    except ValueError:
        return Corroboration(
            company=company,
            hit_count=0,
            top_points=0,
            note="HN returned a body that is not JSON; treating as no evidence",
        )

    hits = payload.get("hits") or []
    target = _norm(company)

    # Algolia will happily return loose matches. Require the company name to
    # actually appear in the story title before counting it as corroboration,
    # otherwise a company called "Notion" matches every note-taking thread.
    relevant = [
        h for h in hits
        if target and target in _norm(str(h.get("title") or ""))
    ]

    top_points = max((int(h.get("points") or 0) for h in relevant), default=0)
    titles = [str(h.get("title") or "")[:110] for h in relevant[:3]]

    supports = len(relevant) >= 1 and top_points >= 5

    if supports:
        note = (
            f"{len(relevant)} HN story title(s) mention this company, "
            f"top story {top_points} points -- consistent with a real, publicly discussed entity"
        )
    elif hits and not relevant:
        note = (
            f"{len(hits)} HN result(s) returned but none name this company in the title "
            f"-- loose keyword matches only, so this is no evidence either way"
        )
    else:
        note = (
            "no HN stories name this company; most real employers have never been "
            "discussed on HN, so this is weak evidence and not a mark against them"
        )

    return Corroboration(
        company=company,
        hit_count=len(relevant),
        top_points=top_points,
        titles=titles,
        supports_existence=supports,
        note=note,
    )
