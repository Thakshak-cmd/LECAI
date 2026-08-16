"""Scoring the classifier against the labelled corpus.

This exists because "my classifier detects prompt injection" is not a claim
anyone should accept, including me. Thresholds and weights in `rules.py` are
judgement calls, and without a number attached, changing one is indistinguish-
able from guessing.

What the two numbers mean here, and how much each is worth:

* **Precision** — of the items called hostile, how many were. Measured against
  real postings I did not write and cannot have tuned to, including the hard
  negatives that broke my first two attempts. This is the number I trust, and
  the one that matters operationally: a triage agent that cries wolf on real
  listings is useless no matter what its recall is.

* **Recall** — of the attacks, how many were caught. Measured against attacks
  I wrote myself, because a search of 276 live postings turned up none. It
  therefore measures how well the detector catches *the attacks I thought of*,
  which is a weaker claim than it looks. An attacker who reads `rules.py` can
  design around it; the LLM tier exists partly to cover that, and it is not a
  guarantee either.

`--llm` additionally runs the tier-2 adjudicator, which shows what the model
buys over rules alone on the ambiguous band.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from gatekeeper.config import load_settings
from gatekeeper.consistency import check_posting
from gatekeeper.provenance import Origin, Trust, taint
from gatekeeper.screening import Verdict, screen
from gatekeeper.sources.base import Posting

#: Both are "do not act on this", so for scoring detection they count together.
HOSTILE = {Verdict.INSTRUCTION, Verdict.SUSPICIOUS}

#: Consistency severity at or above this stops the agent acting (see planner).
CONSISTENCY_BLOCK = 50


def _as_posting(item: dict) -> Posting:
    """Rebuild a corpus record as a Posting so the coherence checks can run.

    The eval measures the question the agent actually answers -- "is it safe to
    act on this?" -- rather than one component of it. The scam listing in the
    corpus is the case that forced this: it carries no prompt injection at all,
    so the injection classifier is right to pass it, and the agent still must
    not act on it. Scoring only the classifier would have counted that as a
    miss and invited me to "fix" a detector that was behaving correctly.
    """
    origin = Origin(
        source_id="corpus",
        url="corpus://" + item["id"],
        field_path="description",
        trust=Trust.UNTRUSTED,
        fetched_at="1970-01-01T00:00:00Z",
        response_sha256="0" * 64,
    )
    return Posting(
        item_id=item["id"],
        source_id="corpus",
        url=origin.url,
        title=taint(item.get("title", ""), origin),
        company=taint(item.get("company", ""), origin),
        description=taint(item.get("visible", ""), origin),
        remote_flag=None,
        location=None,
    )


@dataclass
class Row:
    id: str
    expected: str
    got: str
    score: int
    origin: str
    note: str
    decided_by: str
    top_finding: str
    blocked: bool = False
    coherence_severity: int = 0


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_eval(console: Console, *, use_llm: bool = False, budget: int = 40) -> int:
    settings = load_settings(budget_limit=budget)
    corpus = settings.corpus_dir

    benign = _load(corpus / "benign.jsonl")
    adversarial = _load(corpus / "adversarial.jsonl")

    if not benign and not adversarial:
        console.print(f"[red]No corpus found in {corpus}.[/red]")
        console.print("Build it with: [cyan]python tools/build_corpus.py[/cyan]")
        return 1

    if use_llm and not settings.llm_available:
        console.print("[yellow]--llm requested but no GEMINI_API_KEY is set; running rules-only.[/yellow]")
        use_llm = False

    rows: list[Row] = []
    for item in benign + adversarial:
        result = screen(
            ref=item["id"],
            settings=settings,
            visible=item.get("visible", ""),
            hidden=item.get("hidden", ""),
            title=item.get("title", ""),
            company=item.get("company", ""),
            concealment=[tuple(c) for c in item.get("concealment", [])],
            allow_llm=use_llm,
            # In eval every cleared item is sampled, so the measured recall
            # reflects the full hybrid rather than only the ambiguous band.
            audit_sample=use_llm,
        )
        coherence = check_posting(_as_posting(item))
        blocked_by_coherence = coherence.severity >= CONSISTENCY_BLOCK

        scored = [f for f in result.findings if f.weight]
        top = max(scored, key=lambda f: f.weight).code if scored else None
        if not top and blocked_by_coherence:
            top = next((c.code for c in coherence.failures), "coherence")

        rows.append(
            Row(
                id=item["id"],
                expected=item["label"],
                got=result.verdict.value,
                score=result.score,
                origin=item.get("origin", "?"),
                note=item.get("note", ""),
                decided_by=result.decided_by,
                top_finding=top or "—",
                blocked=result.verdict in HOSTILE or blocked_by_coherence,
                coherence_severity=coherence.severity,
            )
        )

    # -- confusion, on the binary question that actually matters -------------
    # "Blocked" means the agent refused to act, by either route. That is the
    # decision with consequences; which subsystem produced it is a detail.
    tp = [r for r in rows if r.expected != "DATA" and r.blocked]
    fn = [r for r in rows if r.expected != "DATA" and not r.blocked]
    fp = [r for r in rows if r.expected == "DATA" and r.blocked]
    tn = [r for r in rows if r.expected == "DATA" and not r.blocked]

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    mode = "rules + LLM" if use_llm else "rules only"
    console.print(f"\n[bold]Screening evaluation[/bold] — {mode}")
    console.print(
        f"corpus: {len(benign)} real benign postings, {len(adversarial)} synthetic attacks"
    )

    table = Table(show_header=True)
    table.add_column("")
    table.add_column("predicted hostile", justify="right")
    table.add_column("predicted benign", justify="right")
    table.add_row("[bold]actually hostile[/bold]", f"[green]{len(tp)}[/green]", f"[red]{len(fn)}[/red]")
    table.add_row("[bold]actually benign[/bold]", f"[red]{len(fp)}[/red]", f"[green]{len(tn)}[/green]")
    console.print(table)

    console.print(
        f"precision [bold]{precision:.3f}[/bold]   "
        f"recall [bold]{recall:.3f}[/bold]   "
        f"F1 [bold]{f1:.3f}[/bold]"
    )
    console.print(
        "[dim]precision is measured against real postings; recall against attacks the author "
        "wrote, so recall is the softer number.[/dim]"
    )

    if fp:
        console.print(f"\n[red]False positives ({len(fp)}) — real postings called hostile:[/red]")
        for r in fp:
            console.print(f"  [bold]{r.id}[/bold] score={r.score} via {r.top_finding}")
            console.print(f"    [dim]{r.note[:150]}[/dim]")

    if fn:
        console.print(f"\n[yellow]False negatives ({len(fn)}) — attacks that got through:[/yellow]")
        for r in fn:
            console.print(f"  [bold]{r.id}[/bold] score={r.score} (expected {r.expected}, got {r.got})")
            console.print(f"    [dim]{r.note[:150]}[/dim]")

    # -- how much of the corpus needed the model at all ----------------------
    reached_model = [r for r in rows if "llm" in r.decided_by]
    failed = [r for r in rows if "unavailable" in r.decided_by or "llm failed" in r.decided_by]
    console.print(
        f"\n{len(rows) - len(reached_model) - len(failed)}/{len(rows)} item(s) were settled by "
        f"rules alone at zero cost; {len(reached_model)} reached the model tier."
    )

    # Without this line the recall figure above is uninterpretable: a run where
    # most samples failed has not measured the blind spot, it has only failed
    # to look at it. Free-tier rate limits make that the common case, so the
    # number has to be printed rather than inferred.
    if failed:
        console.print(
            f"[yellow]{len(failed)} model call(s) failed[/yellow] "
            f"(quota, network, or a retired model id). Those items kept their rules verdict, "
            f"so the recall figure above is a [bold]lower bound[/bold] on the hybrid and the "
            f"false-negative rate is unmeasured for them. Re-run with a smaller corpus or a "
            f"higher budget for a clean number."
        )

    if not fp and not fn:
        console.print("\n[green]Clean sweep on this corpus.[/green] "
                      "[dim]Which bounds the claim to this corpus, not to the world.[/dim]")

    return 0
