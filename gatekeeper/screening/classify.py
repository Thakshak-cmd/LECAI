"""Combining the two tiers into one verdict, and being explicit about who decided.

The division of labour:

* **Rules decide the extremes.** A score at or above 70 is called an attack
  without spending a model call -- if text contains `<|im_start|>` and a
  demand to ignore prior instructions, a model adds nothing but latency and
  cost. A score below 25 is cleared the same way.

* **The model decides the middle.** Between those thresholds the rules have
  found something but cannot say what it means. That band is exactly what the
  LLM tier is for, and it is the only band that spends budget.

The asymmetry in what the model is allowed to change is deliberate:

* it **may clear** an ambiguous item down to DATA, but only with confidence
  ≥ 0.7, because clearing is the direction that lets content through;
* it **may escalate** anything, at any confidence;
* it **never sees** an item the rules already called at ≥ 70, so a persuasive
  payload cannot talk its way out of a verdict that was reached from structure.

Every failure mode lands on FLAG rather than ACT. No key, no budget, HTTP
error, unparseable response, low confidence -- all of them stop the item and
hand it to a human. The agent is allowed to be unhelpful; it is not allowed to
act on something it did not manage to check.
"""

from __future__ import annotations

from gatekeeper.config import Settings
from gatekeeper.screening import llm, rules
from gatekeeper.screening.verdicts import Action, Finding, Screening, Verdict

#: Below this, the model is not trusted to clear an item the rules doubted.
CLEAR_CONFIDENCE = 0.7


def screen(
    *,
    ref: str,
    settings: Settings,
    visible: str,
    hidden: str = "",
    title: str = "",
    company: str = "",
    concealment: list[tuple[str, str]] | None = None,
    context_reason: str | None = None,
    allow_llm: bool = True,
    audit_sample: bool = False,
) -> Screening:
    """Judge one item.

    `allow_llm=False` forces a rules-only verdict. `audit_sample=True` permits
    spending a model call on an item the rules *cleared*, to measure what the
    pattern tier is missing rather than assuming it misses nothing.
    """
    report = rules.scan(
        visible=visible,
        hidden=hidden,
        title=title,
        company=company,
        concealment=concealment,
        context_reason=context_reason,
    )
    findings = list(report.findings)

    findings.insert(
        0,
        Finding(
            "rules_score",
            (
                f"deterministic score {report.score}/100 -> band '{report.band}' "
                f"(thresholds: ≥{rules.THRESHOLD_INSTRUCTION} instruction, "
                f"≥{rules.THRESHOLD_AMBIGUOUS} ambiguous); "
                f"channels scanned: {', '.join(report.channels_scanned) or 'none'}"
            ),
            where="structured",
        ),
    )

    # ---- the rules are confident it is hostile ----------------------------
    if report.band == "instruction":
        return Screening(
            ref=ref,
            verdict=Verdict.INSTRUCTION,
            action=Action.REJECT,
            score=report.score,
            findings=findings,
            decided_by="rules",
            rationale=(
                f"Rules scored {report.score}, at or above the {rules.THRESHOLD_INSTRUCTION} "
                f"threshold, on structural grounds that do not depend on interpretation. "
                f"No model call was spent, and the content was never sent to a model."
            ),
        )

    # ---- the rules are confident it is fine -------------------------------
    if report.band == "clean":
        # A clean score means "no pattern fired", which is not the same as
        # "nothing is wrong". A payload written in plain, polite English --
        # no override phrasing, no delimiters, no concealment -- scores zero
        # here and would otherwise never be looked at again. That is the
        # structural blind spot of any pattern tier, and it cannot be fixed by
        # adding more patterns, because the whole class is defined by not
        # matching any.
        #
        # The audit sample is the answer: spend a model call on a *cleared*
        # item to find out what the rules are missing. It is how the run
        # measures its own false-negative rate instead of assuming it is zero.
        can_sample = (
            audit_sample
            and allow_llm
            and settings.llm_available
            and not settings.budget.exhausted
        )
        if not can_sample:
            return Screening(
                ref=ref,
                verdict=Verdict.DATA,
                action=Action.ACT,
                score=report.score,
                findings=findings,
                decided_by="rules",
                rationale=(
                    f"Rules scored {report.score}, below the {rules.THRESHOLD_AMBIGUOUS} "
                    f"ambiguity threshold. No instruction-shaped content, no concealment. "
                    f"Cleared without spending a model call."
                ),
            )

        settings.budget.charge()
        opinion = llm.adjudicate(
            settings,
            text=visible or hidden,
            rules_summary=f"score {report.score}/100 — no pattern fired; this is an audit sample of a cleared item",
        )
        findings.append(
            Finding(
                "audit_sample",
                (
                    f"item was cleared by rules ({report.score}) and adjudicated anyway as a "
                    f"sampled control; model said {opinion.verdict} at {opinion.confidence:.2f}"
                    + (f" — {opinion.reason}" if opinion.reason else "")
                ),
                where="structured",
            )
        )

        if opinion.ok and opinion.verdict in {"INSTRUCTION", "SUSPICIOUS"} and opinion.confidence >= CLEAR_CONFIDENCE:
            hostile = Verdict.INSTRUCTION if opinion.verdict == "INSTRUCTION" else Verdict.SUSPICIOUS
            return Screening(
                ref=ref,
                verdict=hostile,
                action=Action.REJECT if hostile is Verdict.INSTRUCTION else Action.FLAG,
                score=report.score,
                findings=findings
                + [
                    Finding(
                        "rules_false_negative",
                        (
                            "the deterministic tier scored this 0 and would have let it through; "
                            "it was caught only because it was sampled. Worth adding to the corpus"
                        ),
                        where="structured",
                    )
                ],
                decided_by="rules+llm (audit sample)",
                rationale=(
                    f"No rule fired on this item, but it was selected as an audit sample and the "
                    f"adjudicator identified it as {opinion.verdict} at confidence "
                    f"{opinion.confidence:.2f}: {opinion.reason} This is a rules-tier miss caught "
                    f"by sampling."
                ),
            )

        return Screening(
            ref=ref,
            verdict=Verdict.DATA,
            action=Action.ACT,
            score=report.score,
            findings=findings,
            decided_by="rules+llm (audit sample)",
            rationale=(
                f"Rules scored {report.score} and an audit-sample adjudication agreed "
                f"({opinion.verdict} at {opinion.confidence:.2f}). Cleared, with the sample "
                f"recorded as evidence about the rules tier rather than just about this item."
            ),
        )

    # ---- the ambiguous middle: this is what the model is for ---------------
    rules_summary = (
        f"score {report.score}/100, codes: "
        + (", ".join(f.code for f in report.findings if f.weight) or "none")
    )

    if not allow_llm or not settings.llm_available or settings.budget.exhausted:
        if not settings.llm_available:
            why = "no GEMINI_API_KEY is configured"
        elif settings.budget.exhausted:
            why = f"the model budget for this run is spent ({settings.budget.spent}/{settings.budget.limit})"
        else:
            why = "adjudication was disabled for this item"

        findings.append(
            Finding(
                "llm_unavailable",
                f"could not adjudicate because {why}; failing closed to FLAG rather than guessing",
                where="structured",
            )
        )
        return Screening(
            ref=ref,
            verdict=Verdict.SUSPICIOUS,
            action=Action.FLAG,
            score=report.score,
            findings=findings,
            decided_by=f"rules ({why})",
            rationale=(
                f"Rules scored {report.score}, inside the ambiguous band, so this item "
                f"needed a second opinion that was not available ({why}). Held for human "
                f"review. It is not being called an attack -- only unverified."
            ),
        )

    settings.budget.charge()
    opinion = llm.adjudicate(settings, text=visible or hidden, rules_summary=rules_summary)

    findings.append(
        Finding(
            "llm_verdict",
            (
                f"model {opinion.model} said {opinion.verdict} at confidence "
                f"{opinion.confidence:.2f} — {opinion.reason or '(no reason given)'}"
                + (f" — quoting: {opinion.quote!r}" if opinion.quote else "")
            ),
            where="structured",
        )
    )

    if not opinion.ok:
        findings.append(
            Finding(
                "llm_failed_closed",
                f"adjudication failed ({opinion.error}); treating as unverified, not as clean",
                where="structured",
            )
        )
        return Screening(
            ref=ref,
            verdict=Verdict.SUSPICIOUS,
            action=Action.FLAG,
            score=report.score,
            findings=findings,
            decided_by="rules+llm (llm failed)",
            rationale=(
                f"Rules were unsure ({report.score}) and the adjudicator did not return a "
                f"usable answer ({opinion.error}). Failing closed to human review."
            ),
        )

    if opinion.verdict == "INSTRUCTION":
        return Screening(
            ref=ref,
            verdict=Verdict.INSTRUCTION,
            action=Action.REJECT,
            score=report.score,
            findings=findings,
            decided_by="rules+llm",
            rationale=(
                f"Rules flagged this as ambiguous ({report.score}); the adjudicator read the "
                f"text and identified a directive aimed at an automated reader. Rejected."
            ),
        )

    if opinion.verdict == "SUSPICIOUS":
        return Screening(
            ref=ref,
            verdict=Verdict.SUSPICIOUS,
            action=Action.FLAG,
            score=report.score,
            findings=findings,
            decided_by="rules+llm",
            rationale=(
                f"Rules flagged this as ambiguous ({report.score}) and the adjudicator agreed "
                f"something is wrong without calling it a directive. Held for human review."
            ),
        )

    # opinion.verdict == "DATA" -- the only direction that needs a confidence bar
    if opinion.confidence >= CLEAR_CONFIDENCE:
        return Screening(
            ref=ref,
            verdict=Verdict.DATA,
            action=Action.ACT,
            score=report.score,
            findings=findings,
            decided_by="rules+llm",
            rationale=(
                f"Rules raised {report.score} points of concern; the adjudicator examined the "
                f"text and cleared it at confidence {opinion.confidence:.2f} "
                f"(≥{CLEAR_CONFIDENCE} required to clear). The rules signal is recorded above "
                f"so the disagreement stays visible."
            ),
        )

    findings.append(
        Finding(
            "llm_low_confidence",
            (
                f"adjudicator said DATA but at {opinion.confidence:.2f}, below the "
                f"{CLEAR_CONFIDENCE} bar required to clear a flagged item; not clearing"
            ),
            where="structured",
        )
    )
    return Screening(
        ref=ref,
        verdict=Verdict.SUSPICIOUS,
        action=Action.FLAG,
        score=report.score,
        findings=findings,
        decided_by="rules+llm",
        rationale=(
            f"Rules were unsure ({report.score}) and the adjudicator's clearance was itself "
            f"unsure ({opinion.confidence:.2f}). Two weak signals do not make a strong one, "
            f"so this goes to a human."
        ),
    )
