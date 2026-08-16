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

**In the ambiguous band, every failure mode lands on FLAG rather than ACT.** No
key, no budget, HTTP error, unparseable response, low confidence -- all of them
stop the item and hand it to a human. The agent is allowed to be unhelpful; it
is not allowed to act on something it did not manage to check.

The audit-sample path is the one deliberate exception, and it is worth being
precise about why. There, the rules found nothing and the model call is an
*extra* check on an already-cleared item. If that call fails, flagging would
make the verdict depend on whether the network held rather than on the content
-- an identical unsampled item would sail through, and a rate limit would turn
a clean run into a wall of false flags. So the item keeps the verdict it
earned, and the log records that the sample is missing. The failure is
reported as a gap in *measurement*, never as evidence about the item.
"""

from __future__ import annotations

from gatekeeper.config import Settings
from gatekeeper.screening import llm, rules
from gatekeeper.screening.verdicts import Action, Finding, Screening, Verdict

#: Below this, the model is not trusted to clear an item the rules doubted.
CLEAR_CONFIDENCE = 0.7


def _informational_veto(quote: str) -> str | None:
    """Is the model objecting to content the rules already know is benign?

    Returns the name of the matching informational detector, or None. See the
    long comment at the call site for the measurement that motivated this.
    """
    if not quote or not quote.strip():
        return None
    for detector in rules.INFORMATIONAL:
        if detector.pattern.search(quote):
            return detector.code
    return None


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
        # The audit sample is the mitigation: spend a model call on a *cleared*
        # item to find out what the rules are missing. It is how the run
        # measures its own false-negative rate instead of assuming it is zero.
        # Measured on the corpus, it recovers all three subtle attacks the
        # rules tier scores at 0 -- but only when the call actually succeeds,
        # which is why the failure path below is written the way it is.
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

        # A failed sample is not a suspicious item -- it is a missing
        # measurement, and the two must not be conflated in either direction.
        #
        # Flagging here would be incoherent: an identical item that simply was
        # not sampled is cleared, so flagging this one would make the verdict
        # depend on whether the network held rather than on the content. Under
        # a rate limit that turns a clean run into a wall of false flags.
        #
        # But silently returning "cleared, and the model agreed" is worse, and
        # is the bug this replaces: the log asserted corroboration that was
        # never obtained. So the item keeps exactly the verdict it had earned
        # on its own -- and the log says, in as many words, that the second
        # opinion is missing.
        if not opinion.ok:
            findings.append(
                Finding(
                    "audit_sample_failed",
                    (
                        f"audit sample could not be taken ({opinion.error}). The rules verdict "
                        f"stands unchanged, because a failed measurement is not evidence about "
                        f"this item. What it does mean is that this run's false-negative rate "
                        f"is UNMEASURED, not zero"
                    ),
                    where="structured",
                )
            )
            return Screening(
                ref=ref,
                verdict=Verdict.DATA,
                action=Action.ACT,
                score=report.score,
                findings=findings,
                decided_by="rules (audit sample unavailable)",
                rationale=(
                    f"Rules scored {report.score} and cleared this item. An audit sample was "
                    f"attempted and failed ({opinion.error}), so no second opinion was obtained. "
                    f"The item is treated exactly as any other rules-cleared item — no better, "
                    f"no worse. Note that a run with failed samples has not verified its own "
                    f"blind spot."
                ),
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

        # Positive identification beats general suspicion.
        #
        # Measured: the adjudicator flags RemoteOK's anti-bot canary ("mention
        # the word CAJOLE ... to show you read the job post") as prompt
        # injection, and does so *inconsistently* -- across four real postings
        # carrying the identical canary it returned INSTRUCTION at 0.95 for
        # one, SUSPICIOUS at 0.95 for another, and DATA at 0.95-1.00 for the
        # other two, correctly describing it as "a typical attention check" in
        # the last case. Same pattern, opposite verdicts, high confidence
        # either way. That alone drove hybrid precision from 1.000 to 0.750 on
        # real postings.
        #
        # The rules tier already knows what that string is, deterministically,
        # every time. Where a detector has *positively identified* content as a
        # known benign human-directed instruction, that beats the model's
        # guess-from-priors -- so if the span the model is objecting to is
        # exactly such content, the escalation is refused and the disagreement
        # is logged rather than hidden.
        #
        # Deliberately narrow: it only applies when the model's own quote
        # matches an informational pattern. A posting carrying both a canary
        # and a real payload still escalates, because the model would quote the
        # payload instead.
        vetoed_by = _informational_veto(opinion.quote)
        if vetoed_by and opinion.verdict in {"INSTRUCTION", "SUSPICIOUS"}:
            findings.append(
                Finding(
                    "rules_override_llm",
                    (
                        f"adjudicator said {opinion.verdict} at {opinion.confidence:.2f}, but the "
                        f"span it quoted matches '{vetoed_by}' — content the rules tier has "
                        f"positively identified as a benign instruction aimed at human "
                        f"applicants. A specific identification outranks a general suspicion, "
                        f"so the escalation is refused. Quoted: {opinion.quote[:120]!r}"
                    ),
                    where="structured",
                )
            )
            return Screening(
                ref=ref,
                verdict=Verdict.DATA,
                action=Action.ACT,
                score=report.score,
                findings=findings,
                decided_by="rules+llm (rules overrode the model)",
                rationale=(
                    f"The audit sample disagreed with the rules, and the rules won. The model "
                    f"objected to a known anti-bot canary — a real instruction, aimed at humans, "
                    f"placed there by the job board itself. The disagreement is recorded above "
                    f"rather than resolved silently."
                ),
            )

        if opinion.verdict in {"INSTRUCTION", "SUSPICIOUS"} and opinion.confidence >= CLEAR_CONFIDENCE:
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
