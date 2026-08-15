"""Checking claims against other claims, which is the only reason two sources beat one.

Screening asks "is this text trying to manipulate me". This module asks a
different and complementary question: **is this posting internally coherent, and
does anything outside it agree?** A posting can be entirely free of injection
and still be false, and a triage agent that only defends against prompt attacks
while cheerfully forwarding scams has solved the wrong half of the problem.

Three kinds of check, in increasing order of cost:

**Intra-posting** — free. Compare the structured fields against the free text.
This is the strongest check available here, because the two are authored
differently: `remote: false` is a form control the poster ticked, while "fully
remote position" is prose they typed. When they disagree, one of them is wrong,
and the disagreement is machine-detectable without asking anyone.

**Cross-source** — free, but usually unavailable. If the same company appears on
both boards, their claims can be compared. Measured company overlap between
RemoteOK and Arbeitnow is about 1% (1 of 85), so this check *almost always has
nothing to say*, and saying so honestly is the point. An agent that only reports
when corroboration succeeds gives a badly skewed picture of its own confidence.

**External** — costs a fetch. Handled by the planner, not here, because whether
it is worth doing depends on what the cheaper checks found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from gatekeeper.sources.base import Posting

#: Phrases asserting physical presence. German included because Arbeitnow is
#: Germany-weighted and roughly a third of its descriptions are in German --
#: an English-only check would silently pass every German on-site listing as
#: consistent with a remote claim.
ONSITE_CLAIMS = re.compile(
    r"\b(?:on[- ]?site|onsite|in[- ]office|in the office|at our office"
    r"|relocat\w+|must (?:be (?:based|located)|live|reside)"
    r"|\d\s*(?:days?|tage?)\s*(?:per|a|pro)\s*(?:week|woche)\s*(?:in|im)\s*(?:the\s*)?(?:office|büro)"
    r"|vor ort|präsenz|prasenz|nicht remote|kein[e]? remote|büro"
    r")\b",
    re.I,
)

REMOTE_CLAIMS = re.compile(
    r"\b(?:fully|100%|entirely|completely)?\s*remote(?:[- ]first|[- ]only)?\b"
    r"|\bwork from (?:home|anywhere)\b|\bhomeoffice\b|\bhome office\b|\bortsunabhängig\b",
    re.I,
)

#: Markers of the classic job-board scam: the applicant is asked to pay, to
#: move money, or to move the conversation to an unlogged channel.
#:
#: `applicant_pays` was rewritten after it fired on a real American Bureau of
#: Shipping listing containing:
#:
#:     "ABS ... will not pay a fee to any third-party agency without a valid
#:      Master Service Agreement"
#:
#: — a routine notice telling recruitment agencies not to send speculative CVs.
#: The original pattern matched the bare phrase "pay a fee" and got two things
#: wrong at once: it ignored the negation ("will **not** pay"), and it ignored
#: direction. The fraud is *the applicant pays the employer*; here the employer
#: is declining to pay an agency, which is the opposite transaction. Matching a
#: money-word without establishing who pays whom is not a detector, it is a
#: word search. The patterns below require the payer to be the reader.
SCAM_MARKERS = {
    "applicant_pays": re.compile(
        r"\b(?:you|applicants?|candidates?|employees?)\s+(?:must|will|need\s+to|have\s+to"
        r"|are\s+required\s+to|should)\s+(?:pay|cover|send|transfer|wire)\b"
        r"[^.\n]{0,40}\b(?:fee|deposit|payment|charge)\b"
        r"|\b(?:registration|training|application|processing|starter|equipment|onboarding)\s+fee\s+"
        r"(?:of|is|will\s+be|must\s+be)\b[^.\n]{0,30}(?:required|paid|payable|\$|€|£|\d)"
        r"|\bpay\s+(?:a\s+)?(?:one[- ]time\s+)?(?:\$|€|£)?\s?\d+\s*(?:\.\d+)?\s*(?:fee|deposit)\b"
        r"|\bpurchase\s+(?:your\s+own\s+)?equipment\s+upfront\b",
        re.I,
    ),
    "money_handling": re.compile(
        r"\b(?:money mule|process payments? through your|transfer funds? (?:through|via) your"
        r"|receive (?:and forward )?payments? (?:in|to) your (?:personal )?account"
        r"|wire transfer|western union|cash ?app)\b",
        re.I,
    ),
    "off_channel_contact": re.compile(
        r"\b(?:contact|message|reach|text|apply|interview)\w*\s+(?:us\s+)?(?:only\s+)?"
        r"(?:on|via|through|at)\s+(?:telegram|whatsapp|signal|wechat|icq)\b"
        r"|\b(?:telegram|whatsapp)\s*(?:handle|id|number)\s*[:@]",
        re.I,
    ),
    "credential_request": re.compile(
        r"\b(?:send|provide|share|submit)\b[^.\n]{0,40}\b(?:bank (?:account|details)"
        r"|social security number|\bssn\b|passport (?:number|scan|copy)|credit card"
        r"|national insurance number)\b",
        re.I,
    ),
}


@dataclass
class Check:
    code: str
    passed: bool
    detail: str
    #: How much this should count against acting on the posting, 0-100.
    severity: int = 0


@dataclass
class ConsistencyReport:
    checks: list[Check] = field(default_factory=list)
    #: Questions the cheap checks could not settle, which the planner may
    #: choose to spend an external fetch on.
    open_questions: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    @property
    def severity(self) -> int:
        return min(100, sum(c.severity for c in self.failures))

    def as_log_findings(self) -> list[tuple[str, str]]:
        return [
            (c.code if c.passed else f"{c.code}_FAILED", c.detail)
            for c in self.checks
        ]


def check_posting(posting: Posting) -> ConsistencyReport:
    """Every check that costs nothing but reading what we already fetched."""
    report = ConsistencyReport()
    text = posting.description.for_rules()
    location = posting.location or ""

    # -- structured remote flag vs what the prose actually says -------------
    if posting.remote_flag is not None and text.strip():
        says_onsite = ONSITE_CLAIMS.search(text)
        says_remote = REMOTE_CLAIMS.search(text)

        if posting.remote_flag and says_onsite and not says_remote:
            report.checks.append(
                Check(
                    "remote_claim_contradicted",
                    False,
                    (
                        f"listing is published as remote, but the description requires physical "
                        f"presence — matched {_span(says_onsite)}. One of the two is wrong, and "
                        f"a candidate filtering on 'remote' would be misled."
                    ),
                    severity=35,
                )
            )
        elif not posting.remote_flag and says_remote and not says_onsite:
            report.checks.append(
                Check(
                    "remote_flag_understates",
                    False,
                    (
                        f"listing is published as non-remote but the description offers remote "
                        f"work — matched {_span(says_remote)}. Mild: this loses opportunities "
                        f"rather than creating false ones."
                    ),
                    severity=10,
                )
            )
        else:
            report.checks.append(
                Check(
                    "remote_claim_consistent",
                    True,
                    f"structured remote={posting.remote_flag} is not contradicted by the description",
                )
            )

    # -- a remote-board listing that names a specific workplace -------------
    if posting.remote_flag and location:
        # "Worldwide", "Remote", "EMEA" are region hints, not workplaces.
        if not re.search(
            r"worldwide|anywhere|remote|global|emea|apac|americas|europe|usa|uk|"
            r"united states|probably|any\b|^\W*$",
            location,
            re.I,
        ):
            report.checks.append(
                Check(
                    "remote_with_fixed_location",
                    False,
                    (
                        f"published as remote but tied to the specific location "
                        f"{location!r}; on a remote-only board this usually means the listing "
                        f"is region-locked rather than genuinely remote"
                    ),
                    severity=15,
                )
            )
        else:
            report.checks.append(
                Check("location_consistent", True, f"location {location!r} is compatible with a remote listing")
            )

    # -- seniority: title against body --------------------------------------
    title = posting.title.for_rules()
    senior_title = re.search(r"\b(senior|sr\.?|lead|principal|staff|head)\b", title, re.I)
    junior_body = re.search(r"\b(intern(ship)?|graduate|entry.level|no experience|working student|trainee|apprentice)\b", text, re.I)
    if senior_title and junior_body:
        report.checks.append(
            Check(
                "seniority_mismatch",
                False,
                (
                    f"title claims seniority ({_span(senior_title)}) but the body describes an "
                    f"entry-level role ({_span(junior_body)}); the title may be inflated to "
                    f"attract applicants"
                ),
                severity=20,
            )
        )

    # -- scam markers --------------------------------------------------------
    for code, pattern in SCAM_MARKERS.items():
        m = pattern.search(text)
        if m:
            report.checks.append(
                Check(
                    f"scam_{code}",
                    False,
                    (
                        f"contains a known recruitment-fraud marker ({code}) — matched "
                        f"{_span(m)}. Legitimate employers do not ask applicants for this."
                    ),
                    severity=60,
                )
            )

    # -- empty body ----------------------------------------------------------
    if not text.strip():
        report.checks.append(
            Check(
                "empty_description",
                False,
                "posting has no description text at all; nothing to verify and nothing to judge it on",
                severity=15,
            )
        )

    if not report.checks:
        report.checks.append(
            Check("no_checks_applicable", True, "no structured claims available to cross-check")
        )

    return report


def _norm_company(name: str) -> str:
    """Normalise a company name enough to match across boards.

    Strips punctuation and the usual legal suffixes. Kept conservative: a
    looser match would create false corroboration, which is worse than none,
    because it manufactures confidence the agent has not earned.
    """
    s = re.sub(r"[^a-z0-9 ]+", " ", name.lower())
    s = re.sub(
        r"\b(gmbh|ag|se|kg|ug|mbh|inc|llc|ltd|limited|corp|corporation|co|plc|bv|nv|oy|ab|as)\b",
        " ",
        s,
    )
    return re.sub(r"\s+", " ", s).strip()


def cross_source(posting: Posting, others: list[Posting]) -> Check:
    """Look for the same company on the *other* board and compare claims."""
    target = _norm_company(posting.company.for_rules())
    if not target:
        return Check("cross_source_skipped", True, "posting has no usable company name")

    matches = [
        p for p in others
        if p.source_id != posting.source_id and _norm_company(p.company.for_rules()) == target
    ]

    if not matches:
        return Check(
            "cross_source_unavailable",
            True,
            (
                f"no listing from {_norm_company(posting.company.for_rules())!r} on the other "
                f"board, so nothing to corroborate against. Measured overlap between these two "
                f"boards is ~1%, so this is the normal case and not a negative signal — but it "
                f"does mean this posting rests on a single source."
            ),
        )

    disagreements = []
    for other in matches:
        if (
            posting.remote_flag is not None
            and other.remote_flag is not None
            and posting.remote_flag != other.remote_flag
        ):
            disagreements.append(
                f"{posting.source_id} says remote={posting.remote_flag}, "
                f"{other.source_id} says remote={other.remote_flag}"
            )

    if disagreements:
        return Check(
            "cross_source_disagreement",
            False,
            f"same company listed on both boards with conflicting claims: {'; '.join(disagreements)}",
            severity=25,
        )

    return Check(
        "cross_source_corroborated",
        True,
        (
            f"company also listed on {matches[0].source_id} ({len(matches)} listing(s)) "
            f"with no conflicting claims — independent evidence the employer is real"
        ),
    )


def _span(m: re.Match[str], limit: int = 70) -> str:
    text = " ".join(m.group(0).split())
    return f"{text[:limit]!r}"
