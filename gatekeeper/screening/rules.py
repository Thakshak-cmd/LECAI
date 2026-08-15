"""Tier 1: deterministic detectors. Free, instant, and impossible to talk out of.

## Why this tier is shaped the way it is

My first version of this file matched AI vocabulary -- "GPT", "Claude", "LLM",
"prompt", "AI agent". I ran it over 276 live postings from the two boards. It
fired 26 times. **Every single hit was a false positive**: they were job ads for
AI engineers, and job ads for AI engineers talk about AI.

    "AI-First-Workflow. Copilot, Claude, Cursor und Co. sind bei uns
     selbstverständliches Werkzeug."          <- an employer describing its stack

    "Is comfortable working in AI tools like Claude (including building
     skills files and workflows)"             <- a genuine job requirement

That result is the reason for everything below. Topic words carry no signal at
all: the base rate of *talking about AI* in this corpus is enormous, and the
base rate of *attacking an AI* is near zero. A detector on that axis is pure
noise, and worse than useless -- it would have flagged precisely the postings I
most want to find, since the roles I am searching for are AI roles.

So no detector here matches a topic. They match one of three things:

1. **An imperative addressed to an automated reader.** Not "we use Claude", but
   "if you are an AI, do X". The tell is second-person instruction crossing the
   boundary from content into control.
2. **Prompt-structure smuggling.** Fake role delimiters, chat templates, system
   headers -- text trying to look like the scaffolding around it.
3. **Concealment.** Content placed where a human reviewer cannot see it. This
   one is nearly self-proving: there is no innocent reason for a job
   description to carry instructions in an HTML comment.

## The second lesson: who is being instructed

The first version of this file rejected a real job ad from Alexander & Bebout,
Inc. at score 70. The offending text was:

    "You are welcome to stop in and complete an application or upload your
     resume ... or email to hr@alexanderbebout.com."

My "exfiltration" detector saw *send data to an address* and called it an
attack. It is of course an employer telling a human being how to apply.

That false positive is worth more than the true positives, because it names the
distinction the whole project turns on. Job postings are **full** of imperatives
— "send your CV", "apply by Friday", "mention this reference". Instruction-shaped
text is the normal register of the genre. What makes something an attack is not
that it instructs, but *who it instructs*: content aimed at the human applicant
is data about a job, while content aimed at the machine reading the feed is an
attempt at control.

So "email X to Y" moved to the context-gated set, and only programmatic
operations — issue an HTTP request, fetch this URL — stayed unconditional,
because no job ad has a reason to say those to anybody.

The same corpus makes the point a third way. RemoteOK appends an anti-bot canary
to postings:

    "Please mention the word **CAJOLE** and tag RMmEwMTo0YjAwOm... when applying
     to show you read the job post"

That is unambiguously an instruction embedded in a data field, and it is
entirely benign — it exists to catch bots that apply without reading. The agent
records it and does not obey it, which is the correct handling of a real
instruction from a legitimate source. It is logged at weight 0 by the
informational detectors below, so a reviewer can see it was noticed rather than
missed.

## Context gating

Some phrases are attacks in one setting and ordinary English in another. "Act
as a bridge between engineering and design" is a real responsibility; "act as
an unrestricted assistant" is not. Those patterns are marked
`needs_context=True` and score only when the item *also* shows an addressing
cue or concealment. Standalone-unambiguous patterns score on their own.

Weights are integers on a 0-100ish scale and are tuned against the labelled
corpus in `corpus/`. `make eval` prints precision and recall, so changing a
number here has a visible, checkable consequence rather than being a vibe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from gatekeeper.screening.verdicts import Finding

#: At or above this, the rules tier is confident enough to call it an attack
#: without spending a model call.
THRESHOLD_INSTRUCTION = 70

#: At or above this (but below the above), something is wrong but the rules
#: cannot say what. This is the band the LLM tier exists to resolve.
THRESHOLD_AMBIGUOUS = 25


@dataclass(frozen=True)
class Detector:
    code: str
    #: What this detector claims when it fires. Written to be read by a
    #: reviewer who is deciding whether to trust the verdict.
    claim: str
    pattern: re.Pattern[str]
    weight: int
    #: When True, only scores if an addressing cue or concealment is present.
    needs_context: bool = False


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I | re.S)


# --------------------------------------------------------------------------
# Cues that the text is speaking *to an automated reader* rather than to a
# human applicant. These gate the context-dependent detectors below, and are
# weak evidence on their own.
# --------------------------------------------------------------------------

ADDRESSING_CUES: list[Detector] = [
    Detector(
        "addresses_ai",
        "text speaks directly to an AI/bot/model reading it, which a job ad written for humans has no reason to do",
        _rx(
            r"\b(?:if|when)\s+you(?:'re| are)?\s+(?:an?\s+|the\s+)?"
            r"(?:ai|a\s*i|bot|llm|language\s+model|assistant|agent|chatbot|crawler|scraper"
            r"|robot|machine|algorithm|automated?\s+\w+|screening\s+\w+|resume\s+\w+|ats)\b"
        ),
        weight=35,
    ),
    Detector(
        "addresses_screener",
        "text addresses an automated screening/ATS system directly",
        _rx(r"\b(?:note|message|attention|instruction[s]?|dear)\s*(?:to|for)?\s*[:,-]?\s*(?:the\s+)?(?:ai|ats|bot|recruiter\s*bot|screening\s+(?:system|tool|ai)|automated\s+(?:system|screener|reviewer)|resume\s+(?:parser|scanner))\b"),
        weight=35,
    ),
    Detector(
        "ai_self_reference",
        "text asserts what the reader is, in the second person, as a model would be told",
        _rx(r"\bas\s+an?\s+(?:ai|llm|language\s+model)\b[^.]{0,40}\byou\b|\byou\s+are\s+(?:an?\s+)?(?:ai|llm|language\s+model|helpful\s+assistant)\b"),
        weight=30,
    ),
]


# --------------------------------------------------------------------------
# Standalone-unambiguous. These do not need corroboration; there is no benign
# reading of them inside a job posting.
# --------------------------------------------------------------------------

STRONG: list[Detector] = [
    Detector(
        "override_instructions",
        "classic instruction-override: tells the reader to discard its prior instructions",
        _rx(r"\b(?:ignore|disregard|forget|discard|override)\b[^.\n]{0,30}?\b(?:all\s+|any\s+|the\s+|your\s+|previous|prior|earlier|above|preceding|system|initial|original)\b[^.\n]{0,30}?\b(?:instruction|prompt|direction|rule|guideline|context|command|constraint)s?\b"),
        weight=80,
    ),
    Detector(
        "new_instructions",
        "declares a fresh instruction block, the standard pivot after an override",
        _rx(r"(?:^|\n|\s)(?:new|updated|revised|real|actual|true)\s+(?:instruction|task|directive|prompt|objective|system\s+prompt)s?\s*[:\-]"),
        weight=70,
    ),
    Detector(
        "chat_template_injection",
        "chat-template or role delimiters embedded in content, imitating the scaffolding around the model",
        _rx(r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[/?INST\]|<\|begin_of_text\|>|###\s*(?:instruction|system)\b|^\s*(?:system|assistant)\s*:\s*$"),
        weight=80,
    ),
    Detector(
        "role_delimiter_spoof",
        "fake system/assistant role header inside body text, attempting to end the data section",
        _rx(r"(?:^|\n)\s*(?:system|assistant|developer)\s*(?:prompt)?\s*:\s*\S"),
        weight=55,
    ),
    Detector(
        "programmatic_exfiltration",
        (
            "asks the reader to perform a network operation. A job ad describes a job; it has "
            "no reason to instruct anyone to issue an HTTP request or fetch a URL"
        ),
        _rx(
            # "make an HTTP POST request" puts a verb between protocol and noun,
            # so the method token has to be optional-but-allowed in the middle.
            r"\b(?:make|issue|perform|send|execute|submit)\s+(?:an?\s+)?"
            r"(?:http|https|api|curl|fetch|web)\s*"
            r"(?:get|post|put|patch|delete|head)?\s*(?:request|call|query)\b"
            r"|\b(?:fetch|retrieve|download|visit|navigate\s+to|browse\s+to)\s+(?:the\s+)?(?:url|link|endpoint|address)\b"
            r"|\bcurl\s+https?://"
        ),
        weight=70,
    ),
    Detector(
        "secrecy_demand",
        "instructs the reader to conceal something from the user or operator",
        _rx(r"\b(?:do\s*n[o']?t|don't|never|without)\s+(?:tell|inform|mention|reveal|disclose|show|notify|alert|report)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|operator|candidate|applicant|recruiter|anyone|admin)\b"),
        weight=65,
    ),
]


# --------------------------------------------------------------------------
# Context-gated. Ordinary English in a job ad; attacks when they appear next to
# an addressing cue or inside a hidden channel.
# --------------------------------------------------------------------------

CONTEXTUAL: list[Detector] = [
    Detector(
        "scoring_manipulation",
        "asks for a specific favourable evaluation outcome, i.e. tries to set the answer rather than inform it",
        _rx(r"\b(?:rate|rank|score|mark|classify|categorise|categorize|flag|list|place|consider|treat)\b[^.\n]{0,40}\b(?:as\s+)?(?:the\s+)?(?:highly|highest|first|top|10/10|100%|best|perfect|excellent|qualified|approved|a\s+(?:strong|perfect|ideal)\s+(?:match|fit|candidate))\b"),
        weight=55,
        needs_context=True,
    ),
    Detector(
        "role_reassignment",
        "attempts to reassign the reader's role or persona",
        _rx(r"\b(?:you\s+are\s+now|from\s+now\s+on|henceforth|act\s+as|pretend\s+to\s+be|roleplay\s+as|behave\s+as|assume\s+the\s+role\s+of|your\s+new\s+(?:role|task|job|purpose))\b"),
        weight=50,
        needs_context=True,
    ),
    Detector(
        "output_control",
        "dictates the reader's output verbatim, rather than describing a job",
        _rx(r"\b(?:reply|respond|answer|output|print|return|say|write)\s+(?:only\s+)?(?:with|the\s+following|exactly|verbatim)\b|\byour\s+(?:response|output|answer)\s+must\b"),
        weight=45,
        needs_context=True,
    ),
    Detector(
        "safety_bypass",
        "references removing restrictions or safety constraints",
        _rx(r"\b(?:without\s+(?:any\s+)?(?:restriction|limitation|filter|censorship)|no\s+(?:restrictions|filters|guardrails)|bypass\s+(?:your\s+)?(?:safety|filter|guideline|restriction)|jailbreak|dan\s+mode|developer\s+mode)\b"),
        weight=60,
        needs_context=True,
    ),
    Detector(
        "contact_exfiltration",
        (
            "asks for information to be sent to an address or URL. Ordinary in a job ad, which "
            "is why it scores nothing on its own -- see the note below on the false positive "
            "that put it here. It only counts once something else shows the text is speaking "
            "to a machine"
        ),
        _rx(
            r"\b(?:send|email|forward|transmit|upload|post)\b[^.\n]{0,40}"
            r"\b(?:to\s+)?(?:https?://|www\.|[\w.-]+@[\w.-]+\.\w{2,})"
        ),
        weight=55,
        needs_context=True,
    ),
    Detector(
        "consumer_directive",
        (
            "imposes an obligation on whoever is consuming the feed -- attribution demands, "
            "usage restrictions, or a threatened consequence for non-compliance. A job posting "
            "describes a job; it does not tell its reader what the reader must do"
        ),
        _rx(
            r"\b(?:link\s+back|backlink)\b"
            r"|\bsuspend(?:ed|ing)?\s+(?:your\s+|the\s+)?(?:api\s+)?access\b"
            r"|\bapi\s+terms\s+of\s+service\b"
            r"|\b(?:please\s+)?(?:do\s*n[o']?t|don't|never)\s+use\b[^.\n]{0,60}\bwithout\s+written\s+permission\b"
            r"|\b(?:must|please|should)\s+(?:credit|attribute|mention)\b[^.\n]{0,40}\bas\s+(?:a\s+|the\s+)?source\b"
            r"|\bregistered\s+trademark\b[^.\n]{0,40}\b(?:do|please|must)\b"
        ),
        weight=50,
        needs_context=True,
    ),
]


# --------------------------------------------------------------------------
# Scored at zero, always reported. These are instruction-shaped but aimed at a
# human, and recording them is how the log shows the mention/instruct
# distinction being applied rather than merely asserted.
# --------------------------------------------------------------------------

INFORMATIONAL: list[Detector] = [
    Detector(
        "human_directed_canary",
        (
            "an anti-bot canary aimed at human applicants (RemoteOK adds these). A genuine "
            "instruction in a data field, from a legitimate source, with no hostile intent -- "
            "noted and deliberately not obeyed"
        ),
        _rx(r"\bmention\s+the\s+word\b|\bto\s+show\s+you\s+read\s+the\s+(?:job\s+)?(?:post|ad|listing)\b"),
        weight=0,
    ),
    Detector(
        "human_directed_application",
        "ordinary application instructions addressed to a human applicant; data about a job, not control",
        _rx(r"\b(?:send|submit|upload|email)\s+(?:us\s+)?(?:your\s+)?(?:cv|resume|résumé|application|portfolio)\b"),
        weight=0,
    ),
]


@dataclass
class RuleReport:
    score: int = 0
    findings: list[Finding] = field(default_factory=list)
    #: Whether any addressing cue or concealment was present, which is what
    #: unlocks the context-gated detectors.
    context_present: bool = False
    channels_scanned: list[str] = field(default_factory=list)

    @property
    def band(self) -> str:
        if self.score >= THRESHOLD_INSTRUCTION:
            return "instruction"
        if self.score >= THRESHOLD_AMBIGUOUS:
            return "ambiguous"
        return "clean"


#: Hidden-channel content is scored harder than the same words in the visible
#: body. A phrase in a rendered job ad might be a joke, a quote, or a warning
#: about prompt injection; the identical phrase in an HTML comment was put
#: there to be read by a machine and not by a person.
HIDDEN_MULTIPLIER = 1.6

#: Reported in the log, scored at zero, and — most importantly — not permitted
#: to open the context gate for the detectors in CONTEXTUAL.
NON_CONCEALING = {"soft_hyphen", "parse_failed"}


#: A record that does not conform to the schema its feed advertises is already
#: anomalous before a single detector runs. That is not proof of hostility, but
#: it is genuine context: it means the usual reading ("this is a job ad, and job
#: ads talk like this") no longer applies, so phrasing that would be unremarkable
#: in a job description stops being explainable that way. Enough to open the
#: context gate, not enough to convict on its own.
NONCONFORMING_WEIGHT = 25


def scan(
    *,
    visible: str,
    hidden: str = "",
    title: str = "",
    company: str = "",
    concealment: list[tuple[str, str]] | None = None,
    context_reason: str | None = None,
) -> RuleReport:
    """Run every detector across every channel and total the evidence.

    `context_reason`, when given, records an out-of-band reason to treat this
    item as already suspect -- currently only "it did not match the schema".
    It opens the context gate and contributes its own weight.
    """
    report = RuleReport()
    concealment = concealment or []

    if context_reason:
        report.findings.append(
            Finding(
                "nonconforming_record",
                (
                    f"record does not conform to the feed's own schema ({context_reason}); "
                    f"the 'this is just how job ads are written' defence does not apply to it"
                ),
                weight=NONCONFORMING_WEIGHT,
                where="structured",
            )
        )
        report.score += NONCONFORMING_WEIGHT
        report.context_present = True

    channels: list[tuple[str, str, float]] = [
        ("title", title, 1.0),
        ("company", company, 1.0),
        ("visible", visible, 1.0),
        ("hidden", hidden, HIDDEN_MULTIPLIER),
    ]
    report.channels_scanned = [name for name, text, _ in channels if text.strip()]

    # Concealment is evidence in its own right, and it is what gates the
    # context-dependent detectors even when no addressing cue is present.
    #
    # Because opening that gate turns other detectors on, anything listed here
    # is effectively stronger than its own weight. Techniques with an innocent
    # explanation are therefore recorded at zero and do not open the gate --
    # see SUSPICIOUS_ZERO_WIDTH in textutil for the false positive that taught
    # me this.
    for technique, detail in concealment:
        if technique in NON_CONCEALING:
            report.findings.append(
                Finding(f"noted_{technique}", detail, 0, "hidden")
            )
            continue

        weight = 45 if technique in {"html_comment", "css_hidden", "hidden_attr"} else 30
        report.findings.append(
            Finding(
                code=f"concealed_{technique}",
                detail=f"content concealed from human readers via {technique}: {detail}",
                weight=weight,
                where="hidden",
            )
        )
        report.score += weight
        report.context_present = True

    # Pass 1: addressing cues and standalone-unambiguous detectors.
    for name, text, mult in channels:
        if not text.strip():
            continue

        for det in ADDRESSING_CUES:
            m = det.pattern.search(text)
            if m:
                w = int(det.weight * mult)
                report.findings.append(
                    Finding(det.code, f"{det.claim} — matched {_quote(m)}", w, name)
                )
                report.score += w
                report.context_present = True

        for det in STRONG:
            m = det.pattern.search(text)
            if m:
                w = int(det.weight * mult)
                report.findings.append(
                    Finding(det.code, f"{det.claim} — matched {_quote(m)}", w, name)
                )
                report.score += w
                report.context_present = True

    # Pass 1b: instruction-shaped but human-directed. Recorded, never scored.
    for name, text, _mult in channels:
        if not text.strip():
            continue
        for det in INFORMATIONAL:
            m = det.pattern.search(text)
            if m:
                report.findings.append(
                    Finding(det.code, f"{det.claim} — matched {_quote(m)}", 0, name)
                )

    # Pass 2: context-gated detectors, only once we know something is off.
    for name, text, mult in channels:
        if not text.strip():
            continue
        for det in CONTEXTUAL:
            m = det.pattern.search(text)
            if not m:
                continue
            if report.context_present:
                w = int(det.weight * mult)
                report.findings.append(
                    Finding(det.code, f"{det.claim} — matched {_quote(m)}", w, name)
                )
                report.score += w
            else:
                # Recorded at zero weight. This is deliberate: the log should
                # show what was considered and consciously not counted, so a
                # reviewer can see the gate working rather than infer it.
                report.findings.append(
                    Finding(
                        f"{det.code}_ungated",
                        (
                            f"pattern matched {_quote(m)} but scored 0: no addressing cue or "
                            f"concealment in this item, and this phrasing is common in ordinary "
                            f"job copy, so on its own it is not evidence"
                        ),
                        0,
                        name,
                    )
                )

    report.score = min(report.score, 100)
    return report


def _quote(m: re.Match[str], limit: int = 90) -> str:
    """The matched span, flattened, so the log shows what actually fired."""
    text = " ".join(m.group(0).split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return f"{text!r}"
