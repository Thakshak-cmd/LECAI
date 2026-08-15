"""Turning source HTML into text, while keeping track of what a human would see.

Job descriptions on both boards are HTML written by the poster. That matters
more than it first appears, because it splits the content into two channels:

* what a **human reviewer** sees in a browser, and
* what the **agent** sees after parsing.

Anything in the gap between them is an attack surface. Text inside an HTML
comment, a `display:none` div, or a zero-width character run is invisible to
the person who would otherwise catch the problem, but perfectly legible to a
model. An instruction placed there is strictly better for an attacker than one
in the visible body, because nobody reviewing the listing will ever see it.

So extraction returns both channels separately. `hidden` is not noise to be
stripped -- it is evidence, and the rules tier scores it far more harshly than
the same words appearing in `visible`.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser

#: Characters with no visual width, used to break up keywords ("ig​nore")
#: or to smuggle whole payloads past naive filters.
ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
}

#: Soft hyphen is deliberately excluded from the suspicious set. It is ordinary
#: typography -- a hyphenation hint -- and it survives copy-paste out of Word
#: and PDF, so it turns up in perfectly innocent job descriptions.
#:
#: Counting it as concealment cost me a real false positive: a University of
#: Patanjali listing carried exactly one U+00AD, which scored as "hidden
#: content", which opened the context gate, which in turn let an ordinary
#: "email provc@uop.edu.in" match count as exfiltration. Final score 85 and a
#: legitimate university posting was rejected as an attack.
#:
#: The lesson is about cascades rather than about hyphens. A weak signal that
#: unlocks stronger detectors is not weak any more, so anything holding a gate
#: open has to be much more certain than its own weight suggests.
SUSPICIOUS_ZERO_WIDTH = {
    ch: name for ch, name in ZERO_WIDTH.items() if ch != "­"
}

#: Bidirectional control characters. These can visually reorder text, so what a
#: human reads and what the parser sees genuinely differ.
BIDI_CONTROL = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

_INVISIBLE_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?!\.[1-9])"
    r"|font-size\s*:\s*0"
    r"|text-indent\s*:\s*-\d{3,}"
    r"|(?:left|top)\s*:\s*-\d{3,}px"
    r"|clip\s*:\s*rect\(0",
    re.I,
)

_SKIP_CONTENT = {"script", "style", "noscript"}


@dataclass
class Extracted:
    """The two channels, plus the encoding tricks found along the way."""

    visible: str = ""
    hidden: str = ""
    #: (technique, detail) pairs describing *how* something was concealed.
    concealment: list[tuple[str, str]] = field(default_factory=list)

    @property
    def has_hidden_content(self) -> bool:
        return bool(self.hidden.strip()) or bool(self.concealment)


class _Splitter(HTMLParser):
    """Walks the document tracking whether the current node is visible.

    Uses stdlib `html.parser` rather than a regex or a new dependency: regexes
    on HTML break on exactly the malformed markup an attacker would supply.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.concealment: list[tuple[str, str]] = []
        self._hidden_depth = 0
        self._skip_depth = 0
        self._stack: list[tuple[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrd = {k.lower(): (v or "") for k, v in attrs}
        hides = False

        style = attrd.get("style", "")
        if style and _INVISIBLE_STYLE.search(style):
            hides = True
            self.concealment.append(("css_hidden", f"<{tag} style={style.strip()[:80]!r}>"))

        if attrd.get("hidden") is not None and "hidden" in attrd:
            hides = True
            self.concealment.append(("hidden_attr", f"<{tag} hidden>"))

        if attrd.get("aria-hidden", "").lower() == "true":
            hides = True
            self.concealment.append(("aria_hidden", f"<{tag} aria-hidden=true>"))

        if tag in _SKIP_CONTENT:
            self._skip_depth += 1

        self._stack.append((tag, hides))
        if hides:
            self._hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT and self._skip_depth > 0:
            self._skip_depth -= 1
        # Unwind to the matching open tag; malformed markup is common here.
        for i in range(len(self._stack) - 1, -1, -1):
            name, hides = self._stack[i]
            if name == tag:
                if hides:
                    self._hidden_depth = max(0, self._hidden_depth - 1)
                del self._stack[i:]
                return

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        if self._hidden_depth > 0:
            self.hidden.append(data)
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        # Never rendered, always parsed. The cheapest place to hide a payload.
        if data.strip():
            self.hidden.append(data)
            self.concealment.append(("html_comment", f"<!--{data.strip()[:80]}-->"))


def extract(html: str) -> Extracted:
    """Split HTML into what a human sees and what only the machine sees."""
    parser = _Splitter()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must not stop a run
        # Fall back to a crude strip; better a degraded reading than none.
        text = re.sub(r"<[^>]+>", " ", html)
        return _finish(text, "", [("parse_failed", "HTML parser raised; used fallback strip")])

    return _finish(
        "".join(parser.visible),
        "".join(parser.hidden),
        parser.concealment,
    )


def _finish(visible: str, hidden: str, concealment: list[tuple[str, str]]) -> Extracted:
    combined = visible + hidden

    soft = combined.count("­")
    if soft:
        concealment.append((
            "soft_hyphen",
            f"{soft}x SOFT HYPHEN (U+00AD) — ordinary typographic hyphenation, "
            f"reported for completeness and explicitly not treated as concealment",
        ))

    for ch, name in SUSPICIOUS_ZERO_WIDTH.items():
        # Only word-internal occurrences count. That is the actual attack
        # signature -- splitting a keyword so a literal match fails ("ig<ZWSP>nore").
        # The same character between words is almost always encoding debris.
        internal = len(re.findall(rf"(?<=\w){re.escape(ch)}(?=\w)", combined))
        if internal:
            concealment.append((
                "zero_width",
                f"{internal}x {name} (U+{ord(ch):04X}) inside words — splits keywords "
                f"so that literal matching fails",
            ))

    bidi = sum(combined.count(c) for c in BIDI_CONTROL)
    if bidi:
        concealment.append(("bidi_control", f"{bidi} bidirectional control character(s)"))

    # Homoglyph-ish signal: Cyrillic or Greek letters inside otherwise-Latin
    # text are a standard way to defeat keyword matching ("іgnore" with U+0456).
    scripts = {
        "CYRILLIC" if "CYRILLIC" in unicodedata.name(c, "") else
        "GREEK" if "GREEK" in unicodedata.name(c, "") else ""
        for c in combined if c.isalpha() and ord(c) > 127
    }
    for script in sorted(s for s in scripts if s):
        concealment.append(("mixed_script", f"{script} letters mixed into Latin text"))

    return Extracted(
        visible=_normalise(visible),
        hidden=_normalise(hidden),
        concealment=concealment,
    )


def _normalise(text: str) -> str:
    for ch in ZERO_WIDTH:
        text = text.replace(ch, "")
    for ch in BIDI_CONTROL:
        text = text.replace(ch, "")
    return re.sub(r"[ \t ]+", " ", text).strip()


#: Sequences that only occur when UTF-8 bytes were decoded as Latin-1.
_MOJIBAKE_HINT = re.compile(r"[ÃÂâ][\x80-\xbf-¿–—“”’]")


def repair_mojibake(text: str) -> str:
    """Undo one round of UTF-8-decoded-as-Latin-1, if that is what happened.

    Not a hypothetical: RemoteOK serves "Forces armÃ©es canadiennes" for
    "Forces armées canadiennes" today. This is the source's own encoding bug,
    upstream of me, and it matters here because company names are matched
    across boards -- a mojibaked name will never equal its clean counterpart,
    so corroboration silently fails for every accented employer.

    Conservative by construction: the repair is attempted only when the text
    shows the signature byte pattern, and is kept only if it round-trips
    cleanly. Anything else is returned untouched.
    """
    if not text or not _MOJIBAKE_HINT.search(text):
        return text
    try:
        repaired = text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text
    # Keep it only if it removed the signature without introducing replacements.
    if "�" in repaired:
        return text
    return repaired


def collapse(text: str, limit: int | None = None) -> str:
    flat = " ".join(text.split())
    if limit and len(flat) > limit:
        return flat[: limit - 1] + "…"
    return flat
