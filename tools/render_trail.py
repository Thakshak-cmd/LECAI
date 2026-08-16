"""Render selected decision trails from an audit log as readable Markdown.

The JSONL log is the machine-readable record and it is deliberately verbose --
about a megabyte for a full run. That is correct for an audit artefact and
useless for a human opening the repository in a browser.

This produces the human view: a handful of complete trails, generated from real
committed logs rather than written by hand, so what a reviewer reads is what
the agent actually emitted.

Run: python tools/render_trail.py > examples/DECISION-TRAIL.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LIVE = REPO / "examples" / "run-live-data-only.jsonl"
INJECTED = REPO / "examples" / "run-with-injected-attacks.jsonl"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def fmt(event: dict, indent: str = "") -> str:
    out = [f"{indent}**`{event['kind']}`**  ·  step `{event['step_id']}`"]
    out.append(f"{indent}> {event['summary']}")
    if event.get("findings"):
        out.append("")
        for f in event["findings"]:
            detail = " ".join(f["detail"].split())
            out.append(f"{indent}- `{f['code']}` — {detail}")
    return "\n".join(out) + "\n"


def trail_for(events: list[dict], ref: str, kinds: set[str] | None = None) -> list[dict]:
    return [
        e for e in events
        if (ref in e["step_id"] or ref in e["summary"])
        and (kinds is None or e["kind"] in kinds)
    ]


def section(title: str, blurb: str, events: list[dict]) -> str:
    parts = [f"## {title}\n", blurb + "\n"]
    for e in events:
        parts.append(fmt(e))
    return "\n".join(parts)


def main() -> None:
    live = load(LIVE)
    inj = load(INJECTED)

    out: list[str] = []
    out.append(
        "# Decision trails\n\n"
        "Generated from the committed logs by `tools/render_trail.py` — this is what the "
        "agent actually emitted, not a hand-written illustration. The full machine-readable "
        f"records are [`run-live-data-only.jsonl`](run-live-data-only.jsonl) "
        f"({len(live):,} events) and "
        f"[`run-with-injected-attacks.jsonl`](run-with-injected-attacks.jsonl) "
        f"({len(inj):,} events).\n\n"
        "Regenerate any view yourself:\n\n"
        "```bash\n"
        "gatekeeper log examples/run-live-data-only.jsonl --ref remoteok:0\n"
        "gatekeeper verify examples/run-live-data-only.jsonl\n"
        "```\n\n---\n"
    )

    # 1. The centrepiece: a real instruction arriving in a data channel.
    ev = trail_for(live, "remoteok:0", {"SCREEN", "DECIDE"})
    out.append(section(
        "1. A real instruction, found in live data",
        "The first element of RemoteOK's API response is not a job posting — it is the "
        "API terms of service, addressed to whoever is consuming the feed, with a "
        "threatened consequence for non-compliance. Benign in intent, and structurally "
        "identical to an attack.\n\n"
        "Nothing special-cases it. The agent notices a record that fails the feed's own "
        "schema, screens it like everything else, and concludes it is an instruction "
        "rather than data.",
        ev,
    ))
    out.append("\n---\n")

    # 2. A full shortlist trail, all four stages.
    act = next(
        (e for e in live if e["kind"] == "DECIDE" and e["data"].get("action") == "ACT"
         and e["data"].get("relevance", 0) >= 40),
        None,
    )
    if act:
        ref = act["data"]["ref"]
        ev = [e for e in live if ref in e["step_id"]]
        out.append(section(
            "2. A posting the agent chose to act on",
            "All four stages for a single item: screening (is it safe?), consistency "
            "(is it coherent?), relevance (do I want it?), and the decision that "
            "combines them. Note that the agent then *spent a network request* to try to "
            "corroborate the employer, and recorded that it failed to — without "
            "downgrading the candidate for it.",
            ev,
        ))
        out.append("\n---\n")

    # 3. Coherence failure with no injection involved.
    flag = next(
        (e for e in live if e["kind"] == "DECIDE" and e["data"].get("action") == "FLAG"),
        None,
    )
    if flag:
        ref = flag["data"]["ref"]
        ev = [e for e in live if ref in e["step_id"] and e["kind"] in {"CONSISTENCY", "DECIDE"}]
        out.append(section(
            "3. Clean content that is still not safe to act on",
            "No prompt injection anywhere in this posting. It is flagged because it "
            "contradicts itself: published as remote, while the description requires "
            "physical presence. An agent that only defended against prompt attacks would "
            "have forwarded this happily.",
            ev,
        ))
        out.append("\n---\n")

    # 4. The feedback loop, from the injected run.
    ev = [
        e for e in inj
        if (e["kind"] == "NOTE" and "trust in" in e["summary"])
        or (e["kind"] == "DECIDE" and "rescreen" in e["step_id"])
        or (e["kind"] == "PLAN" and e["data"].get("action") == "RESCREEN")
    ][:12]
    out.append(section(
        "4. The agent revising its own earlier conclusions",
        "From the run with labelled synthetic attacks spliced in (`--inject 8`); the "
        "attacks are marked synthetic in that log and in `corpus/adversarial.jsonl`.\n\n"
        "As attacks accumulate, trust in the source falls. Crossing the floor changes "
        "posture, and items the agent had **already cleared earlier in the same run** are "
        "pulled back and re-examined under the stricter standard. This is the part that "
        "cannot be replaced by a script: the agent's later observations change what it "
        "believes about its earlier ones.",
        ev,
    ))
    out.append("\n---\n")

    # 5. Planner reasoning, including roads not taken.
    plans = [e for e in live if e["kind"] == "PLAN"]
    picked = [plans[0]] + [p for p in plans if p["data"]["action"] in {"FETCH_BOARD", "CORROBORATE", "STOP"}][:4]
    out.append(section(
        "5. Why each step was chosen, and what was passed over",
        "Every planning step records the action, the reason, and the alternatives that "
        "were available and not taken. Alternatives are what let a reviewer tell a "
        "decision from a rationalisation.",
        picked,
    ))

    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()
