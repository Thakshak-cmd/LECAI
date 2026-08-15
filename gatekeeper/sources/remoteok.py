"""RemoteOK — https://remoteok.com/api (public JSON, no auth).

Attribution, as their API terms request: job data from RemoteOK
(https://remoteok.com). Those terms are worth reading, because of *where* they
live: the first element of the JSON array is not a job. It is a message
addressed to whoever is consuming the feed --

    "Please link back (with follow, and without nofollow!) to the URL on
     Remote OK ... If you do not we'll have to suspend API access."

That is a real, unplanted, imperative instruction arriving through a data
channel, on a live public API, today. Nobody put it there to test an agent. It
is benign in intent and I have honoured it in the line above.

It is also structurally identical to the attack this whole project is about: a
consumer that concatenates feed content into a prompt has just been handed an
instruction by a third party. The agent does not special-case it. It observes a
record that does not fit the job schema, screens it like anything else, and
concludes it is an instruction rather than data -- which is the correct reading.
"""

from __future__ import annotations

from gatekeeper.provenance import Origin, Trust, taint
from gatekeeper.sources.base import Anomaly, Posting
from gatekeeper.sources.http import Response
from gatekeeper.textutil import extract, repair_mojibake

SOURCE_ID = "remoteok"
URL = "https://remoteok.com/api"


def _origin(response: Response, path: str, trust: Trust) -> Origin:
    return Origin(
        source_id=SOURCE_ID,
        url=response.url,
        field_path=path,
        trust=trust,
        fetched_at=response.fetched_at,
        response_sha256=response.sha256,
    )


def parse(response: Response) -> tuple[list[Posting], list[Anomaly]]:
    payload = response.json()
    postings: list[Posting] = []
    anomalies: list[Anomaly] = []

    if not isinstance(payload, list):
        return [], [
            Anomaly(
                item_id="root",
                source_id=SOURCE_ID,
                url=response.url,
                reason=f"expected a JSON array, got {type(payload).__name__}",
                text=taint(response.body[:4000], _origin(response, "$", Trust.UNTRUSTED)),
            )
        ]

    for i, item in enumerate(payload):
        path = f"[{i}]"

        if not isinstance(item, dict):
            anomalies.append(
                Anomaly(
                    item_id=str(i),
                    source_id=SOURCE_ID,
                    url=response.url,
                    reason=f"array element is {type(item).__name__}, not an object",
                    text=taint(str(item)[:4000], _origin(response, path, Trust.UNTRUSTED)),
                    raw={},
                )
            )
            continue

        # The schema test is "does it have the fields a job must have", not
        # "is it at index 0". A feed can grow a second preamble record, or
        # reorder; positional assumptions would miss that.
        if not item.get("position") or not item.get("company"):
            present = ", ".join(sorted(item.keys())[:12]) or "(no keys)"
            blob = " ".join(
                str(v) for k, v in item.items() if isinstance(v, str) and len(str(v)) > 20
            )
            anomalies.append(
                Anomaly(
                    item_id=str(item.get("id") or i),
                    source_id=SOURCE_ID,
                    url=response.url,
                    reason=(
                        f"record has no 'position'/'company', so it is not a job posting; "
                        f"fields present: {present}"
                    ),
                    text=taint(blob[:6000], _origin(response, path, Trust.UNTRUSTED)),
                    origin=_origin(response, path, Trust.UNTRUSTED),
                    raw=item,
                )
            )
            continue

        html = item.get("description") or ""
        body = extract(html)

        postings.append(
            Posting(
                item_id=str(item.get("id") or i),
                source_id=SOURCE_ID,
                url=item.get("url") or item.get("apply_url") or response.url,
                title=taint(repair_mojibake(str(item.get("position", ""))), _origin(response, f"{path}.position", Trust.LABEL)),
                company=taint(repair_mojibake(str(item.get("company", ""))), _origin(response, f"{path}.company", Trust.LABEL)),
                description=taint(repair_mojibake(body.visible), _origin(response, f"{path}.description", Trust.UNTRUSTED)),
                # RemoteOK is a remote-only board, so every listing asserts
                # remote=true by construction. That claim is checked against
                # the description later -- it is frequently wrong.
                remote_flag=True,
                location=(item.get("location") or "").strip() or None,
                tags=[str(t) for t in (item.get("tags") or [])][:20],
                posted_at=item.get("date"),
                origin=_origin(response, path, Trust.STRUCTURED),
                raw={
                    "salary_min": item.get("salary_min"),
                    "salary_max": item.get("salary_max"),
                    "hidden_text": body.hidden,
                    "concealment": body.concealment,
                    "description_html_len": len(html),
                },
            )
        )

    return postings, anomalies
