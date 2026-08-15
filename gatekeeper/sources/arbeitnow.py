"""Arbeitnow — https://www.arbeitnow.com/api/job-board-api (public JSON, no auth).

Chosen as the second board specifically because it disagrees with the first in
useful ways:

* It carries an explicit `remote` boolean, where RemoteOK asserts remote by
  construction. That gives the consistency layer a *structured* claim to test
  the free text against, rather than two pieces of prose to compare.
* It is Germany-weighted and largely on-site; RemoteOK is global and remote.
  Company overlap between the two is about 1%, measured. That is inconvenient
  and it is the honest situation: corroboration is usually unavailable, so the
  agent has to be able to say so and decide anyway.
* Its descriptions are richer HTML, which is where hidden-channel content shows
  up if it shows up anywhere.
"""

from __future__ import annotations

from datetime import UTC, datetime

from gatekeeper.provenance import Origin, Trust, taint
from gatekeeper.sources.base import Anomaly, Posting
from gatekeeper.sources.http import Response
from gatekeeper.textutil import extract

SOURCE_ID = "arbeitnow"
URL = "https://www.arbeitnow.com/api/job-board-api"


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

    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return [], [
            Anomaly(
                item_id="root",
                source_id=SOURCE_ID,
                url=response.url,
                reason="response is not an object with a 'data' array",
                text=taint(response.body[:4000], _origin(response, "$", Trust.UNTRUSTED)),
            )
        ]

    for i, item in enumerate(payload["data"]):
        path = f"data[{i}]"

        if not isinstance(item, dict) or not item.get("title") or not item.get("company_name"):
            present = ", ".join(sorted(item.keys())[:12]) if isinstance(item, dict) else "(not an object)"
            anomalies.append(
                Anomaly(
                    item_id=str(i),
                    source_id=SOURCE_ID,
                    url=response.url,
                    reason=f"record has no 'title'/'company_name'; fields present: {present}",
                    text=taint(str(item)[:6000], _origin(response, path, Trust.UNTRUSTED)),
                    origin=_origin(response, path, Trust.UNTRUSTED),
                    raw=item if isinstance(item, dict) else {},
                )
            )
            continue

        html = item.get("description") or ""
        body = extract(html)

        created = item.get("created_at")
        posted_at = None
        if isinstance(created, (int, float)):
            posted_at = datetime.fromtimestamp(created, UTC).isoformat(timespec="seconds")

        postings.append(
            Posting(
                item_id=str(item.get("slug") or i),
                source_id=SOURCE_ID,
                url=item.get("url") or response.url,
                title=taint(str(item.get("title", "")), _origin(response, f"{path}.title", Trust.LABEL)),
                company=taint(str(item.get("company_name", "")), _origin(response, f"{path}.company_name", Trust.LABEL)),
                description=taint(body.visible, _origin(response, f"{path}.description", Trust.UNTRUSTED)),
                remote_flag=bool(item.get("remote")) if "remote" in item else None,
                location=(item.get("location") or "").strip() or None,
                tags=[str(t) for t in (item.get("tags") or [])][:20],
                posted_at=posted_at,
                origin=_origin(response, path, Trust.STRUCTURED),
                raw={
                    "job_types": item.get("job_types") or [],
                    "hidden_text": body.hidden,
                    "concealment": body.concealment,
                    "description_html_len": len(html),
                },
            )
        )

    return postings, anomalies
