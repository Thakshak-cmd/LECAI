# Decision trails

Generated from the committed logs by `tools/render_trail.py` — this is what the agent actually emitted, not a hand-written illustration. The full machine-readable records are [`run-live-data-only.jsonl`](run-live-data-only.jsonl) (1,029 events) and [`run-with-injected-attacks.jsonl`](run-with-injected-attacks.jsonl) (470 events).

Regenerate any view yourself:

```bash
gatekeeper log examples/run-live-data-only.jsonl --ref remoteok:0
gatekeeper verify examples/run-live-data-only.jsonl
```

---

## 1. A real instruction, found in live data

The first element of RemoteOK's API response is not a job posting — it is the API terms of service, addressed to whoever is consuming the feed, with a threatened consequence for non-compliance. Benign in intent, and structurally identical to an attack.

Nothing special-cases it. The agent notices a record that fails the feed's own schema, screens it like everything else, and concludes it is an instruction rather than data.

**`SCREEN`**  ·  step `screen:remoteok:0`
> remoteok:0 (non-job record): INSTRUCTION via rules

- `rules_score` — deterministic score 75/100 -> band 'instruction' (thresholds: ≥70 instruction, ≥25 ambiguous); channels scanned: visible [structured]
- `nonconforming_record` — record does not conform to the feed's own schema (record has no 'position'/'company', so it is not a job posting; fields present: last_updated, legal); the 'this is just how job ads are written' defence does not apply to it [structured] (+25)
- `consumer_directive` — imposes an obligation on whoever is consuming the feed -- attribution demands, usage restrictions, or a threatened consequence for non-compliance. A job posting describes a job; it does not tell its reader what the reader must do — matched 'API Terms of Service' (+50)
- `schema_reason` — record has no 'position'/'company', so it is not a job posting; fields present: last_updated, legal
- `excerpt` — API Terms of Service: Please link back (with follow, and without nofollow!) to the URL on Remote OK and mention Remote OK as a source, so we get traffic back from your site. If you do not we'll have to suspend API access. Please don't use the Remote OK logo without written permission as it's a regi…

**`DECIDE`**  ·  step `decide:remoteok:0`
> remoteok:0 -> REJECT: <non-job record from remoteok>

- `disposition` — REJECT
- `because` — This record arrived through a data channel but is not data: record has no 'position'/'company', so it is not a job posting; fields present: last_updated, legal. Screening called it INSTRUCTION. It is not a job posting, so there is nothing here to act on either way; recording it and moving on.


---

## 2. A posting the agent chose to act on

All four stages for a single item: screening (is it safe?), consistency (is it coherent?), relevance (do I want it?), and the decision that combines them. Note that the agent then *spent a network request* to try to corroborate the employer, and recorded that it failed to — without downgrading the candidate for it.

**`SCREEN`**  ·  step `screen:remoteok:1136594`
> remoteok:1136594 'Senior Data Engineer @ Lemon.io': DATA via rules

- `rules_score` — deterministic score 0/100 -> band 'clean' (thresholds: ≥70 instruction, ≥25 ambiguous); channels scanned: title, company, visible [structured]
- `human_directed_canary` — an anti-bot canary aimed at human applicants (RemoteOK adds these). A genuine instruction in a data field, from a legitimate source, with no hostile intent -- noted and deliberately not obeyed — matched 'mention the word'

**`CONSISTENCY`**  ·  step `consistency:remoteok:1136594`
> remoteok:1136594: 0 failed / 2 checks, severity 0

- `remote_claim_consistent` — structured remote=True is not contradicted by the description
- `cross_source_unavailable` — no listing from 'lemon io' on the other board, so nothing to corroborate against. Measured overlap between these two boards is ~1%, so this is the normal case and not a negative signal — but it does mean this posting rests on a single source.

**`NOTE`**  ·  step `relevance:remoteok:1136594`
> remoteok:1136594: relevance 82 vs threshold (match)

- `relevance_core` — matched /\bai\b/ (+12)
- `relevance_core` — matched /\bml\b|machine learning/ (+14)
- `relevance_core` — matched /\bllm|large language model/ (+18)
- `relevance_core` — matched /\bagent(ic)?\b/ (+14)
- `relevance_core` — matched /data scien/ (+8)
- `relevance_core` — matched /\bpython\b/ (+8)
- `relevance_bonus` — matched /\bremote\b/ (+8)

**`DECIDE`**  ·  step `decide:remoteok:1136594`
> remoteok:1136594 -> ACT: Senior Data Engineer @ Lemon.io

- `disposition` — ACT
- `because` — Relevant (relevance 82 vs threshold (match)), no hostile content, and every consistency check passed. Shortlisted.

**`FETCH`**  ·  step `corroborate:remoteok:1136594`
> replayed https://hn.algolia.com/api/v1/search?query=Lemon.io&tags=story&hitsPerPage=5 -> HTTP 200, 7570 bytes

- `source_offline` — served from committed cassette

**`CONSISTENCY`**  ·  step `corroborated:remoteok:1136594`
> remoteok:1136594: HN corroboration for 'Lemon.io' -> inconclusive

- `corroboration_result` — 5 HN result(s) returned but none name this company in the title -- loose keyword matches only, so this is no evidence either way
- `corroboration_titles` — (no matching story titles)
- `corroboration_limits` — HN presence supports existence; HN absence proves nothing, since most employers are never discussed there. Not used to downgrade anyone.


---

## 3. Clean content that is still not safe to act on

No prompt injection anywhere in this posting. It is flagged because it contradicts itself: published as remote, while the description requires physical presence. An agent that only defended against prompt attacks would have forwarded this happily.

**`CONSISTENCY`**  ·  step `consistency:remoteok:1136723`
> remoteok:1136723: 2 failed / 3 checks, severity 50

- `remote_claim_contradicted_FAILED` — listing is published as remote, but the description requires physical presence — matched 'on site'. One of the two is wrong, and a candidate filtering on 'remote' would be misled.
- `remote_with_fixed_location_FAILED` — published as remote but tied to the specific location 'Edinburgh,'; on a remote-only board this usually means the listing is region-locked rather than genuinely remote
- `cross_source_unavailable` — no listing from 'bae systems australia' on the other board, so nothing to corroborate against. Measured overlap between these two boards is ~1%, so this is the normal case and not a negative signal — but it does mean this posting rests on a single source.

**`DECIDE`**  ·  step `decide:remoteok:1136723`
> remoteok:1136723 -> FLAG: 1st Class Machinist @ BAE Systems Australia

- `disposition` — FLAG
- `because` — Content screening found nothing hostile, but the posting contradicts itself or carries fraud markers (severity 50: remote_claim_contradicted, remote_with_fixed_location). Coherence failures are not prompt injection, and they are still a reason not to act.


---

## 4. The agent revising its own earlier conclusions

From the run with labelled synthetic attacks spliced in (`--inject 8`); the attacks are marked synthetic in that log and in `corpus/adversarial.jsonl`.

As attacks accumulate, trust in the source falls. Crossing the floor changes posture, and items the agent had **already cleared earlier in the same run** are pulled back and re-examined under the stricter standard. This is the part that cannot be replaced by a script: the agent's later observations change what it believes about its earlier ones.

**`NOTE`**  ·  step `trust:remoteok:2`
> trust in 'remoteok' 100 -> 70 after a INSTRUCTION verdict

- `trust_lowered` — INSTRUCTION content found on 'remoteok'; -30 points

**`NOTE`**  ·  step `trust:remoteok:7`
> trust in 'remoteok' 70 -> 40 after a INSTRUCTION verdict

- `trust_lowered` — INSTRUCTION content found on 'remoteok'; -30 points
- `posture_change` — trust crossed below 60: this source is now treated as compromised. Items already cleared from it are queued for re-screening under the stricter standard.

**`PLAN`**  ·  step `plan:8`
> step 8: RESCREEN -> remoteok:1136695

- `chosen_because` — trust in 'remoteok' fell to 40 (below 60) after hostile content was found there, so 4 item(s) cleared under the earlier posture must be re-examined before anything is acted on
- `alternative_not_taken` — continue triaging 43 unseen item(s) first

**`DECIDE`**  ·  step `rescreen:remoteok:1136695`
> re-screen remoteok:1136695: unchanged (IGNORE)

- `rescreen_trigger` — source 'remoteok' fell below the trust floor
- `rescreen_outcome` — Legitimate content, but not what this profile is looking for (relevance 0 vs threshold (no match)). Ignored deliberately, not discarded silently. Re-screened after 'remoteok' was marked compromised; nothing in this item was borderline (rules score 0, consistency severity 15), so the original verdict stands.

**`PLAN`**  ·  step `plan:9`
> step 9: RESCREEN -> remoteok:1136596

- `chosen_because` — trust in 'remoteok' fell to 40 (below 60) after hostile content was found there, so 3 item(s) cleared under the earlier posture must be re-examined before anything is acted on
- `alternative_not_taken` — continue triaging 43 unseen item(s) first

**`DECIDE`**  ·  step `rescreen:remoteok:1136596`
> re-screen remoteok:1136596: unchanged (IGNORE)

- `rescreen_trigger` — source 'remoteok' fell below the trust floor
- `rescreen_outcome` — Legitimate content, but not what this profile is looking for (relevance 14 vs threshold (no match)). Ignored deliberately, not discarded silently. Re-screened after 'remoteok' was marked compromised; nothing in this item was borderline (rules score 0, consistency severity 15), so the original verdict stands.

**`PLAN`**  ·  step `plan:10`
> step 10: RESCREEN -> remoteok:1136576

- `chosen_because` — trust in 'remoteok' fell to 40 (below 60) after hostile content was found there, so 2 item(s) cleared under the earlier posture must be re-examined before anything is acted on
- `alternative_not_taken` — continue triaging 43 unseen item(s) first

**`DECIDE`**  ·  step `rescreen:remoteok:1136576`
> re-screen remoteok:1136576: unchanged (IGNORE)

- `rescreen_trigger` — source 'remoteok' fell below the trust floor
- `rescreen_outcome` — Legitimate content, but not what this profile is looking for (relevance 14 vs threshold (no match)). Ignored deliberately, not discarded silently. Re-screened after 'remoteok' was marked compromised; nothing in this item was borderline (rules score 0, consistency severity 15), so the original verdict stands.

**`PLAN`**  ·  step `plan:11`
> step 11: RESCREEN -> remoteok:1136585

- `chosen_because` — trust in 'remoteok' fell to 40 (below 60) after hostile content was found there, so 1 item(s) cleared under the earlier posture must be re-examined before anything is acted on
- `alternative_not_taken` — continue triaging 43 unseen item(s) first

**`DECIDE`**  ·  step `rescreen:remoteok:1136585`
> re-screen remoteok:1136585: unchanged (IGNORE)

- `rescreen_trigger` — source 'remoteok' fell below the trust floor
- `rescreen_outcome` — Legitimate content, but not what this profile is looking for (relevance 14 vs threshold (no match)). Ignored deliberately, not discarded silently. Re-screened after 'remoteok' was marked compromised; nothing in this item was borderline (rules score 0, consistency severity 15), so the original verdict stands.

**`NOTE`**  ·  step `trust:remoteok:16`
> trust in 'remoteok' 40 -> 10 after a INSTRUCTION verdict

- `trust_lowered` — INSTRUCTION content found on 'remoteok'; -30 points

**`NOTE`**  ·  step `trust:remoteok:49`
> trust in 'remoteok' 10 -> 0 after a INSTRUCTION verdict

- `trust_lowered` — INSTRUCTION content found on 'remoteok'; -30 points


---

## 5. Why each step was chosen, and what was passed over

Every planning step records the action, the reason, and the alternatives that were available and not taken. Alternatives are what let a reviewer tell a decision from a rationalisation.

**`PLAN`**  ·  step `plan:1`
> step 1: FETCH_BOARD -> remoteok

- `chosen_because` — no source has been read yet, so there is nothing to reason about; fetching the first board is the only action that produces information

**`PLAN`**  ·  step `plan:1`
> step 1: FETCH_BOARD -> remoteok

- `chosen_because` — no source has been read yet, so there is nothing to reason about; fetching the first board is the only action that produces information

**`PLAN`**  ·  step `plan:103`
> step 103: FETCH_BOARD -> arbeitnow

- `chosen_because` — only 1 of 99 wanted candidate(s) found so far, and 1 of them rest on a single unverified source; fetching 'arbeitnow' to improve on that
- `alternative_not_taken` — stop now and report a short, single-source result

**`PLAN`**  ·  step `plan:204`
> step 204: CORROBORATE -> remoteok:1136594

- `chosen_because` — 'Senior Data Engineer @ Lemon.io' is relevant (score 82) but unverified: no second board lists this employer. Spending 1 of 5 remaining external lookups to check whether the company has any public footprint
- `alternative_not_taken` — accept it on a single source
- `alternative_not_taken` — flag it without checking

**`PLAN`**  ·  step `plan:205`
> step 205: CORROBORATE -> arbeitnow:cybersecurity-working-student-munchen-351085

- `chosen_because` — 'Cybersecurity Working Student (m/w/d) @ Trusteq Gmbh' is relevant (score 43) but unverified: no second board lists this employer. Spending 1 of 4 remaining external lookups to check whether the company has any public footprint
- `alternative_not_taken` — accept it on a single source
- `alternative_not_taken` — flag it without checking
