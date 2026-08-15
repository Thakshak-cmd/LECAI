"""Coherence checks, including the negation bug that produced a real false positive."""

from __future__ import annotations

from gatekeeper.consistency import check_posting, cross_source
from gatekeeper.provenance import Origin, Trust, taint
from gatekeeper.sources.base import Posting

ORIGIN = Origin("remoteok", "https://remoteok.com/api", "[0]", Trust.UNTRUSTED,
                "2026-08-15T00:00:00Z", "00" * 32)


def _posting(description="", *, remote=None, location=None, title="Engineer",
             company="Acme", source="remoteok", item_id="1"):
    return Posting(
        item_id=item_id, source_id=source, url="https://x/1",
        title=taint(title, ORIGIN), company=taint(company, ORIGIN),
        description=taint(description, ORIGIN),
        remote_flag=remote, location=location,
    )


def _codes(report):
    return {c.code for c in report.checks}


def test_remote_flag_contradicted_by_body():
    r = check_posting(_posting("You must be on-site in our Berlin office five days a week.",
                               remote=True, location="Worldwide"))
    assert "remote_claim_contradicted" in _codes(r)
    assert r.severity > 0


def test_german_onsite_language_is_caught():
    """Arbeitnow is Germany-weighted; an English-only check would miss a third of it."""
    r = check_posting(_posting("Die Arbeit erfolgt vor Ort in unserem Büro.", remote=True))
    assert "remote_claim_contradicted" in _codes(r)


def test_consistent_remote_listing_passes():
    r = check_posting(_posting("Fully remote, work from anywhere.", remote=True, location="Worldwide"))
    assert "remote_claim_consistent" in _codes(r)
    assert r.severity == 0


def test_seniority_mismatch():
    r = check_posting(_posting("This is an entry-level graduate position.", title="Senior Engineer"))
    assert "seniority_mismatch" in _codes(r)


def test_scam_markers_fire_on_real_fraud_shape():
    r = check_posting(_posting(
        "A one-time training fee of $250 is required to activate your account. "
        "Contact us on Telegram @globalstaffing."
    ))
    assert "scam_applicant_pays" in _codes(r)
    assert "scam_off_channel_contact" in _codes(r)
    assert r.severity >= 50


def test_employer_declining_to_pay_an_agency_is_not_a_scam():
    """The American Bureau of Shipping false positive, locked in as a test.

    Two failures in one: the negation was ignored, and so was the direction of
    payment. The fraud is the applicant paying the employer.
    """
    real = (
        "Notice: ABS and Affiliated Companies will not pay a fee to any third-party agency "
        "without a valid ABS Master Service Agreement authorized and signed by Human Resources."
    )
    r = check_posting(_posting(real))
    assert "scam_applicant_pays" not in _codes(r)
    assert r.severity == 0


def test_cross_source_reports_absence_honestly():
    """~99% of the time there is nothing to corroborate against; that must be said."""
    check = cross_source(_posting(company="Unique Co"), [])
    assert check.code == "cross_source_unavailable"
    assert check.passed
    assert "single source" in check.detail


def test_cross_source_corroborates_across_boards():
    a = _posting(company="Bjak", source="remoteok", item_id="1")
    b = _posting(company="Bjak GmbH", source="arbeitnow", item_id="2")
    check = cross_source(a, [a, b])
    assert check.code == "cross_source_corroborated"


def test_cross_source_detects_conflicting_claims():
    a = _posting(company="Acme", source="remoteok", item_id="1", remote=True)
    b = _posting(company="Acme", source="arbeitnow", item_id="2", remote=False)
    check = cross_source(a, [a, b])
    assert check.code == "cross_source_disagreement"
    assert not check.passed


def test_empty_description_is_flagged():
    r = check_posting(_posting(""))
    assert "empty_description" in _codes(r)
