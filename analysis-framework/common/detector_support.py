"""Shared input normalization for family detectors."""
from __future__ import annotations
from malware_io import ArchiveValidationError, read_single_aes_zip_member, sha256_bytes

def unwrap_single_submission(data: bytes, password: str = "infected") -> tuple[bytes, str, str | None]:
    """Unwrap a single-member ZIP when possible, otherwise keep the original bytes.

    Multi-member ZIPs are intentionally returned unchanged for structural detectors.
    The optional error is diagnostic and is not itself a family match.
    """
    if not data.startswith(b"PK"):
        return data, "", None
    try:
        member = read_single_aes_zip_member(data, password=password)
        return member.data, member.name, None
    except ArchiveValidationError as exc:
        return data, "", str(exc)

def known_campaign_result(data: bytes, campaigns: dict[str, str], signatures: list[tuple[bytes, str]]) -> dict:
    inner, member, unwrap_error = unwrap_single_submission(data)
    digest = sha256_bytes(inner)
    campaign = campaigns.get(digest)
    lower = inner[:6_000_000].lower()
    reasons = ["known inner SHA-256"] if campaign else []
    reasons.extend(description for token, description in signatures if token in lower)
    if not campaign and reasons:
        campaign = "unresolved_family_artifact"
    candidates = [] if not campaign else [{"campaign_type": campaign, "confidence": "high" if digest in campaigns else "medium", "reasons": reasons}]
    observations = {"inner_sha256": digest, "member": member}
    if unwrap_error and not member:
        observations["unwrap_note"] = unwrap_error
    return {"matched": bool(campaign or reasons), "observations": observations, "campaigns": candidates}
