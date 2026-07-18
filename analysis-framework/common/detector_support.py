"""Shared input normalization for conservative family detectors."""
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

def known_campaign_result(
    data: bytes,
    campaigns: dict[str, str],
    signatures: list[tuple[bytes, str]],
    *,
    minimum_signatures: int = 2,
) -> dict:
    """Match an exact reviewed hash or at least two independent literals.

    Signature literals are correlation evidence only. A single runtime or
    namespace string is retained in observations but cannot select a family.
    """
    if minimum_signatures < 2:
        raise ValueError("minimum_signatures must be at least two")
    inner, member, unwrap_error = unwrap_single_submission(data)
    digest = sha256_bytes(inner)
    campaign = campaigns.get(digest)
    lower = inner[:6_000_000].lower()
    matched_signatures: list[tuple[bytes, str]] = []
    seen_tokens: set[bytes] = set()
    for token, description in signatures:
        normalized = token.lower()
        if not normalized or normalized in seen_tokens or normalized not in lower:
            continue
        seen_tokens.add(normalized)
        matched_signatures.append((normalized, description))
    independent_signatures = [
        (token, description)
        for token, description in matched_signatures
        if not any(token != other and token in other for other, _description in matched_signatures)
    ]
    signature_hits = [description for _token, description in independent_signatures]
    reasons = ["known inner SHA-256"] if campaign else []
    if campaign or len(signature_hits) >= minimum_signatures:
        reasons.extend(signature_hits)
    if not campaign and len(signature_hits) >= minimum_signatures:
        campaign = "unresolved_family_artifact"
    candidates = [] if not campaign else [{"campaign_type": campaign, "confidence": "high" if digest in campaigns else "medium", "reasons": reasons}]
    observations = {
        "inner_sha256": digest,
        "member": member,
        "signature_hits": signature_hits,
        "signature_threshold": minimum_signatures,
    }
    if unwrap_error and not member:
        observations["unwrap_note"] = unwrap_error
    return {"matched": bool(campaign), "observations": observations, "campaigns": candidates}
