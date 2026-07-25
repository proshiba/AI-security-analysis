"""プロファイル定義型マルウェアで共有する保守的な検出器。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from functools import lru_cache
import sys

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from extractors.profiled_family import (  # noqa: E402
    _independent_marker_hits,
    bounded_strings,
    extract_family,
    profile_for,
)

SCRIPT_SUFFIXES = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".hta", ".bat", ".cmd"}


@lru_cache(maxsize=64)
def _known_hashes_cached(path: Path, mtime_ns: int, size: int) -> frozenset[str]:
    """file identity付きcacheからレビュー済みhashを読む。"""

    value = json.loads(path.read_text(encoding="utf-8"))
    return frozenset(str(item).lower() for item in value.get("known_sample_sha256") or [])


def known_hashes(family: str, framework: Path | None = None) -> set[str]:
    """変更済みcampaignレジストリも同一processで反映してhashを返す。"""

    framework = framework or Path(__file__).parents[1]
    path = framework / "malware" / family / "campaigns.json"
    if not path.is_file():
        return set()
    resolved = path.resolve(strict=True)
    stat = resolved.stat()
    return set(_known_hashes_cached(resolved, stat.st_mtime_ns, stat.st_size))


def clear_known_hash_cache() -> None:
    """レビュー済みhashのfile cacheを明示的に破棄する。"""

    _known_hashes_cached.cache_clear()


def campaign_type(family: str, path: Path, category: str, recovered: bool) -> str:
    """レビュー済み検体を安定した配布・設定campaign形状へ分類する。"""
    if path.suffix.lower() in SCRIPT_SUFFIXES:
        return "script_delivery"
    if category == "loader":
        return "staged_loader_or_container"
    if recovered:
        return "static_config_candidate_recovered"
    return "reviewed_direct_payload_or_wrapper"


def detect_family(family: str, data: bytes, path: Path) -> dict:
    """レビュー済み完全hashまたはmarker・設定key・network候補の相関を照合する。"""
    profile = profile_for(family)
    digest = hashlib.sha256(data).hexdigest()
    exact = digest in known_hashes(profile["family"])
    marker_probe = "\n".join(bounded_strings(data)).lower()
    prefilter_hits = _independent_marker_hits(profile["markers"], marker_probe)
    if not exact and len(prefilter_hits) < max(2, int(profile["minimum_markers"])):
        return {
            "matched": False,
            "observations": {
                "sha256": digest,
                "family": profile["family"],
                "category": profile["category"],
                "marker_hits": prefilter_hits,
                "observed_config_keys": [],
                "network_candidate_count": 0,
                "profile_literal_correlation": False,
                "decoded_config_recovered": False,
                "static_config_recovered": False,
                "prefilter": "insufficient_family_markers",
                "executed": False,
                "network_contacted": False,
            },
            "campaigns": [],
        }
    result = extract_family(profile["family"], data, path.name)
    config = result["config"]
    profile_correlated = bool(config.get("profile_literal_correlation"))
    decoded_config = bool(config.get("decoded_config_recovered"))
    matched = exact or profile_correlated
    campaign = campaign_type(profile["family"], path, profile["category"], decoded_config)
    reasons = []
    if exact:
        reasons.append("reviewed exact SHA-256 from the MalwareBazaar acquisition set")
    if profile_correlated:
        reasons.append(
            "independent profile literals plus config key and sanitized network candidate; config not decoded"
        )
    return {
        "matched": matched,
        "observations": {
            "sha256": digest,
            "family": profile["family"],
            "category": profile["category"],
            "marker_hits": config.get("marker_hits") or [],
            "observed_config_keys": config.get("observed_config_keys") or [],
            "network_candidate_count": len(result.get("findings") or []),
            "profile_literal_correlation": profile_correlated,
            "decoded_config_recovered": decoded_config,
            "static_config_recovered": decoded_config,
            "executed": False,
            "network_contacted": False,
        },
        "campaigns": []
        if not matched
        else [
            {
                "campaign_type": campaign,
                "confidence": "high" if exact else "medium",
                "reasons": reasons,
            }
        ],
    }
