"""Snake Keylogger detectorのexact/structural routeを検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
DETECTOR_PATH = REPOSITORY / "analysis-framework" / "malware" / "snakekeylogger" / "detect.py"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

spec = importlib.util.spec_from_file_location("snakekeylogger_detect", DETECTOR_PATH)
assert spec is not None and spec.loader is not None
detector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector)


def _base_result() -> dict[str, object]:
    return {
        "matched": False,
        "observations": {"known_hash": False},
        "campaigns": [],
    }


def test_structural_route_requires_extractor_corroboration(monkeypatch) -> None:
    evidence = {
        "matched": True,
        "matched_groups": ["builder", "ftp", "keylogging", "smtp", "telegram"],
        "sample_executed": False,
        "network_contacted": False,
    }
    monkeypatch.setattr(detector, "detect_family", lambda *_args: _base_result())
    monkeypatch.setattr(detector, "structural_evidence", lambda _data: evidence)
    result = detector.detect(b"synthetic managed fixture", Path("fixture.exe"))
    assert result["matched"] is True
    assert result["observations"]["variant"] == "vipkeylogger"
    assert result["observations"]["builder_version"] == "4.4"
    assert result["observations"]["static_config_recovered"] is False
    assert result["campaigns"] == [
        {
            "campaign_type": "vipkeylogger_v44_managed_terminal",
            "confidence": "high",
            "reasons": ["builder、Telegram、SMTP/FTP/keyloggingの独立managed marker群が一致"],
        }
    ]


def test_detector_does_not_upgrade_without_structural_match(monkeypatch) -> None:
    base = _base_result()
    monkeypatch.setattr(detector, "detect_family", lambda *_args: base)
    monkeypatch.setattr(
        detector,
        "structural_evidence",
        lambda _data: {
            "matched": False,
            "matched_groups": ["smtp"],
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    assert detector.detect(b"generic SMTP client", Path("fixture.exe")) is base


def test_detector_rejects_shared_stealer_profile_without_vip_structure(
    monkeypatch,
) -> None:
    """共有する持出し機能だけでは別stealerをSnakeへ帰属させない。"""

    base = {
        "matched": True,
        "observations": {
            "profile_literal_correlation": True,
            "marker_hits": ["smtpclient", "ftpwebrequest", "keylogger"],
            "observed_config_keys": ["Host", "Port", "From", "To"],
        },
        "campaigns": [{"campaign_type": "reviewed_direct_payload_or_wrapper"}],
    }
    evidence = {
        "matched": False,
        "matched_groups": ["ftp", "keylogging", "smtp", "telegram"],
        "sample_executed": False,
        "network_contacted": False,
    }
    monkeypatch.setattr(detector, "detect_family", lambda *_args: base)
    monkeypatch.setattr(detector, "structural_evidence", lambda _data: evidence)
    monkeypatch.setattr(detector, "known_hashes", lambda _family: set())

    result = detector.detect(b"shared stealer profile", Path("fixture.exe"))

    assert result["matched"] is False
    assert result["campaigns"] == []
    assert result["observations"]["shared_profile_candidate"] is True
    assert result["observations"]["vip_structural_evidence"] == evidence
    assert result["observations"]["attribution_rejected_reason"] == (
        "reviewed_exact_hash_or_vip_structural_evidence_required"
    )


def test_detector_keeps_reviewed_exact_hash_without_vip_structure(monkeypatch) -> None:
    """完全SHA-256一致は既存のreview済みrouteを維持する。"""

    data = b"reviewed Snake fixture"
    base = {
        "matched": True,
        "observations": {"profile_literal_correlation": False},
        "campaigns": [{"campaign_type": "reviewed_direct_payload_or_wrapper"}],
    }
    monkeypatch.setattr(detector, "detect_family", lambda *_args: base)
    monkeypatch.setattr(
        detector,
        "structural_evidence",
        lambda _data: {
            "matched": False,
            "matched_groups": [],
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    monkeypatch.setattr(
        detector,
        "known_hashes",
        lambda _family: {hashlib.sha256(data).hexdigest()},
    )

    result = detector.detect(data, Path("fixture.exe"))

    assert result is base
    assert result["matched"] is True
    assert result["campaigns"]
