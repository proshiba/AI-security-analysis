"""Snake Keylogger detectorのexact/structural routeを検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
DETECTOR_PATH = (
    REPOSITORY / "analysis-framework" / "malware" / "snakekeylogger" / "detect.py"
)
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
            "reasons": [
                "builder、Telegram、SMTP/FTP/keyloggingの独立managed marker群が一致"
            ],
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
