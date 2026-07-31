"""OWAReaperのdetector／extractorを検証する。"""

from __future__ import annotations

import base64
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "malware" / "owareaper"
sys.path.insert(0, str(FAMILY))

import detect  # noqa: E402
import extract_config  # noqa: E402


def fixture_html() -> bytes:
    """fragment payloadを持つ合成HTMLを返す。"""

    payload = (
        b"OwaUserDefaultSettings owa_offline_db GetClientAccessToken "
        b"https://acocdn.com/assets/v1_packet asecdns.com"
    )
    encoded = base64.b64encode(payload).decode("ascii")
    midpoint = len(encoded) // 2
    return (
        "<html><img src='data:image/svg+xml;base64,AAAA#not:base64()'>"
        "<div contenteditable><span class='social-icon-first'>"
        "<img src='data:image/svg+xml;base64,AAAA#decoy:not-base64'></span>"
        "<span class='social-icon'>"
        f"<img src='data:image/png;base64,AA#{encoded[:midpoint]}'>"
        f"<img src='data:image/png;base64,AA#{encoded[midpoint:]}'>"
        "</span></div>ZXZhbChhdG9i</html>"
    ).encode()


def test_structural_detector_and_extractor() -> None:
    data = fixture_html()
    detection = detect.detect(data, Path("message.html"))
    config = extract_config.extract_config(data)

    assert detection["matched"] is True
    assert detection["campaigns"][0]["campaign_type"] == "ta488_owareaper_half_click"
    assert config["static_config_recovered"] is True
    assert {item["host"] for item in config["network_endpoints"]} == {"acocdn.com", "asecdns.com"}
    assert {item["host"] for item in config["c2"]} == {"acocdn.com", "asecdns.com"}
    assert all(item["confidence"] == "confirmed_static_configuration" for item in config["c2"])
    assert config["decoded_payload"]["content_exported"] is False
    assert config["safety"]["sample_executed"] is False


def test_normal_html_is_not_attributed() -> None:
    data = b"<html><body><p>normal newsletter</p></body></html>"
    assert detect.detect(data, Path("normal.html"))["matched"] is False
