"""Onyx reviewed hash routeとterminal family意味論を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_ROOT = REPOSITORY_ROOT / "analysis-framework"
COMMON = FRAMEWORK_ROOT / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def _load_detector():
    path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "detect.py"
    spec = importlib.util.spec_from_file_location("onyx_valleyrat_detector", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


DETECTOR = _load_detector()


def _load_onyx_fixtures():
    path = REPOSITORY_ROOT / "unpackers" / "tests" / "test_onyx_qt_loader.py"
    spec = importlib.util.spec_from_file_location("onyx_detector_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ONYX_FIXTURES = _load_onyx_fixtures()


def test_structural_terminal_recovery_routes_without_family_attribution() -> None:
    """3層外層と4つの終端slotが揃う場合だけOnyx handlerへrouteする。"""

    shellcode, _config = ONYX_FIXTURES._terminal_config_fixture()
    data = ONYX_FIXTURES._fixture(shellcode)

    result = DETECTOR.detect(data, Path("unknown-hash.exe"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert result["campaigns"] == [
        {
            "campaign_type": "onyx_qt_loader",
            "confidence": "high",
            "reasons": [
                "Onyx／D3D外層markerと一意な境界検証済みHuffman envelope",
                "安定Huffman・改変ChaCha20・Onyx LZによる一意な静的payload復元",
                "XOR-swap・Onyx LZ終端設定と4つの同一C2 slot",
                "終端componentは確認済みだが独立malware familyの帰属範囲は未確定",
            ],
            "attribution_scope": "component_handler_route",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
        }
    ]
    observation = result["observations"]["onyx_terminal_component"]
    assert observation["status"] == "validated_onyx_terminal_component"
    assert observation["input_sha256"] == hashlib.sha256(data).hexdigest()
    assert observation["payload_sha256"] == hashlib.sha256(shellcode).hexdigest()
    assert observation["terminal_endpoint_count"] == 1
    assert observation["repeated_slot_count"] == 4
    assert observation["terminal_transport"] == "http"
    assert observation["raw_endpoint_included"] is False
    assert observation["raw_config_included"] is False
    assert observation["raw_key_included"] is False
    assert observation["raw_payload_included"] is False
    assert observation["executed"] is False
    assert observation["network_contacted"] is False
    serialized = json.dumps(result, sort_keys=True)
    assert "utuhv.cn" not in serialized
    assert "8080" not in serialized


def test_onyx_outer_without_terminal_config_fails_closed() -> None:
    """外層markerと復号可能payloadだけでは候補routeへ昇格しない。"""

    data = ONYX_FIXTURES._fixture(b"\x90" * 128)

    result = DETECTOR.detect(data, Path("outer-only.exe"))

    assert result["matched"] is False
    assert result["campaigns"] == []


def test_onyx_profile_marker_without_valid_envelope_fails_closed() -> None:
    """Onyx／D3D文字列だけを構造検出として扱わない。"""

    data = b"MZ\0Onyx agent\0D3DCompile\0not-an-envelope"

    result = DETECTOR.detect(data, Path("marker-only.exe"))

    assert result["matched"] is False
    assert result["campaigns"] == []


def test_reviewed_route_does_not_claim_terminal_family(monkeypatch) -> None:
    """exact routeは専用handler選択に使うが、終端family確定とは記録しない。"""

    data = b"MZ offline onyx routing fixture"
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setitem(DETECTOR.KNOWN_CAMPAIGNS, digest, "onyx_qt_loader")
    monkeypatch.setitem(
        DETECTOR.REVIEWED_SAMPLES,
        digest,
        {
            "campaign": "onyx_qt_loader",
            "terminal_component": "onyx_terminal_stage",
            "terminal_family_attribution": "component_confirmed_family_unresolved",
            "routing_semantics": "reviewed_static_handler_route_not_family_confirmation",
        },
    )

    result = DETECTOR.detect(data, Path("fixture.exe"))
    route = result["campaigns"][0]
    semantics = result["observations"]["reviewed_routing_semantics"]

    assert result["matched"] is True
    assert route["campaign_type"] == "onyx_qt_loader"
    assert route["attribution_scope"] == "reviewed_component_handler_route"
    assert route["terminal_family_confirmed"] is False
    assert semantics == {
        "scope": "component_handler_routing",
        "terminal_component": "onyx_terminal_stage",
        "terminal_family_attribution": "component_confirmed_family_unresolved",
        "prior_review_recorded_terminal": False,
        "terminal_family_confirmed": False,
    }
