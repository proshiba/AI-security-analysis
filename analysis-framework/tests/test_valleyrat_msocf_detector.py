"""ValleyRAT MSOCF終端configのhash非依存検出を検証する。"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_msocf_detector", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def test_appdomainmanager_prefilter_skips_full_pe_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLR metadataなしと判明した入力をfull PE parserへ渡さない。"""

    monkeypatch.setattr(DETECT, "has_clr_metadata", lambda _data: False)
    monkeypatch.setattr(
        DETECT.pefile,
        "PE",
        lambda **_kwargs: pytest.fail("managed prefilter後にPEを再解析してはならない"),
    )

    result = DETECT._appdomainmanager_loader_shape(b"MZ-native-fixture")

    assert result == {
        "matched": False,
        "status": "managed_prefilter_rejected",
        "clr_directory_size": 0,
        "required_markers": [],
        "supporting_markers": [],
    }


def _proxy_result(*, count: int = 1) -> dict[str, object]:
    components = []
    for index in range(count):
        endpoints = [
            "198.51.100.24:443",
            "198.51.100.24:443",
            "198.51.100.25:449",
        ]
        payload = {
            "status": "recovered_static_not_executed",
            "algorithm": [
                "ascii_hex_decode",
                "rc4",
                "xor_each_byte_0xff",
            ],
            "encrypted_size": 2381,
            "encrypted_sha256": "b" * 64,
            "key_size": 1000,
            "key_sha256": "c" * 64,
            "payload_size": 2381,
            "payload_sha256": "a" * 64,
            "hex_file_offset": 4096,
            "key_builder_file_offset": 8192,
            "markers": ["codemark"],
            "endpoints": endpoints,
            "executed": False,
            "network_contacted": False,
        }
        components.append(
            {
                "name": f"component-{index}.dll",
                "size": 65536,
                "sha256": hashlib.sha256(f"component-{index}".encode()).hexdigest(),
                "proxy_type": "msocf_rc4_ff_proxy",
                "export_count": 54,
                "loader_markers": ["sys_cache.dat"],
                "injection_or_decryption_apis": ["VirtualAlloc", "ReadFile"],
                "embedded_payload": payload,
            }
        )
    payloads = [item["embedded_payload"] for item in components]
    endpoints = sorted({endpoint for payload in payloads for endpoint in payload["endpoints"]})
    return {
        "components": components,
        "sideload_edges": [],
        "structural_proxy_detected": True,
        "matched_patterns": ["proxy_profile:msocf_rc4_ff_proxy"],
        "config": {
            "static_config_recovered": True,
            "endpoints": endpoints,
            "nvml_dat": None,
            "msocf_payloads": payloads,
        },
        "executed": False,
        "network_contacted": False,
    }


def test_unknown_hash_msocf_terminal_config_supports_family_attribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未知hashでも一意な復元とcodemark設定が揃えば終端帰属する。"""

    data = b"MZ synthetic MSOCF detector fixture"
    monkeypatch.setattr(DETECT, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        DETECT,
        "_appdomainmanager_loader_shape",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: _proxy_result())

    result = DETECT.detect(data, Path("unknown.dll"))
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)

    assert result["matched"] is True
    assert result["campaigns"][0]["confidence"] == "high"
    assert result["campaigns"][0]["terminal_family_confirmed"] is True
    assert result["campaigns"][0]["attribution_scope"] == ("validated_terminal_component_structure")
    terminal = result["observations"]["msocf_terminal_config"]
    assert terminal["endpoint_count"] == 3
    assert terminal["slot_endpoint_count"] == 3
    assert terminal["unique_endpoint_count"] == 2
    assert terminal["duplicate_slot_endpoint_count"] == 1
    assert result["observations"]["msocf_terminal_config"]["raw_endpoints_included"] is False
    assert "198.51.100.24" not in serialized


def test_reviewed_hash_does_not_bypass_current_msocf_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既知hash routeより現在のbytesから再検証した終端構造を優先する。"""

    data = b"MZ reviewed MSOCF detector fixture"
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setitem(DETECT.KNOWN_CAMPAIGNS, digest, "signed_proxy_sideload")
    monkeypatch.setitem(
        DETECT.REVIEWED_SAMPLES,
        digest,
        {"campaign": "signed_proxy_sideload", "final_rat_confirmed": True},
    )
    monkeypatch.setattr(DETECT, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        DETECT,
        "_appdomainmanager_loader_shape",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: _proxy_result())

    result = DETECT.detect(data, Path("reviewed.dll"))

    assert result["campaigns"][0]["terminal_family_confirmed"] is True
    assert result["campaigns"][0]["attribution_scope"] == ("validated_terminal_component_structure")
    assert "known_inner_sha256" not in result["campaigns"][0]


def test_multiple_or_malformed_msocf_components_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """相反し得る複数componentや不正summaryを終端へ昇格しない。"""

    data = b"MZ ambiguous MSOCF detector fixture"
    monkeypatch.setattr(DETECT, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        DETECT,
        "_appdomainmanager_loader_shape",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(
        DETECT,
        "analyze_signed_proxy_sideload",
        lambda *_args: _proxy_result(count=2),
    )
    assert DETECT.detect(data, Path("ambiguous.dll"))["matched"] is False

    malformed = _proxy_result()
    malformed["components"][0]["embedded_payload"]["payload_sha256"] = "short"
    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: malformed)
    assert DETECT.detect(data, Path("malformed.dll"))["matched"] is False


@pytest.mark.parametrize(
    ("target", "field", "value"),
    (
        ("root", "executed", True),
        ("root", "network_contacted", None),
        ("config", "static_config_recovered", False),
        ("component", "sha256", "A" * 64),
        ("payload", "algorithm", ["rc4"]),
        ("payload", "encrypted_sha256", "A" * 64),
        ("payload", "key_sha256", "short"),
        ("payload", "executed", True),
        ("payload", "network_contacted", None),
        ("payload", "endpoints", ["EXAMPLE.COM:443"]),
        (
            "payload",
            "endpoints",
            [
                "198.51.100.24:443",
                "198.51.100.25:449",
                "198.51.100.24:443",
            ],
        ),
    ),
)
def test_msocf_summary_tampering_fails_closed(
    target: str,
    field: str,
    value: object,
) -> None:
    """algorithm、safety、SHA、endpoint正規形の改変を再検証で拒否する。"""

    result = copy.deepcopy(_proxy_result())
    container = {
        "root": result,
        "config": result["config"],
        "component": result["components"][0],
        "payload": result["components"][0]["embedded_payload"],
    }[target]
    container[field] = value

    assert DETECT._validated_msocf_terminal_components(result) == []


def test_msocf_component_limit_is_rejected_without_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全component数が上限を超えた場合は先頭部分を採用しない。"""

    monkeypatch.setattr(DETECT, "MAX_ISO_MEMBERS", 1)

    assert DETECT._validated_msocf_terminal_components(_proxy_result(count=2)) == []


def test_valid_component_plus_malformed_duplicate_fails_closed() -> None:
    """valid componentだけをfilterし、malformed duplicateを無視して採用しない。"""

    result = _proxy_result(count=2)
    del result["components"][1]["embedded_payload"]

    assert DETECT._validated_msocf_terminal_components(result) == []


def test_unknown_hash_handler_confirms_single_structural_msocf_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """handler metadataも単一MSOCF構造＋復元configを終端確定として返す。"""

    proxy = _proxy_result()
    component = copy.deepcopy(proxy["components"][0])
    component["imports"] = {}
    function_globals = DETECT.analyze_signed_proxy_sideload.__globals__
    monkeypatch.setitem(function_globals, "_iso_root_files", lambda _data: [])
    monkeypatch.setitem(
        function_globals,
        "_pe_summary",
        lambda _name, _data: copy.deepcopy(component),
    )

    result = DETECT.analyze_signed_proxy_sideload(
        b"MZ unknown structural MSOCF fixture",
        "unknown.dll",
    )

    assert result["classification_confidence"] == "high_structural"
    assert result["config"]["static_config_recovered"] is True
    assert result["final_rat_confirmed"] is True


@pytest.mark.parametrize("target", ("root_endpoints", "root_payloads", "nvml_union"))
def test_msocf_root_config_union_or_identity_conflict_fails_closed(
    target: str,
) -> None:
    """component payloadとroot集約値のpartial union／identity相反を拒否する。"""

    result = _proxy_result()
    if target == "root_endpoints":
        result["config"]["endpoints"].append("198.51.100.26:450")
    elif target == "root_payloads":
        result["config"]["msocf_payloads"].append(copy.deepcopy(result["components"][0]["embedded_payload"]))
    else:
        result["config"]["nvml_dat"] = {"status": "conflicting_terminal"}

    assert DETECT._validated_msocf_terminal_components(result) == []
