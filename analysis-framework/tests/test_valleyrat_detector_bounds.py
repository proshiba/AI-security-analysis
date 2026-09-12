"""ValleyRAT detectorの境界超過fail-closed回帰テスト。"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_bounded_detect", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _large_pe_fixture(label: bytes) -> bytes:
    """section境界契約を満たす、実行不能な大容量PE風byte fixtureを返す。"""

    return b"MZ" + label + bytes(1_100_000)


def _zip_fixture() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("fixture-a.bin", b"fixture-a")
        archive.writestr("fixture-b.bin", b"fixture-b")
    return stream.getvalue()


def test_archive_limit_is_unmatched_observation_not_detector_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(_data: bytes):
        raise DETECT.ArchiveValidationError("member exceeds bounded limit")

    monkeypatch.setattr(DETECT, "inspect_zip", reject)
    result = DETECT.detect(_zip_fixture(), Path("sample.zip"))
    assert result["matched"] is False
    assert result["campaigns"] == []
    assert result["observations"]["archive_scan"] == "bounded_rejection"
    assert "ArchiveValidationError" in result["observations"]["reason"]


def test_raw_msi_requires_packed_valleyrat_pe_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """展開済みraw MSIでもCABと保護stub形状が揃う場合だけ候補にする。"""

    raw_msi = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture"
    monkeypatch.setattr(
        DETECT,
        "inspect_msi_structure",
        lambda _data: {
            "stream_count": 3,
            "cab_count": 1,
            "pe_count": 1,
            "packed_valleyrat_pe_count": 1,
            "streams": [],
        },
    )
    result = DETECT.detect(raw_msi, Path("sample.msi"))
    assert result["matched"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "msi_embedded_cab_custom_actions"
    assert campaign["confidence"] == "medium"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False


def test_generic_msi_with_cab_and_pe_is_not_attributed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一般的なCAB+PE MSIだけではValleyRATへ帰属しない。"""

    raw_msi = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture"
    monkeypatch.setattr(
        DETECT,
        "inspect_msi_structure",
        lambda _data: {
            "stream_count": 3,
            "cab_count": 1,
            "pe_count": 1,
            "packed_valleyrat_pe_count": 0,
            "streams": [],
        },
    )
    result = DETECT.detect(raw_msi, Path("benign.msi"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_appdomainmanager_pixel_loader_requires_correlated_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directories = [SimpleNamespace(Size=0) for _ in range(15)]
    directories[14] = SimpleNamespace(Size=72)
    fake_pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories))
    monkeypatch.setattr(DETECT, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(DETECT.pefile, "PE", lambda **_kwargs: fake_pe)
    data = b"MZ fixture MyAppDomainManager InitializeNewDomain VirtualAllocExNuma EnumUILanguagesA Win32_CacheMemory"

    result = DETECT.detect(data, Path("loader.dll"))

    assert result["matched"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "appdomainmanager_pixel_loader"
    assert campaign["confidence"] == "high"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False


def _cef_proxy_result(data: bytes) -> dict[str, object]:
    """signed-proxy analyzerの公開契約に合わせたCEF route fixtureを返す。"""

    return {
        "sample_sha256": hashlib.sha256(data).hexdigest(),
        "campaign_type": "signed_proxy_sideload",
        "components": [
            {
                "name": "libcef.dll",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "proxy_type": "cef_proxy",
                "export_count": 64,
                "export_sample": ["cef_initialize"],
                "export_target_peak_ratio": 0.5,
                "resource_types": [],
                "loader_markers": [],
                "injection_or_decryption_apis": [],
                "sections": [
                    {
                        "name": ".data",
                        "raw_size": 1_000_001,
                        "virtual_size": 1_000_001,
                        "entropy": 7.9,
                    }
                ],
            }
        ],
        "sideload_edges": [],
        "structural_proxy_detected": True,
        "matched_patterns": ["proxy_profile:cef_proxy"],
        "config": {
            "static_config_recovered": False,
            "endpoints": [],
            "nvml_dat": None,
            "msocf_payloads": [],
        },
        "executed": False,
        "network_contacted": False,
    }


def _route_only_proxy_result(data: bytes, proxy_type: str) -> dict[str, object]:
    """4種の厳格proxy profileをdetector公開契約へ正規化する。"""

    result = _cef_proxy_result(data)
    component = result["components"][0]
    component["proxy_type"] = proxy_type
    result["matched_patterns"] = [f"proxy_profile:{proxy_type}"]
    if proxy_type == "nvml_proxy":
        component.update(
            export_count=9,
            export_sample=["nvmlInit_v2"],
            injection_or_decryption_apis=[
                "CreateToolhelp32Snapshot",
                "OpenProcess",
                "Process32FirstW",
                "VirtualAllocEx",
                "WriteProcessMemory",
            ],
        )
    elif proxy_type == "pdfcore8_winos_proxy":
        component.update(
            export_count=1_392,
            export_sample=["CoreLibFin", "CoreLibInit"],
            export_target_peak_ratio=1.0,
            resource_types=["UNDATAMANAGER", "UNDATAMODEL", "UNDATAPLUGIN"],
            injection_or_decryption_apis=[
                "CreateProcessW",
                "CreateThread",
                "DeviceIoControl",
                "VirtualAlloc",
            ],
        )
    elif proxy_type == "pdfcore8_minimal_protected_proxy":
        component.update(
            export_count=4,
            export_sample=[
                "CoreLibFin",
                "CoreLibInit",
                "GetCoreHFT",
                "RestorePlugInFrame",
            ],
            export_target_peak_ratio=1.0,
            injection_or_decryption_apis=[
                "CreateProcessW",
                "CreateThread",
                "DeviceIoControl",
                "VirtualAlloc",
            ],
        )
    return result


@pytest.mark.parametrize(
    "proxy_type",
    (
        "cef_proxy",
        "nvml_proxy",
        "pdfcore8_winos_proxy",
        "pdfcore8_minimal_protected_proxy",
    ),
)
def test_all_strict_signed_proxy_profiles_are_hash_independent_routes(
    monkeypatch: pytest.MonkeyPatch,
    proxy_type: str,
) -> None:
    """既知4 profileはexact hashなしでもfamily非帰属routeへ載せる。"""

    data = _large_pe_fixture(f" strict {proxy_type} fixture".encode())
    proxy = _route_only_proxy_result(data, proxy_type)
    monkeypatch.setattr(
        DETECT,
        "analyze_signed_proxy_sideload",
        lambda *_args: proxy,
    )

    result = DETECT.detect(data, Path(f"unknown-{proxy_type}.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert result["observations"]["validated_route_only_proxy_profile"] == proxy_type
    campaign = result["campaigns"][0]
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False


def test_strict_signed_proxy_profile_is_hash_independent_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """強いCEF proxy構造はexact hashなしでもhandler routeへ載せる。"""

    data = _large_pe_fixture(b" strict CEF proxy fixture")
    monkeypatch.setattr(
        DETECT,
        "analyze_signed_proxy_sideload",
        lambda *_args: _cef_proxy_result(data),
    )

    result = DETECT.detect(data, Path("unknown-libcef.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "signed_proxy_sideload"
    assert campaign["confidence"] == "high"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
    assert (
        result["observations"]["validated_route_only_proxy_profile"]
        == "cef_proxy"
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.update(structural_proxy_detected=False),
        lambda value: value["components"][0].update(sha256="0" * 64),
        lambda value: value["components"][0]["sections"][0].update(entropy=7.7),
        lambda value: value.update(executed=True),
        lambda value: value["config"].update(endpoints=["example.invalid:443"]),
    ),
    ids=("structural-flag", "digest", "entropy", "execution", "config"),
)
def test_route_only_proxy_contract_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation,
) -> None:
    """profile再検証の必須条件を1つでも失うproxyをrouteしない。"""

    data = _large_pe_fixture(b" strict CEF proxy fixture")
    proxy = _cef_proxy_result(data)
    mutation(proxy)
    monkeypatch.setattr(
        DETECT,
        "analyze_signed_proxy_sideload",
        lambda *_args: proxy,
    )

    result = DETECT.detect(data, Path("ambiguous-libcef.dll"))

    assert result["matched"] is False
    assert result["campaigns"] == []


def test_export_funnel_probe_routes_to_single_pe_without_family_attribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """export-funnel形状はgeneric single-PE解析へだけrouteする。"""

    data = _large_pe_fixture(b" anonymous export funnel fixture")
    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: {})
    monkeypatch.setattr(
        DETECT,
        "probe_export_funnel_route",
        lambda _data: {
            "matched": True,
            "attribution_scope": "component_handler_route",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "terminal_network_lineage_proven": False,
            "evidence": {
                "export_names_included": False,
                "resource_labels_included": False,
                "raw_addresses_included": False,
            },
            "sample_executed": False,
            "network_contacted": False,
        },
    )

    result = DETECT.detect(data, Path("anonymous.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert "export_funnel_native_route" in result["observations"]
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "single_pe"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
