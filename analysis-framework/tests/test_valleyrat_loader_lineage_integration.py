"""native／SilverFox loader lineageのproduction接続を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

from extractors.common import build_result
from extractors.valleyrat import extractor
from extractors.valleyrat.native_loader_lineage import NativeLoaderLineage
from extractors.valleyrat.silverfox_loader_lineage import SilverFoxLoaderLineage

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_loader_lineage_integration_detect",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _native_observation(*, confirmed: bool) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": (
            "validated_native_loader_to_valleyrat_terminal_lineage"
            if confirmed
            else "native_loader_candidate_terminal_unproven"
        ),
        "matched": True,
        "terminal": {
            "family": "valleyrat" if confirmed else None,
            "static_config_recovered": confirmed,
            "endpoint_count": 1 if confirmed else 0,
            "candidate_only": not confirmed,
            "endpoint_values_included": False,
        },
        "supports_family_attribution": confirmed,
        "terminal_family_confirmed": confirmed,
        "terminal_network_lineage_proven": confirmed,
        "terminal_protocol_lineage_proven": confirmed,
        "endpoint_values_included": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def _silverfox_observation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "validated_silverfox_style_infection_loader_lineage",
        "matched": True,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "terminal_network_lineage_proven": False,
        "terminal_protocol_lineage_proven": False,
        "candidate_only": True,
        "endpoint_values_included": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def test_detector_promotes_only_confirmed_native_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """通常detect経路がstrict終端付きnative lineageだけをfamily確定する。"""

    terminal = b"MZ validated terminal"
    monkeypatch.setattr(DETECT, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        DETECT,
        "_appdomainmanager_loader_shape",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(
        DETECT,
        "analyze_native_loader_lineage",
        lambda _data: NativeLoaderLineage(
            observation=_native_observation(confirmed=True),
            terminal_component=terminal,
        ),
    )

    result = DETECT.detect(b"MZ native loader", Path("loader.exe"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is True
    assert result["campaigns"][0]["terminal_family_confirmed"] is True
    assert "native_loader_lineage" in result["observations"]
    assert terminal.decode("ascii") not in repr(result)


@pytest.mark.parametrize("route_kind", ["native", "silverfox"])
def test_detector_loader_candidates_remain_route_only(
    monkeypatch: pytest.MonkeyPatch,
    route_kind: str,
) -> None:
    """未検証native終端とSilverFox loaderはfamily／C2確定へ昇格しない。"""

    monkeypatch.setattr(DETECT, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        DETECT,
        "_appdomainmanager_loader_shape",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: {})
    monkeypatch.setattr(
        DETECT,
        "analyze_native_loader_lineage",
        lambda _data: (
            NativeLoaderLineage(
                observation=_native_observation(confirmed=False),
                terminal_component=None,
            )
            if route_kind == "native"
            else None
        ),
    )
    monkeypatch.setattr(
        DETECT,
        "analyze_silverfox_loader_lineage",
        lambda _data: (
            SilverFoxLoaderLineage(
                observation=_silverfox_observation(),
                recovered_component=b"MZ route-only component",
            )
            if route_kind == "silverfox"
            else None
        ),
    )

    result = DETECT.detect(b"MZ loader candidate", Path("loader.exe"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert result["campaigns"][0]["terminal_family_confirmed"] is False
    assert result["campaigns"][0]["attribution_scope"] == "component_handler_route"
    assert "endpoints" not in result
    lineage_key = (
        "native_loader_lineage"
        if route_kind == "native"
        else "silverfox_loader_lineage"
    )
    observation = result["observations"][lineage_key]
    assert observation["endpoint_values_included"] is False
    assert "route-only component" not in repr(result)


def test_native_route_component_is_exposed_only_as_follow_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """検証済み実行子PEを親のfamily/C2へ帰属せず後段専用で返す。"""

    component = b"MZ native route-only component"
    observation = _native_observation(confirmed=False)
    observation["follow_on_candidate_set_complete"] = True
    monkeypatch.setattr(
        extractor,
        "analyze_native_loader_lineage",
        lambda _data: NativeLoaderLineage(
            observation=observation,
            terminal_component=None,
            recovered_components=(component,),
        ),
    )
    monkeypatch.setattr(
        extractor,
        "analyze_silverfox_loader_lineage",
        lambda _data: None,
    )

    terminal, observations, payloads = extractor._extract_native_loader_lineage(
        b"MZ loader",
        "loader.exe",
    )

    assert terminal is None
    assert observations["native_loader_lineage"]["terminal_family_confirmed"] is False
    assert payloads == (
        {
            "role": "final_payload",
            "name": f"{hashlib.sha256(component).hexdigest()}.bin",
            "data": component,
        },
    )
    assert "native route-only component" not in repr(observations)


def test_native_incomplete_follow_on_set_is_not_exposed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上限等で不完全になった子集合のprefix bytesは後段へ渡さない。"""

    observation = _native_observation(confirmed=False)
    observation["follow_on_candidate_set_complete"] = False
    monkeypatch.setattr(
        extractor,
        "analyze_native_loader_lineage",
        lambda _data: NativeLoaderLineage(
            observation=observation,
            terminal_component=None,
            recovered_components=(b"MZ incomplete prefix",),
        ),
    )
    monkeypatch.setattr(
        extractor,
        "analyze_silverfox_loader_lineage",
        lambda _data: None,
    )

    terminal, _observations, payloads = extractor._extract_native_loader_lineage(
        b"MZ loader",
        "loader.exe",
    )

    assert terminal is None
    assert payloads == ()


def test_follow_on_merge_preserves_existing_final_payload() -> None:
    """既存の復元payloadをloader follow-onで上書きせずdigest重複を除く。"""

    first = b"MZ existing final payload"
    second = b"MZ loader follow-on"
    result = {
        "final_payload": {
            "role": "final_payload",
            "name": "existing.bin",
            "data": first,
        }
    }

    extractor._attach_final_payloads(
        result,
        (
            {
                "role": "final_payload",
                "name": "duplicate.bin",
                "data": first,
            },
            {
                "role": "final_payload",
                "name": "follow-on.bin",
                "data": second,
            },
        ),
    )

    assert "final_payload" not in result
    assert [item["data"] for item in result["final_payloads"]] == [first, second]


def test_shared_extractor_reuses_confirmed_terminal_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """shared extractorが終端のstrict C2結果をouter lineageへ結び付ける。"""

    root = b"MZ native loader"
    terminal = b"MZ validated terminal"
    terminal_result = build_result(
        "valleyrat",
        terminal,
        {
            "variant": "winos_plaintext_pipe_bootstrap_terminal",
            "static_config_recovered": True,
            "terminal_family_confirmed": True,
            "endpoints": ["example.test:443"],
            "ipv4": [],
            "urls": [],
        },
        [
            {
                "kind": "network.endpoint",
                "value": "example.test:443",
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_wide_pipe_winos_bootstrap_lineage",
            }
        ],
        ["検体実行と外部通信は行っていません。"],
    )
    monkeypatch.setattr(
        extractor,
        "_extract_wide_pipe_config",
        lambda data, _name: terminal_result if data == terminal else None,
    )
    monkeypatch.setattr(
        extractor,
        "analyze_native_loader_lineage",
        lambda data: (
            NativeLoaderLineage(
                observation=_native_observation(confirmed=True),
                terminal_component=terminal,
            )
            if data == root
            else None
        ),
    )

    result = extractor.extract(root, r"C:\private\loader.exe")

    assert result["sample_sha256"] == hashlib.sha256(root).hexdigest()
    assert result["config"]["variant"] == "native_loader_valleyrat_terminal_lineage"
    assert result["config"]["terminal_family_confirmed"] is True
    assert result["config"]["terminal_protocol_lineage_proven"] is True
    assert result["config"]["endpoints"] == ["example.test:443"]
    assert result["terminal_payload"]["data"] == terminal
    assert "private" not in result["config"]["source_name"].casefold()


def test_shared_extractor_keeps_silverfox_lineage_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SilverFox復元componentを親に帰属せずfollow-onだけへ渡す。"""

    component = b"MZ route-only component"
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: None)
    monkeypatch.setattr(
        extractor,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=_silverfox_observation(),
            recovered_component=component,
        ),
    )
    monkeypatch.setattr(
        extractor,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(extractor, "_extract_wide_pipe_config", lambda *_args: None)
    monkeypatch.setattr(
        extractor,
        "probe_export_funnel_route",
        lambda _data: {"matched": False},
    )

    result = extractor.extract(b"MZ silverfox loader", "loader.exe")

    assert result["config"]["variant"] == "silverfox_style_infection_loader"
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["findings"] == []
    assert "terminal_payload" not in result
    assert "silverfox_loader_lineage" in result["config"]
    assert result["config"]["silverfox_loader_lineage"]["raw_payload_included"] is False
    assert result["final_payload"] == {
        "role": "final_payload",
        "name": f"{hashlib.sha256(component).hexdigest()}.bin",
        "data": component,
    }
    assert "route-only component" not in repr(result["config"])


def test_shared_extractor_does_not_retain_ambiguous_silverfox_component(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SilverFox復元経路が曖昧な場合は、付随bytesもfollow-onへ渡さない。"""

    observation = _silverfox_observation()
    observation["status"] = "silverfox_style_loader_candidate_incomplete_lineage"
    observation["missing_proof_codes"] = [
        "multiple_outer_stage_interpretations_ambiguous"
    ]
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: None)
    monkeypatch.setattr(
        extractor,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=observation,
            recovered_component=b"MZ ambiguous component",
        ),
    )
    monkeypatch.setattr(
        extractor,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(extractor, "_extract_wide_pipe_config", lambda *_args: None)
    monkeypatch.setattr(
        extractor,
        "probe_export_funnel_route",
        lambda _data: {"matched": False},
    )

    result = extractor.extract(b"MZ ambiguous silverfox loader", "loader.exe")

    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["endpoints"] == []
    assert "terminal_payload" not in result
    assert "final_payload" not in result
    assert "ambiguous component" not in repr(result)
