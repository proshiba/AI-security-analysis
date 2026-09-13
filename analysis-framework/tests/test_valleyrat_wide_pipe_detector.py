"""Winos plaintext pipe bootstrapの終端family gateを検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_wide_pipe_detect", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def test_campaign_registry_documents_all_strict_gates_and_fallback() -> None:
    registry_path = MODULE_PATH.parent / "campaigns.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))["patterns"]
    entry = registry["winos_plaintext_pipe_bootstrap_terminal"]

    assert len(entry["required_observations"]) == 13
    assert all(
        observation.startswith(f"{index}.") for index, observation in enumerate(entry["required_observations"], 1)
    )
    assert "13必須gate" in entry["campaign_interpretation"]
    assert "candidate-only" in entry["campaign_interpretation"]


def _probe(*, terminal: bool = True) -> dict[str, object]:
    return {
        "matched": True,
        "family": "valleyrat" if terminal else None,
        "variant": ("winos_plaintext_pipe_bootstrap_terminal" if terminal else "winos_plaintext_pipe_config_candidate"),
        "supports_family_attribution": terminal,
        "terminal_family_confirmed": terminal,
        "static_config_recovered": terminal,
        "candidate_config_recovered": not terminal,
        "attribution_scope": ("validated_winos_bootstrap_component" if terminal else "component_handler_route"),
        "classification_confidence": "high_structural_decoded_config",
        "family_attribution_basis": "unique_pipe_config_parser_runtime_globals_tcp_vtable_winos_frame_dispatcher",
        "evidence": {
            "wide_pipe_config": {
                "status": "decoded_static_config",
                "configuration_style": "winos_plaintext_utf16_pipe",
                "candidate_count": 1,
                "unique_configuration_count": 1,
                "configured_slot_count": 2,
                "external_endpoint_count": 2,
                "raw_build_metadata_included": False,
                "sample_executed": False,
                "network_contacted": False,
                "lineage": {
                    "status": "terminal_winos_bootstrap_lineage_proven",
                    "analysis_complete": True,
                    "terminal_network_lineage_proven": True,
                    "required_groups": {
                        group: True
                        for group in DETECT._WIDE_PIPE_REQUIRED_LINEAGE_PROOF
                    },
                    "protocol": {
                        "transport": "tcp",
                        "frame_prefix_size": 4,
                        "header_size": 10,
                        "payload_offset": 14,
                        "payload_transform": "header_derived_xor",
                        "initial_command": "0x0004",
                        "dispatcher_command_marker": "0xc9",
                        "raw_payload_included": False,
                    },
                    "raw_addresses_included": False,
                    "raw_config_included": False,
                    "raw_network_values_included": False,
                    "sample_executed": False,
                    "network_contacted": False,
                },
                "raw_config_included": False,
                "raw_network_values_included": False,
            }
        },
        "config": {
            "endpoint_count": 2,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _disable_unrelated_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        DETECT,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(DETECT, "probe_ca01_config", lambda _data: {"matched": False})
    monkeypatch.setattr(DETECT, "_onyx_terminal_observation", lambda _data: None)
    monkeypatch.setattr(
        DETECT,
        "_codemark_stage_observation",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        DETECT,
        "probe_x86_codemark_resource_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(DETECT, "probe_n520_config", lambda _data: {"matched": False})
    monkeypatch.setattr(
        DETECT,
        "probe_vvas_config",
        lambda *_args, **_kwargs: {"matched": False},
    )
    monkeypatch.setattr(
        DETECT,
        "probe_vvas_resource_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(DETECT, "recover_bin101_payload", lambda _data: None)
    monkeypatch.setattr(
        DETECT,
        "probe_xor_b1_downloader",
        lambda _data: {"matched": False},
    )


def test_complete_wide_pipe_lineage_selects_terminal_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_unrelated_probes(monkeypatch)
    monkeypatch.setattr(DETECT, "probe_wide_pipe_config", lambda _data: _probe())
    data = b"MZ synthetic wide-pipe bootstrap"

    result = DETECT._terminal_configuration_detection(data, DETECT.hashlib.sha256(data).hexdigest(), "unknown.dll")

    assert result is not None
    assert result["supports_family_attribution"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "winos_plaintext_pipe_bootstrap_terminal"
    assert campaign["attribution_scope"] == "validated_winos_bootstrap_component"
    assert campaign["terminal_family_confirmed"] is True
    assert result["observations"]["terminal_config_probe"]["config"]["raw_network_values_included"] is False


def test_incomplete_wide_pipe_lineage_does_not_select_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_unrelated_probes(monkeypatch)
    monkeypatch.setattr(
        DETECT,
        "probe_wide_pipe_config",
        lambda _data: _probe(terminal=False),
    )
    data = b"MZ synthetic incomplete wide-pipe config"

    result = DETECT._terminal_configuration_detection(data, DETECT.hashlib.sha256(data).hexdigest(), "unknown.dll")

    assert result is None


@pytest.mark.parametrize(
    "mutation",
    (
        "generic_evidence",
        "lineage_status",
        "lineage_group",
        "protocol",
        "nested_raw",
    ),
)
def test_modified_wide_pipe_probe_never_confirms_family(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """matchedだけのwide_pipe probeや改変lineageをfamilyへ昇格しない。"""

    _disable_unrelated_probes(monkeypatch)
    probe = _probe()
    if mutation == "generic_evidence":
        probe["evidence"] = {"validated_structure": True}
    elif mutation == "lineage_status":
        probe["evidence"]["wide_pipe_config"]["lineage"]["status"] = (
            "incomplete_wide_pipe_lineage"
        )
    elif mutation == "lineage_group":
        probe["evidence"]["wide_pipe_config"]["lineage"]["required_groups"][
            "same_socket_field_connect_send_receive"
        ] = False
    elif mutation == "protocol":
        probe["evidence"]["wide_pipe_config"]["lineage"]["protocol"][
            "initial_command"
        ] = "0x0006"
    elif mutation == "nested_raw":
        probe["evidence"]["wide_pipe_config"]["lineage"][
            "raw_addresses_included"
        ] = True
    monkeypatch.setattr(
        DETECT,
        "probe_wide_pipe_config",
        lambda _data: probe,
    )
    data = b"MZ synthetic modified wide-pipe probe"

    result = DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.dll",
    )

    assert result is None
