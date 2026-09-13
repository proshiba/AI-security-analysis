"""ValleyRAT direct config probeのdetector昇格境界を検証する。"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
)
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_direct_config_detect",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _disable_direct_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """対象以外の静的probeを不一致へ固定する。"""

    monkeypatch.setattr(
        DETECT,
        "probe_ca01_config",
        lambda _data: {"matched": False},
    )
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
    monkeypatch.setattr(
        DETECT,
        "probe_wide_pipe_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(
        DETECT,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(
        DETECT,
        "probe_n520_config",
        lambda _data: {"matched": False},
    )
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


def _detect(monkeypatch: pytest.MonkeyPatch, probe: dict) -> dict | None:
    _disable_direct_probes(monkeypatch)
    monkeypatch.setattr(
        DETECT,
        "probe_run_dll_native_core_config",
        lambda _data: copy.deepcopy(probe),
    )
    data = b"MZ synthetic direct probe"
    return DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.dll",
    )


def _run_dll_probe(*, terminal: bool) -> dict:
    proof = {
        group: terminal
        for group in DETECT._RUN_DLL_REQUIRED_TERMINAL_PROOF
    }
    missing = [] if terminal else ["run_dll_runtime_config_to_connect_unproven"]
    return {
        "matched": True,
        "family": "valleyrat" if terminal else None,
        "variant": (
            "run_dll_native_terminal_config"
            if terminal
            else "run_dll_native_core_static_triplet_candidate"
        ),
        "supports_family_attribution": terminal,
        "terminal_family_confirmed": terminal,
        "static_config_recovered": True,
        "candidate_config_recovered": not terminal,
        "attribution_scope": (
            "terminal_payload" if terminal else "component_handler_route"
        ),
        "endpoints": ["198.51.100.24:443"],
        "slots": [
            {"slot": 1, "host": "198.51.100.24", "port": 443},
            {"slot": 2, "host": "198.51.100.24", "port": 443},
        ],
        "evidence": {
            "status": (
                "validated_terminal_family_config"
                if terminal
                else "validated_static_config_route_candidate"
            ),
            "profile": "run_dll_native_core",
            "missing_proof_codes": missing,
            "run_dll_terminal_lineage": {
                "status": (
                    "validated_terminal_lineage"
                    if terminal
                    else "terminal_lineage_incomplete"
                ),
                "analysis_complete": True,
                "terminal_family_lineage_proven": terminal,
                "proof": proof,
                "missing_proof_codes": missing,
                "protocol": {
                    "transport": "tcp" if terminal else None,
                    "length_prefix_size": 4 if terminal else None,
                    "session_header_size": 10 if terminal else None,
                    "frame_header_size": 14 if terminal else None,
                    "marker": "uint16_0x00ca" if terminal else None,
                    "initial_registration_command": 6 if terminal else None,
                    "raw_frame_included": False,
                },
                "sample_executed": False,
                "network_contacted": False,
                "raw_addresses_included": False,
                "raw_config_included": False,
            },
            "terminal_protocol_contract": {
                "proven": terminal,
                "status": (
                    "validated_serializer_producer_consumer_lineage"
                    if terminal
                    else "serializer_producer_consumer_lineage_unproven"
                ),
                "frame_marker_candidate_present": True,
                "literal_marker_alone_is_terminal_proof": False,
                "raw_frame_included": False,
            },
            "raw_config_included": False,
            "raw_payload_included": False,
        },
        "config": {
            "endpoint_count": 1,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def test_run_dll_strict_terminal_probe_confirms_family_without_public_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全証拠が閉じたrun DLLだけを確定し、network値は公開しない。"""

    result = _detect(monkeypatch, _run_dll_probe(terminal=True))

    assert result is not None
    assert result["supports_family_attribution"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "run_dll_native_terminal_config"
    assert campaign["terminal_family_confirmed"] is True
    observation = result["observations"]["terminal_config_probe"]
    assert observation["evidence"]["missing_proof_codes"] == []
    assert observation["raw_endpoints_included"] is False
    serialized = json.dumps(result, sort_keys=True)
    assert "198.51.100.24" not in serialized
    assert ":443" not in serialized


def test_run_dll_terminal_precedes_ca01_and_onyx_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """強いrun DLL終端を先行するroute-only probeで隠さない。"""

    _disable_direct_probes(monkeypatch)
    monkeypatch.setattr(
        DETECT,
        "probe_run_dll_native_core_config",
        lambda _data: _run_dll_probe(terminal=True),
    )
    monkeypatch.setattr(
        DETECT,
        "probe_ca01_config",
        lambda _data: pytest.fail("strict run DLL後にCA01を評価してはならない"),
    )
    monkeypatch.setattr(
        DETECT,
        "_onyx_terminal_observation",
        lambda _data: pytest.fail("strict run DLL後にOnyxを評価してはならない"),
    )
    data = b"MZ synthetic run DLL precedence"

    result = DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.dll",
    )

    assert result is not None
    assert result["campaigns"][0]["campaign_type"] == (
        "run_dll_native_terminal_config"
    )


def test_run_dll_static_config_stays_route_only_without_terminal_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """静的triplet候補を保持するがfamily確定には利用しない。"""

    result = _detect(monkeypatch, _run_dll_probe(terminal=False))

    assert result is not None
    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == (
        "run_dll_native_core_static_triplet_candidate"
    )
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["terminal_family_confirmed"] is False
    observation = result["observations"]["static_config_candidate_probe"]
    assert observation["candidate_config_recovered"] is True
    assert observation["raw_endpoints_included"] is False
    assert "198.51.100.24" not in json.dumps(result, sort_keys=True)


def test_run_dll_route_precedes_raw_codemark_and_reuses_single_probe_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run DLL routeをraw codemarkより先に返し、同じprobe結果を再利用する。"""

    _disable_direct_probes(monkeypatch)
    calls = 0

    def run_dll(_data: bytes) -> dict:
        nonlocal calls
        calls += 1
        return _run_dll_probe(terminal=False)

    monkeypatch.setattr(DETECT, "probe_run_dll_native_core_config", run_dll)
    monkeypatch.setattr(
        DETECT,
        "_codemark_stage_observation",
        lambda *_args, **_kwargs: pytest.fail(
            "run DLL route後にraw codemarkを評価してはならない"
        ),
    )
    data = b"MZ synthetic run DLL route precedence"

    result = DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.dll",
    )

    assert result is not None
    assert calls == 1
    assert result["supports_family_attribution"] is False
    assert result["campaigns"][0]["campaign_type"] == (
        "run_dll_native_core_static_triplet_candidate"
    )


def test_ca01_route_precedes_run_dll_route_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """弱いrun DLL候補より既存CA01 routeの優先順位を維持する。"""

    _disable_direct_probes(monkeypatch)
    calls = 0

    def run_dll(_data: bytes) -> dict:
        nonlocal calls
        calls += 1
        return _run_dll_probe(terminal=False)

    monkeypatch.setattr(DETECT, "probe_run_dll_native_core_config", run_dll)
    monkeypatch.setattr(
        DETECT,
        "probe_ca01_config",
        lambda _data: {
            "matched": True,
            "supports_family_attribution": False,
            "attribution_scope": "component_handler_route",
        },
    )
    monkeypatch.setattr(
        DETECT,
        "_onyx_terminal_observation",
        lambda _data: pytest.fail("CA01 route後にOnyxを評価してはならない"),
    )
    data = b"MZ synthetic CA01 and run DLL routes"

    result = DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.dll",
    )

    assert result is not None
    assert calls == 1
    assert result["campaigns"][0]["campaign_type"] == (
        "ca01_x64_double_base64_sideload_terminal"
    )
    assert result["supports_family_attribution"] is False


def test_onyx_route_precedes_run_dll_route_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """弱いrun DLL候補より既存Onyx routeの優先順位を維持する。"""

    _disable_direct_probes(monkeypatch)
    calls = 0

    def run_dll(_data: bytes) -> dict:
        nonlocal calls
        calls += 1
        return _run_dll_probe(terminal=False)

    monkeypatch.setattr(DETECT, "probe_run_dll_native_core_config", run_dll)
    monkeypatch.setattr(
        DETECT,
        "_onyx_terminal_observation",
        lambda _data: {"status": "validated_terminal_component"},
    )
    data = b"MZ synthetic Onyx and run DLL routes"

    result = DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.dll",
    )

    assert result is not None
    assert calls == 1
    assert result["campaigns"][0]["campaign_type"] == "onyx_qt_loader"
    assert result["supports_family_attribution"] is False


def test_run_dll_protocol_proof_alone_still_stays_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """protocol部分だけ完成しても他の欠落proofをfamily確定へ補完しない。"""

    probe = _run_dll_probe(terminal=False)
    protocol = probe["evidence"]["terminal_protocol_contract"]
    protocol["proven"] = True
    protocol["status"] = "validated_serializer_producer_consumer_lineage"
    lineage_protocol = probe["evidence"]["run_dll_terminal_lineage"]["protocol"]
    lineage_protocol.update(
        {
            "transport": "tcp",
            "length_prefix_size": 4,
            "session_header_size": 10,
            "frame_header_size": 14,
            "marker": "uint16_0x00ca",
            "initial_registration_command": 6,
        }
    )

    result = _detect(monkeypatch, probe)

    assert result is not None
    assert result["supports_family_attribution"] is False
    assert result["campaigns"][0]["terminal_family_confirmed"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "family",
        "variant",
        "supports",
        "terminal",
        "static",
        "candidate",
        "scope",
        "evidence_status",
        "evidence_missing",
        "protocol",
        "protocol_marker_candidate",
        "lineage",
        "lineage_status",
        "lineage_complete",
        "lineage_missing",
        "lineage_transport",
        "lineage_length_prefix",
        "lineage_session_header",
        "lineage_frame_header",
        "lineage_marker",
        "lineage_registration_command",
        "lineage_raw_frame",
        "lineage_sample_executed",
        "lineage_network_contacted",
        "lineage_raw_addresses",
        "lineage_raw_config",
        "config_count",
        "config_count_over_limit",
        "config_raw",
        "evidence_raw_config",
        "evidence_raw_payload",
        "protocol_raw_frame",
        "protocol_literal",
        "sample_executed",
        "network_contacted",
    ],
)
def test_run_dll_terminal_rejects_each_mutated_contract_field(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """matchedでも終端契約の一項が壊れればfamilyへ昇格しない。"""

    probe = _run_dll_probe(terminal=True)
    if mutation == "family":
        probe["family"] = "unknown"
    elif mutation == "variant":
        probe["variant"] = "run_dll_native_core_static_triplet_candidate"
    elif mutation == "supports":
        probe["supports_family_attribution"] = False
    elif mutation == "terminal":
        probe["terminal_family_confirmed"] = False
    elif mutation == "static":
        probe["static_config_recovered"] = False
    elif mutation == "candidate":
        probe["candidate_config_recovered"] = True
    elif mutation == "scope":
        probe["attribution_scope"] = "component_handler_route"
    elif mutation == "evidence_status":
        probe["evidence"]["status"] = "validated_static_config_route_candidate"
    elif mutation == "evidence_missing":
        probe["evidence"]["missing_proof_codes"] = ["proof_missing"]
    elif mutation == "protocol":
        probe["evidence"]["terminal_protocol_contract"]["proven"] = False
    elif mutation == "protocol_marker_candidate":
        probe["evidence"]["terminal_protocol_contract"][
            "frame_marker_candidate_present"
        ] = False
    elif mutation == "lineage":
        probe["evidence"]["run_dll_terminal_lineage"][
            "terminal_family_lineage_proven"
        ] = False
    elif mutation == "lineage_status":
        probe["evidence"]["run_dll_terminal_lineage"]["status"] = (
            "terminal_lineage_incomplete"
        )
    elif mutation == "lineage_complete":
        probe["evidence"]["run_dll_terminal_lineage"][
            "analysis_complete"
        ] = False
    elif mutation == "lineage_missing":
        probe["evidence"]["run_dll_terminal_lineage"][
            "missing_proof_codes"
        ] = ["proof_missing"]
    elif mutation == "lineage_transport":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "transport"
        ] = "udp"
    elif mutation == "lineage_length_prefix":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "length_prefix_size"
        ] = 8
    elif mutation == "lineage_session_header":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "session_header_size"
        ] = 8
    elif mutation == "lineage_frame_header":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "frame_header_size"
        ] = 12
    elif mutation == "lineage_marker":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "marker"
        ] = "uint16_0x00cb"
    elif mutation == "lineage_registration_command":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "initial_registration_command"
        ] = 7
    elif mutation == "lineage_raw_frame":
        probe["evidence"]["run_dll_terminal_lineage"]["protocol"][
            "raw_frame_included"
        ] = True
    elif mutation == "lineage_sample_executed":
        probe["evidence"]["run_dll_terminal_lineage"][
            "sample_executed"
        ] = True
    elif mutation == "lineage_network_contacted":
        probe["evidence"]["run_dll_terminal_lineage"][
            "network_contacted"
        ] = True
    elif mutation == "lineage_raw_addresses":
        probe["evidence"]["run_dll_terminal_lineage"][
            "raw_addresses_included"
        ] = True
    elif mutation == "lineage_raw_config":
        probe["evidence"]["run_dll_terminal_lineage"][
            "raw_config_included"
        ] = True
    elif mutation == "config_count":
        probe["config"]["endpoint_count"] = 0
    elif mutation == "config_count_over_limit":
        probe["config"]["endpoint_count"] = 65
    elif mutation == "config_raw":
        probe["config"]["raw_config_included"] = True
    elif mutation == "evidence_raw_config":
        probe["evidence"]["raw_config_included"] = True
    elif mutation == "evidence_raw_payload":
        probe["evidence"]["raw_payload_included"] = True
    elif mutation == "protocol_raw_frame":
        probe["evidence"]["terminal_protocol_contract"]["raw_frame_included"] = True
    elif mutation == "protocol_literal":
        probe["evidence"]["terminal_protocol_contract"][
            "literal_marker_alone_is_terminal_proof"
        ] = True
    elif mutation == "sample_executed":
        probe["sample_executed"] = True
    elif mutation == "network_contacted":
        probe["network_contacted"] = True

    assert _detect(monkeypatch, probe) is None


@pytest.mark.parametrize(
    "proof_group",
    sorted(DETECT._RUN_DLL_REQUIRED_TERMINAL_PROOF),
)
def test_run_dll_terminal_rejects_inconsistent_false_proof_group(
    monkeypatch: pytest.MonkeyPatch,
    proof_group: str,
) -> None:
    """missing codeを偽装しても10個の必須proofを個別に再検証する。"""

    probe = _run_dll_probe(terminal=True)
    probe["evidence"]["run_dll_terminal_lineage"]["proof"][proof_group] = False

    assert _detect(monkeypatch, probe) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "family",
        "supports",
        "terminal",
        "static",
        "candidate",
        "scope",
        "evidence_status",
        "missing",
        "protocol_type",
        "sample_executed",
        "network_contacted",
    ],
)
def test_run_dll_route_candidate_rejects_inconsistent_contract(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """route-only候補も明示契約が矛盾する場合はdetector一致にしない。"""

    probe = _run_dll_probe(terminal=False)
    if mutation == "family":
        probe["family"] = "valleyrat"
    elif mutation == "supports":
        probe["supports_family_attribution"] = True
    elif mutation == "terminal":
        probe["terminal_family_confirmed"] = True
    elif mutation == "static":
        probe["static_config_recovered"] = False
    elif mutation == "candidate":
        probe["candidate_config_recovered"] = False
    elif mutation == "scope":
        probe["attribution_scope"] = "terminal_payload"
    elif mutation == "evidence_status":
        probe["evidence"]["status"] = "validated_terminal_family_config"
    elif mutation == "missing":
        probe["evidence"]["missing_proof_codes"] = []
    elif mutation == "protocol_type":
        probe["evidence"]["terminal_protocol_contract"]["proven"] = "false"
    elif mutation == "sample_executed":
        probe["sample_executed"] = True
    elif mutation == "network_contacted":
        probe["network_contacted"] = True

    assert _detect(monkeypatch, probe) is None


def _n520_terminal_probe() -> dict:
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "single_pe_n520_managed",
        "supports_family_attribution": True,
        "static_config_recovered": True,
        "attribution_scope": "validated_terminal_component_structure",
        "classification_confidence": "high_structural_decoded_config",
        "evidence": {
            "managed_structure": {
                "matched": True,
                "managed_metadata_validated": True,
                "key_method_name_required": False,
                "key_method_identification": (
                    "validated_cil_initializer_data_flow"
                ),
                "crypto_api_groups": {
                    "runtime_array_initializer": True,
                    "base64_decoder": True,
                    "sha256_key_derivation": True,
                    "aes_cbc_decryptor": True,
                },
                "required_crypto_group_count": 4,
                "matched_crypto_group_count": 4,
                "sample_executed": False,
                "network_contacted": False,
            },
            "initializer": {
                "method_identification": "validated_cil_initializer_data_flow",
                "method_name_required": False,
                "source_array_type": "System.Byte",
                "returned_array_type": "System.Byte",
                "int32_to_byte_conversion_validated": False,
                "initializer": "RuntimeHelpers.InitializeArray",
                "field_rva_present": True,
                "key_size": 16,
                "raw_key_included": False,
            },
            "aes_cbc_pkcs7_validated": True,
        },
        "config": {
            "decrypted_value_count": 2,
            "public_network_value_count": 1,
            "opaque_value_count": 1,
            "raw_key_included": False,
            "raw_ciphertexts_included": False,
            "raw_plaintexts_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _vvas_terminal_probe() -> dict:
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "vvas_reversed_config_terminal",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "static_config_recovered": True,
        "candidate_config_recovered": False,
        "attribution_scope": "validated_terminal_component_structure",
        "classification_confidence": "high_structural_decoded_config",
        "family_attribution_basis": (
            "unique_vvas_config_and_mapped_reachable_parser_network_dataflow"
        ),
        "evidence": {
            "vvas_reversed_config": {
                "candidate_count": 1,
                "unique_configuration_count": 1,
                "endpoint_count": 1,
                "configured_slot_count": 1,
                "mapped_config_scan": {
                    "status": "complete_candidates",
                    "completed": True,
                    "candidate_set_complete": True,
                    "truncated": False,
                    "truncation_reasons": [],
                    "marker_scan_passes": 1,
                    "unique_configuration_count": 1,
                    "raw_config_included": False,
                    "raw_network_values_included": False,
                },
                "raw_config_included": False,
            },
            "format_corroboration": {
                "matched": True,
                "architecture": "x86",
                "root_strategy": "entrypoint",
                "configuration_storage": "mapped_data",
                "validated_network_chain_count": 1,
                "required_groups": {
                    "mapped_configuration_source": True,
                    "resource_source_to_parser": True,
                    "selected_root_to_launcher": True,
                    "reachable_config_reference": True,
                    "reachable_parser_reverse_path": True,
                    "launcher_parser_before_callback": True,
                    "launcher_parser_to_callback_cfg_path": True,
                    "reachable_vtable_network_path": True,
                    "same_descriptor_winsock_cluster": True,
                    "single_reachable_winsock_chain": True,
                },
                "validated_network_chain_groups": {
                    "winsock_initialization": True,
                    "socket_creation": True,
                    "connection": True,
                    "send": True,
                },
                "raw_addresses_included": False,
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
        },
        "config": {
            "endpoint_count": 1,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _vvas_resource_terminal_probe() -> dict:
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "single_pe_vvas_resource",
        "supports_family_attribution": True,
        "static_config_recovered": True,
        "attribution_scope": "validated_terminal_component_structure",
        "evidence": {
            "markers": {
                "entrypoint_reachable_resource_loader_data_flow": True,
                "rcdata_788_present": True,
                "executable_resource_with_decoded_config": True,
                "all_target_resource_languages_validated": True,
                "unique_executable_resource_config": True,
                "resource_string_scans_complete": True,
            },
            "loader_linkage": {
                "architecture": "x86_64",
                "single_kernel32_import_descriptor": True,
                "entrypoint_reachable_loader_function": True,
                "findresource_type_10_name_788_arguments": True,
                "resource_handle_chain_same_function": True,
                "locked_pointer_copied_to_allocated_buffer": True,
                "allocated_buffer_protected_for_execution": True,
                "allocated_buffer_passed_as_thread_start": True,
                "thread_handle_waited": True,
                "instruction_boundary_cfg_validated": True,
                "copy_callee_bounded_memory_move": True,
                "copy_callee_profile": "bounded_scalar_byte_copy_loop",
                "reachable_function_count": 1,
                "validated_loader_count": 1,
                "raw_code_included": False,
            },
            "matched_resource_count": 1,
            "resource_bytes_included": False,
        },
        "config": {
            "endpoint_count": 1,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _direct_terminal_probe(probe_name: str) -> dict:
    return {
        "probe_n520_config": _n520_terminal_probe,
        "probe_vvas_config": _vvas_terminal_probe,
        "probe_vvas_resource_config": _vvas_resource_terminal_probe,
    }[probe_name]()


@pytest.mark.parametrize(
    ("probe_name", "campaign_type"),
    [
        ("probe_n520_config", "single_pe_n520_managed"),
        ("probe_vvas_config", "vvas_reversed_config_terminal"),
        ("probe_vvas_resource_config", "single_pe_vvas_resource"),
    ],
)
def test_complete_direct_terminal_contract_confirms_family(
    monkeypatch: pytest.MonkeyPatch,
    probe_name: str,
    campaign_type: str,
) -> None:
    """実producer同形の完全契約だけは従来どおりfamilyを確定する。"""

    _disable_direct_probes(monkeypatch)
    probe = _direct_terminal_probe(probe_name)
    if probe_name == "probe_vvas_config":
        probe["evidence"]["format_corroboration"]["architecture"] = "x64"
        monkeypatch.setattr(
            DETECT,
            probe_name,
            lambda _data, *, input_format: copy.deepcopy(probe),
        )
    else:
        monkeypatch.setattr(
            DETECT,
            probe_name,
            lambda _data: copy.deepcopy(probe),
        )
    data = b"MZ synthetic complete direct probe"

    result = DETECT._terminal_configuration_detection(
        data,
        DETECT.hashlib.sha256(data).hexdigest(),
        "fixture.exe",
    )

    assert result is not None
    assert result["supports_family_attribution"] is True
    assert result["campaigns"][0]["campaign_type"] == campaign_type
    assert result["campaigns"][0]["terminal_family_confirmed"] is True


@pytest.mark.parametrize(
    "probe_name",
    [
        "probe_n520_config",
        "probe_vvas_config",
        "probe_vvas_resource_config",
    ],
)
@pytest.mark.parametrize(
    "mutation",
    [
        "family",
        "variant",
        "supports",
        "terminal",
        "static",
        "candidate",
        "scope",
        "evidence",
        "generic_evidence",
        "evidence_contract",
        "nested_raw",
        "count",
        "raw_network",
        "sample_executed",
        "network_contacted",
    ],
)
def test_direct_terminal_probe_mutations_never_confirm_family(
    monkeypatch: pytest.MonkeyPatch,
    probe_name: str,
    mutation: str,
) -> None:
    """N520・vvaS系probeをmatchedだけでfamily確定へ昇格しない。"""

    _disable_direct_probes(monkeypatch)
    probe = _direct_terminal_probe(probe_name)
    if mutation == "family":
        probe["family"] = "unknown"
    elif mutation == "variant":
        probe["variant"] = "unexpected_variant"
    elif mutation == "supports":
        probe["supports_family_attribution"] = False
    elif mutation == "terminal":
        probe["terminal_family_confirmed"] = False
    elif mutation == "static":
        probe["static_config_recovered"] = False
    elif mutation == "candidate":
        probe["candidate_config_recovered"] = True
    elif mutation == "scope":
        probe["attribution_scope"] = "component_handler_route"
    elif mutation == "evidence":
        probe["evidence"] = {}
    elif mutation == "generic_evidence":
        probe["evidence"] = {"validated_structure": True}
    elif mutation == "evidence_contract":
        if probe_name == "probe_n520_config":
            probe["evidence"]["aes_cbc_pkcs7_validated"] = False
        elif probe_name == "probe_vvas_config":
            probe["evidence"]["format_corroboration"]["required_groups"][
                "same_descriptor_winsock_cluster"
            ] = False
        else:
            probe["evidence"]["markers"][
                "entrypoint_reachable_resource_loader_data_flow"
            ] = False
    elif mutation == "nested_raw":
        if probe_name == "probe_n520_config":
            probe["config"]["raw_key_included"] = True
        elif probe_name == "probe_vvas_config":
            probe["evidence"]["format_corroboration"][
                "raw_addresses_included"
            ] = True
        else:
            probe["evidence"]["resource_bytes_included"] = True
    elif mutation == "count":
        count_field = (
            "public_network_value_count"
            if probe_name == "probe_n520_config"
            else "endpoint_count"
        )
        probe["config"][count_field] = 0
    elif mutation == "raw_network":
        probe["config"]["raw_network_values_included"] = True
    elif mutation == "sample_executed":
        probe["sample_executed"] = True
    elif mutation == "network_contacted":
        probe["network_contacted"] = True

    if probe_name == "probe_vvas_config":
        monkeypatch.setattr(
            DETECT,
            probe_name,
            lambda _data, *, input_format: copy.deepcopy(probe),
        )
    else:
        monkeypatch.setattr(
            DETECT,
            probe_name,
            lambda _data: copy.deepcopy(probe),
        )
    data = b"MZ synthetic mutated direct probe"

    assert (
        DETECT._terminal_configuration_detection(
            data,
            DETECT.hashlib.sha256(data).hexdigest(),
            "fixture.exe",
        )
        is None
    )
