"""MSI/AHK/AES-GCM manual-only候補handlerの監査境界を検証する。"""

from __future__ import annotations

import ast
import runpy
import sys
from pathlib import Path

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
sys.path.insert(0, str(FRAMEWORK_ROOT / "common"))

import handler_catalog as catalog
from extractors.valleyrat.msi_ahk_aes_gcm import MsiAhkAesGcmRecovery

SOURCE = "extractors/valleyrat/msi_ahk_aes_gcm.py"


def _shape_results(source: str, key: tuple[str, str, str]) -> list[bool]:
    """合成source内の対象call全件へ同じsource限定shape監査を適用する。"""

    tree = ast.parse(source)
    function_name = key[1].removeprefix("reachable:")
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function_name)
    calls = [
        node for node in ast.walk(scope) if isinstance(node, ast.Call) and catalog._ast_call_name(node.func) == key[2]
    ]
    return [
        catalog._reviewed_source_call_shape_allowed(
            call,
            key[2],
            tree,
            scope,
            catalog._import_aliases(tree),
            key=key,
        )
        for call in calls
    ]


def test_cabarchive_guard_requires_exact_memory_candidate() -> None:
    key = (SOURCE, "reachable:_cab_members", "cabarchive.CabArchive")
    source = """import cabarchive
def _cab_members(data):
    cab_streams = []
    archive = cabarchive.CabArchive(cab_streams[0])
    return archive
"""

    assert key in catalog._REVIEWED_SOURCE_CALLS
    assert _shape_results(source, key) == [True]
    assert _shape_results(source.replace("cab_streams[0]", "data"), key) == [False]
    assert _shape_results(source.replace("cab_streams = []", "cab_streams = user_streams"), key) == [False]
    assert _shape_results(source.replace("    archive =", "    data = b'x'\n    archive ="), key) == [False]


def test_gcm_guard_requires_fixed_mode_aad_ciphertext_and_tag() -> None:
    key = (SOURCE, "reachable:_decrypt_gcm", "cipher.decrypt_and_verify")
    source = """from Cryptodome.Cipher import AES
def _decrypt_gcm(container, key):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=container.nonce, mac_len=0x10)
        cipher.update(container.aad)
        return cipher.decrypt_and_verify(container.ciphertext, container.tag)
    except ValueError:
        return None
"""

    assert key in catalog._REVIEWED_SOURCE_CALLS
    assert _shape_results(source, key) == [True]
    assert _shape_results(source.replace("AES.MODE_GCM", "AES.MODE_CBC"), key) == [False]
    assert _shape_results(source.replace("container.aad", "untrusted.aad"), key) == [False]
    assert _shape_results(source.replace("container.ciphertext", "untrusted"), key) == [False]
    assert _shape_results(source.replace("container.tag", "raw_tag"), key) == [False]
    indirect_return = source.replace(
        "        return cipher.decrypt_and_verify(container.ciphertext, container.tag)",
        "        plaintext = cipher.decrypt_and_verify(container.ciphertext, container.tag)\n        return plaintext",
    )
    assert _shape_results(indirect_return, key) == [False]
    conditional_aad = source.replace(
        "        cipher.update(container.aad)",
        "        if key:\n            cipher.update(container.aad)",
    )
    assert _shape_results(conditional_aad, key) == [False]
    dead_aad = source.replace(
        "        cipher.update(container.aad)\n"
        "        return cipher.decrypt_and_verify(container.ciphertext, container.tag)",
        "        if False:\n            cipher.update(container.aad)\n"
        "        return cipher.decrypt_and_verify(container.ciphertext, container.tag)",
    )
    assert _shape_results(dead_aad, key) == [False]
    reordered_aad = source.replace(
        "        cipher.update(container.aad)\n"
        "        return cipher.decrypt_and_verify(container.ciphertext, container.tag)",
        "        return cipher.decrypt_and_verify(container.ciphertext, container.tag)\n"
        "        cipher.update(container.aad)",
    )
    assert _shape_results(reordered_aad, key) == [False]


def test_function_disasm_guard_requires_fixed_x64_bounded_slice() -> None:
    key = (SOURCE, "reachable:_function_instructions", "disassembler.disasm")
    source = """from capstone import CS_ARCH_X86, CS_MODE_64, Cs
MAXIMUM_FUNCTION_BYTES = 0x4000
def _function_instructions(data, offset):
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    return disassembler.disasm(
        data[offset : min(len(data), offset + MAXIMUM_FUNCTION_BYTES)],
        offset,
    )
"""

    assert key in catalog._REVIEWED_SOURCE_CALLS
    assert _shape_results(source, key) == [True]
    assert _shape_results(source.replace("CS_MODE_64", "CS_MODE_32"), key) == [False]
    assert _shape_results(source.replace("0x4000", "0x8000"), key) == [False]
    assert _shape_results(
        source.replace(
            "MAXIMUM_FUNCTION_BYTES = 0x4000",
            "MAXIMUM_FUNCTION_BYTES = 0x4000\nMAXIMUM_FUNCTION_BYTES = 0x8000",
        ),
        key,
    ) == [False]
    assert _shape_results(source.replace("MAXIMUM_FUNCTION_BYTES", "user_limit"), key) == [False]
    assert _shape_results(source.replace("disassembler.detail = True", "disassembler.detail = False"), key) == [False]
    assert _shape_results(source.replace("        offset,\n", "        0,\n"), key) == [False]


def test_main_disasm_guard_allows_only_entry_and_main_windows() -> None:
    key = (SOURCE, "reachable:_main_profile", "disassembler.disasm")
    source = """from capstone import CS_ARCH_X86, CS_MODE_64, Cs
MAXIMUM_FUNCTION_BYTES = 0x4000
def _main_profile(data):
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    entry = tuple(disassembler.disasm(data[:16], 0))
    main = tuple(disassembler.disasm(data[main_offset : main_offset + 64], main_offset))
    return entry, main
"""

    assert key in catalog._REVIEWED_SOURCE_CALLS
    assert _shape_results(source, key) == [True, True]
    assert _shape_results(source.replace("data[:16]", "data[:17]"), key) == [False, False]
    assert _shape_results(source.replace("main_offset + 64", "main_offset + 65"), key) == [False, False]
    assert _shape_results(source.replace("CS_MODE_64", "CS_MODE_32"), key) == [False, False]
    assert _shape_results(source.replace("0x4000", "0x8000"), key) == [False, False]
    assert _shape_results(
        source.replace(
            "MAXIMUM_FUNCTION_BYTES = 0x4000",
            "MAXIMUM_FUNCTION_BYTES = 0x4000\nMAXIMUM_FUNCTION_BYTES = 0x8000",
        ),
        key,
    ) == [False, False]


@pytest.mark.parametrize(
    "escape",
    [
        "    alias = disassembler",
        "    alias = chained = disassembler",
        "    method = disassembler.disasm",
        "    mutate(disassembler)",
        "    receivers = [disassembler]",
        '    receivers = {"disassembler": disassembler}',
        "    holder.value = disassembler",
        "    holder[0] = disassembler",
        "    return disassembler",
        "    yield disassembler",
        "    global leaked\n    leaked = disassembler",
        "    leaked = None\n    def escape_receiver():\n        nonlocal leaked\n        leaked = disassembler",
        "    leaked = lambda: disassembler",
    ],
)
def test_function_disasm_guard_rejects_receiver_escape(escape: str) -> None:
    """MSI/AHK経路でもreceiverを未証明の別名や外部callへ渡さない。"""

    key = (SOURCE, "reachable:_function_instructions", "disassembler.disasm")
    source = """from capstone import CS_ARCH_X86, CS_MODE_64, Cs
MAXIMUM_FUNCTION_BYTES = 0x4000
def _function_instructions(data, offset):
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    return disassembler.disasm(
        data[offset : min(len(data), offset + MAXIMUM_FUNCTION_BYTES)],
        offset,
    )
"""
    source = source.replace(
        "    return disassembler.disasm(",
        f"{escape}\n    return disassembler.disasm(",
    )

    assert _shape_results(source, key) == [False]


def test_handler_is_dependency_audited_but_automatic_preflight_is_disabled() -> None:
    handler_path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "msi_ahk_aes_gcm_terminal" / "analyze.py"
    audit = catalog._recursive_handler_side_effect_audit(handler_path, "analyze")

    assert audit["issues"] == []
    spec = next(
        item
        for item in catalog.discover_handlers()
        if item.relative_path.endswith("malware/valleyrat/campaigns/msi_ahk_aes_gcm_terminal/analyze.py")
        and item.callable_name == "analyze"
    )
    assert spec.automatic is False
    assert spec.reason == "candidate_lineage_requires_manual_evidence_review"
    catalog.clear_handler_caches()
    try:
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format="ole",
            input_size=600_000,
        )
    finally:
        catalog.clear_handler_caches()

    assert preflight["eligible"] is False
    assert preflight["blockers"] == ["handler_not_automatic"]


def test_manual_handler_never_confirms_family_configuration_or_c2() -> None:
    handler_path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "msi_ahk_aes_gcm_terminal" / "analyze.py"
    namespace = runpy.run_path(str(handler_path))
    recovery = MsiAhkAesGcmRecovery(
        source_size=600_000,
        cab_member_count=3,
        shellcode=b"synthetic-candidate",
        endpoint="fixture.example.net:443",
        auxiliary_lengths=(5, 0, 5),
        flag=1,
        evidence={"gcm_authentication_succeeded": True},
    )
    namespace["analyze"].__globals__["recover_msi_ahk_aes_gcm"] = lambda _data: recovery

    result = namespace["analyze"](b"synthetic", "fixture.msi")

    assert result["family"] is None
    assert result["matched"] is False
    assert result["decoded_config_recovered"] is False
    assert result["static_config_recovered"] is False
    assert result["candidate_config_recovered"] is True
    assert result["supports_family_attribution"] is False
    assert result["family_attribution_confirmed"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["final_rat_confirmed"] is False
    assert result["c2_confirmed"] is False
    assert result["command_c2_confirmed"] is False
    assert result["qualified"] is False
    assert result["automatic_route_eligible"] is False
    assert result["used_for_resolution"] is False
    assert result["used_for_family_resolution"] is False
    assert result["used_for_c2_confirmation"] is False
    assert result["endpoints"] == []
    assert result["c2"] == []
    assert result["terminal_payload"] is None
    assert result["evidence_boundary"]["all_expected_fields_validated"] is False
    for missing_proof in (
        "network_caller_stack_frame_integrity_proven",
        "post_getaddrinfo_api_calls_single_path_proven",
        "api_hash_to_slot_assignments_single_path_proven",
        "decryptor_output_and_service_producer_dataflow_proven",
        "msi_component_directory_install_path_binding_proven",
        "ahk_cryptstring_decode_arguments_and_buffer_size_proven",
    ):
        assert result["evidence_boundary"][missing_proof] is False
    assert result["c2_candidates"] == [
        {
            "endpoint": "fixture.example.net:443",
            "transport": "tcp",
            "role": "unverified_route_or_config_candidate",
            "confidence": "unverified_static_candidate",
            "evidence": {
                "kind": "manual_msi_ahk_aes_gcm_candidate",
                "all_expected_fields_validated": False,
                "configured_route_data_flow_validated": False,
                "family_attribution_confirmed": False,
                "static_config_recovered": False,
                "terminal_family_confirmed": False,
                "c2_confirmed": False,
                "command_c2_confirmed": False,
            },
            "contacted": False,
            "liveness_confirmed": False,
            "qualified": False,
            "used_for_resolution": False,
            "used_for_family_resolution": False,
            "used_for_c2_confirmation": False,
        }
    ]


@pytest.mark.parametrize("actual_format", ["pe", "zip", "script", "data"])
def test_handler_preflight_rejects_non_ole_inputs(actual_format: str) -> None:
    spec = next(
        item
        for item in catalog.discover_handlers()
        if item.relative_path.endswith("malware/valleyrat/campaigns/msi_ahk_aes_gcm_terminal/analyze.py")
        and item.callable_name == "analyze"
    )

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format=actual_format,
        input_size=600_000,
    )

    assert preflight["eligible"] is False
    assert f"incompatible_input_format:{actual_format}" in preflight["blockers"]
