"""独立Ghidra照合で確定したWinos variant境界を回帰検証する。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path
from types import ModuleType


FRAMEWORK = Path(__file__).resolve().parents[1]
VALLEY = FRAMEWORK / "malware" / "valleyrat"


def _load(name: str) -> ModuleType:
    path = VALLEY / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"{name}_regression_target", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CA00 = _load("winos_ca00_contracts")
CA01 = _load("winos_ca01_contracts")
BOOTSTRAP = _load("winos_nvml_bootstrap_contracts")
MAIN = _load("winos_nvml_main_contracts")


def _transfer(module: ModuleType, command: int, body: bytes, advertised: int) -> bytes:
    descriptor = bytearray(module.MODULE_DESCRIPTOR_BYTES)
    struct.pack_into(
        "<I",
        descriptor,
        module.MODULE_SIZE_OFFSET_IN_DESCRIPTOR,
        advertised,
    )
    return bytes([command]) + bytes(descriptor) + body


def test_ca00_provenance_points_to_recovered_dispatcher_not_root_dll() -> None:
    assert CA00.SAMPLE_SHA256 == "4df8bda2718afbd6ee42a96e0097d24592e451a1c6a05d9bffa8921c683733e2"
    assert CA00.ROOT_SAMPLE_SHA256 == "da33a95b2ed28e2c50da002584eb81e4e94fe4a55e98945146842ed9e23be066"
    assert CA00.PROGRAM_SELECTOR.endswith(f"/{CA00.SAMPLE_SHA256}.bin")
    assert CA00.DISPATCHER == "FUN_100108b6"
    assert CA00.CIPHER_MODE == "rolling_header_plus_0x36"

    result = CA00.classify_ca00_payload(b"\x02")
    assert result.sample_sha256 == CA00.SAMPLE_SHA256
    assert result.root_sample_sha256 == CA00.ROOT_SAMPLE_SHA256
    assert result.program_selector == CA00.PROGRAM_SELECTOR
    assert result.dispatcher == CA00.DISPATCHER
    assert result.cipher_mode == CA00.CIPHER_MODE


def test_ca00_command_zero_reply_is_metadata_only() -> None:
    result = CA00.classify_ca00_payload(bytes([0x00]) + bytes(0xA44))
    assert result.expected_reply_command == 0x05
    assert result.reply_condition == "module_not_already_loaded"
    assert result.should_respond is False
    assert result.wire_bytes is None


def test_ca00_and_ca01_module_transfer_validate_advertised_body_without_loading() -> None:
    for module, classify in (
        (CA00, CA00.classify_ca00_payload),
        (CA01, CA01.classify_ca01_payload),
    ):
        exact = classify(_transfer(module, 0x01, b"MZ", 2))
        summary = exact.module_transfer_summary
        assert exact.length_valid is True
        assert exact.structure_valid is True
        assert exact.contract_valid is True
        assert summary is not None
        assert summary.module_body_offset == 0xA45
        assert summary.module_size_offset_in_descriptor == 0x208
        assert summary.advertised_module_size == 2
        assert summary.available_module_bytes == 2
        assert summary.body_exactly_advertised_size is True
        assert summary.trailing_bytes_after_advertised_body == 0
        assert ("malware_length_validation", "none") in exact.metadata
        assert exact.operation_executed is False
        assert exact.raw_payload_retained is False
        assert exact.wire_bytes is None

        extra = classify(_transfer(module, 0x01, b"MZEXTRA", 2))
        assert extra.contract_valid is True
        assert extra.module_transfer_summary is not None
        assert extra.module_transfer_summary.body_exactly_advertised_size is False
        assert extra.module_transfer_summary.trailing_bytes_after_advertised_body == 5
        assert ("trailing_module_bytes_ignored", 5) in extra.metadata

        truncated = classify(_transfer(module, 0x01, b"M", 2))
        assert truncated.length_valid is True
        assert truncated.structure_valid is False
        assert "advertised_module_size_exceeds_available_bytes" in truncated.validation_errors

        zero = classify(_transfer(module, 0x01, b"", 0))
        assert zero.structure_valid is False
        assert "advertised_module_size_not_positive" in zero.validation_errors


def test_variant_config_copy_capacity_records_malware_overflow_risk() -> None:
    for module, classify, command in (
        (CA00, CA00.classify_ca00_payload, 0x13),
        (CA01, CA01.classify_ca01_payload, 0x12),
    ):
        minimum = classify(bytes([command]))
        maximum = classify(bytes([command]) + bytes(0x7D1))
        over = classify(bytes([command]) + bytes(0x7D2))
        assert minimum.length_valid is True
        assert maximum.length_valid is True
        assert maximum.maximum_length == 0x7D2
        assert over.length_valid is False
        assert ("malware_length_validation", "none") in maximum.metadata
        assert ("dispatcher_copy_capacity", 0x7D2) in maximum.metadata
        assert ("unchecked_copy_overflow_risk", True) in maximum.metadata


def test_main_acceptance_length_and_safe_utf16_structure_are_separate() -> None:
    command_line_odd = MAIN.classify_main_payload(b"\x06A")
    assert command_line_odd.length_valid is True
    assert command_line_odd.structure_valid is False
    assert command_line_odd.contract_valid is False
    assert command_line_odd.minimum_length == 2
    assert ("malware_minimum_decoded_payload_bytes", 2) in command_line_odd.metadata

    command_line_valid = MAIN.classify_main_payload(b"\x06A\x00")
    assert command_line_valid.contract_valid is True

    unload_odd = MAIN.classify_main_payload(b"\x74A")
    assert unload_odd.length_valid is True
    assert unload_odd.structure_valid is False
    assert unload_odd.minimum_length == 2
    assert ("malware_may_read_undersized_wchar", True) in unload_odd.metadata
    assert MAIN.classify_main_payload(b"\x74A\x00").contract_valid is True

    config_command_only = MAIN.classify_main_payload(b"\x12")
    assert config_command_only.length_valid is True
    assert config_command_only.minimum_length == 1
    assert MAIN.classify_main_payload(b"\x12" + bytes(0x7D1)).length_valid is True
    assert MAIN.classify_main_payload(b"\x12" + bytes(0x7D2)).length_valid is False


def test_main_module_descriptor_and_transfer_are_hash_only_and_bounded() -> None:
    descriptor = _transfer(MAIN, 0x00, b"", 7)
    request = MAIN.classify_main_payload(descriptor)
    assert len(descriptor) == MAIN.MODULE_BODY_OFFSET
    assert request.length_valid is True
    assert request.structure_valid is True
    assert request.module_transfer_summary is not None
    assert request.module_transfer_summary.advertised_module_size == 7
    assert request.module_transfer_summary.advertised_size_available is None

    transfer = MAIN.classify_main_payload(_transfer(MAIN, 0x01, b"MZ", 2))
    assert transfer.contract_valid is True
    assert transfer.module_transfer_summary is not None
    assert transfer.module_transfer_summary.advertised_size_available is True
    assert transfer.module_transfer_summary.module_body_offset == 0xA43
    assert transfer.operation_executed is False
    assert transfer.delegated_handler_called is False
    assert transfer.wire_bytes is None

    truncated = MAIN.classify_main_payload(_transfer(MAIN, 0x01, b"M", 2))
    assert truncated.length_valid is True
    assert truncated.structure_valid is False
    assert "advertised_module_size_exceeds_available_bytes" in truncated.validation_errors


def _command_81(total: int, embedded_size: int) -> bytes:
    payload = bytearray(total)
    payload[0] = 0x81
    struct.pack_into("<I", payload, 2, embedded_size)
    return bytes(payload)


def test_main_command_81_exact_total_and_embedded_size_contract() -> None:
    too_short = MAIN.classify_main_payload(_command_81(0x85, 1))
    minimum_but_inconsistent = MAIN.classify_main_payload(_command_81(0x86, 1))
    minimum_valid = MAIN.classify_main_payload(_command_81(0x87, 1))
    assert too_short.length_valid is False
    assert minimum_but_inconsistent.length_valid is True
    assert minimum_but_inconsistent.structure_valid is False
    assert minimum_valid.contract_valid is True
    assert ("command_81_size_plus_0x86_within_total", True) in minimum_valid.metadata

    zero = MAIN.classify_main_payload(_command_81(0x86, 0))
    assert zero.structure_valid is False
    assert "command_81_embedded_size_outside_range" in zero.validation_errors

    maximum = MAIN.classify_main_payload(_command_81(MAIN.COMMAND_81_MAXIMUM_TOTAL_BYTES, 0x200000))
    assert maximum.length_valid is True
    assert maximum.structure_valid is True
    assert maximum.contract_valid is True
    assert maximum.delegated_handler_called is False

    over_total = MAIN.classify_main_payload(_command_81(MAIN.COMMAND_81_MAXIMUM_TOTAL_BYTES + 1, 1))
    assert over_total.length_valid is False


def test_bootstrap_dispatcher_32mib_branch_is_not_single_frame_reachable() -> None:
    assert BOOTSTRAP.WIRE_MAXIMUM_TOTAL_FRAME_BYTES == 0x02000000
    assert BOOTSTRAP.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES == 0x02000000 - 14
    assert BOOTSTRAP.MAX_EMBEDDED_MODULE_BYTES == 0x02000000
    assert BOOTSTRAP.MODULE_BODY_OFFSET == 0xA43
    assert BOOTSTRAP.MAX_WIRE_REACHABLE_MODULE_BYTES == 0x01FFF5AF
    assert (
        BOOTSTRAP.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES - BOOTSTRAP.MODULE_BODY_OFFSET
        == BOOTSTRAP.MAX_WIRE_REACHABLE_MODULE_BYTES
    )
    assert BOOTSTRAP.MAX_WIRE_REACHABLE_MODULE_BYTES < BOOTSTRAP.MAX_EMBEDDED_MODULE_BYTES
    assert MAIN.MAX_WIRE_REACHABLE_MODULE_BYTES == 0x01FFF5AF


def test_main_group_or_remark_errors_stay_in_utf16_contract_fields() -> None:
    result = MAIN.classify_main_payload(b"\x07\x00\x00\x00")

    assert result.length_valid is True
    assert result.structure_valid is False
    assert result.contract_valid is False
    assert "utf16_no_non_null_code_unit" in result.validation_errors
    assert result.utf16_summary is not None
    assert result.utf16_summary.valid is False
    assert result.module_transfer_summary is None
