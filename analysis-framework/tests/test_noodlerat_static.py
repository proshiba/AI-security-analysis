"""NoodleRAT静的抽出・判定・受動C2出力の回帰テスト。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
COMMON = FRAMEWORK / "common"
FAMILY = FRAMEWORK / "malware" / "noodlerat"
for import_root in (COMMON, FAMILY):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import c2_hunt
import detect
import extract_config as noodle
import handler_catalog
from analysis_contract import handler_result_quality

CODE_OFFSET = 0x1000
CODE_ADDRESS = 0x400000
DATA_OFFSET = 0x4000
DATA_ADDRESS = 0x600000
LENGTH_ADDRESS = DATA_ADDRESS + 0x20
CIPHER_ADDRESS = LENGTH_ADDRESS + 2


def _locator(address: int = CODE_ADDRESS) -> bytes:
    code = bytearray()
    for displacement, value in enumerate(noodle.CONFIG_KEY + b"\x00", start=0x50):
        code.extend((0xC6, 0x44, 0x24, displacement, value))
    code.extend(b"\x48\x8d\x54\x24\x50")
    instruction_address = address + len(code)
    relative = LENGTH_ADDRESS - (instruction_address + 7)
    code.extend(b"\x0f\xb7\x35" + struct.pack("<i", relative))
    code.extend(b"\xbf" + struct.pack("<I", CIPHER_ADDRESS))
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\xbf" + struct.pack("<I", CIPHER_ADDRESS))
    return bytes(code)


def _command_code(*, include_all: bool = True, raw_only: bool = False) -> bytes:
    values = sorted(noodle.TRANSFER_COMMANDS | noodle.VARIANT_COMMANDS["linux_legacy"])
    if not include_all:
        values.pop()
    if raw_only:
        return b"".join(struct.pack("<I", value) for value in values)
    return b"".join(b"\x3d" + struct.pack("<I", value) for value in values)


def build_elf(
    plaintext: bytes = b"C2.EXAMPLE.COM:443;|1;1;1;1;1;1;1;|00-24;|10",
    *,
    include_all_commands: bool = True,
    raw_commands_only: bool = False,
    duplicate_lineage: bool = False,
) -> bytes:
    total_size = DATA_OFFSET + 0x1000
    blob = bytearray(total_size)
    blob[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        blob,
        16,
        2,
        62,
        1,
        CODE_ADDRESS,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        blob,
        64,
        1,
        5,
        CODE_OFFSET,
        CODE_ADDRESS,
        CODE_ADDRESS,
        0x3000,
        0x3000,
        0x1000,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        blob,
        120,
        1,
        6,
        DATA_OFFSET,
        DATA_ADDRESS,
        DATA_ADDRESS,
        0x1000,
        0x1000,
        0x1000,
    )
    code = bytearray(_locator())
    if duplicate_lineage:
        code.extend(b"\x90" * 8)
        code.extend(_locator(CODE_ADDRESS + len(code)))
    code.extend(b"\x90" * 32)
    code.extend(
        _command_code(include_all=include_all_commands, raw_only=raw_commands_only)
    )
    blob[CODE_OFFSET : CODE_OFFSET + len(code)] = code
    ciphertext = noodle.rc4_crypt(plaintext)
    struct.pack_into("<H", blob, DATA_OFFSET + 0x20, len(ciphertext))
    blob[DATA_OFFSET + 0x22 : DATA_OFFSET + 0x22 + len(ciphertext)] = ciphertext
    return bytes(blob)


def test_extract_unknown_hash_with_complete_structural_correlation() -> None:
    result = noodle.extract_config(build_elf())
    assert result["family"] == "noodlerat"
    assert result["classification_confidence"] == "confirmed_structural_lineage"
    assert result["config"]["configured_slots"] == [
        {"slot": 1, "host": "c2.example.com", "port": 443}
    ]
    assert result["static_evidence"]["command_fingerprint"]["variant"] == "linux_legacy"
    assert result["static_evidence"]["raw_config_included"] is False
    assert result["safety"]["network_contacted"] is False


def test_duplicate_config_slots_are_preserved_but_canonical_ioc_is_deduplicated() -> None:
    sample = build_elf(
        b"198.51.100.42:9601;198.51.100.42:9601;|1;1;1;1;1;1;1;|00-24;|1"
    )
    result = noodle.extract_config(sample)
    assert len(result["config"]["configured_slots"]) == 2
    assert len(result["config_endpoints"]) == 1
    assert len(result["findings"]) == 1


@pytest.mark.parametrize(
    "plaintext",
    [
        b"host:443|1;1;1;1;1;1;1;|00-24;|1",
        b"host:443;|1;1;1;1;1;1;|00-24;|1",
        b"host:443;|1;1;1;1;1;1;1;|24-00;|1",
        b"host:443;|1;1;1;1;1;1;1;|00-24;|0",
        b"host:70000;|1;1;1;1;1;1;1;|00-24;|1",
    ],
)
def test_config_grammar_rejects_partial_or_invalid_fields(plaintext: bytes) -> None:
    with pytest.raises(ValueError):
        noodle.parse_plaintext_config(plaintext)


def test_unknown_hash_requires_cmp_command_cluster_not_raw_constants() -> None:
    with pytest.raises(ValueError, match="command cluster"):
        noodle.extract_config(build_elf(raw_commands_only=True))
    with pytest.raises(ValueError, match="command cluster"):
        noodle.extract_config(build_elf(include_all_commands=False))


def test_competing_config_lineages_fail_closed() -> None:
    with pytest.raises(ValueError, match="一意"):
        noodle.extract_config(build_elf(duplicate_lineage=True))


@pytest.mark.parametrize("mutation", ["class", "endian", "type", "machine", "truncated"])
def test_unsupported_or_corrupt_elf_is_rejected(mutation: str) -> None:
    data = bytearray(build_elf())
    if mutation == "class":
        data[4] = 1
    elif mutation == "endian":
        data[5] = 2
    elif mutation == "type":
        data[16:18] = b"\x03\x00"
    elif mutation == "machine":
        data[18:20] = b"\x03\x00"
    else:
        data = data[:40]
    with pytest.raises(ValueError):
        noodle.extract_config(bytes(data))


def test_oversized_elf_is_rejected_before_disassembly() -> None:
    sample = build_elf()
    oversized = sample + b"\x00" * (noodle.MAX_SAMPLE_SIZE - len(sample) + 1)
    with pytest.raises(ValueError, match="解析上限"):
        noodle.extract_config(oversized)


def test_detector_and_passive_hunt_do_not_contact_network() -> None:
    sample = build_elf()
    detection = detect.detect(sample)
    assert detection["matched"] is True
    assert detection["observations"]["supports_family_attribution"] is True
    hunt = c2_hunt.passive_hunt(noodle.extract_config(sample))
    assert hunt["network_contacted"] is False
    assert hunt["sample_executed"] is False
    assert hunt["active_protocol_sender_available"] is False
    assert hunt["targets"][0]["active_probe_performed"] is False
    assert hunt["protocol_profile"]["transport"] == "tcp_or_http_variant"
    assert hunt["protocol_profile"]["active_confirmation_default"] == "disabled"


def test_handler_result_meets_decoded_configuration_quality_gate() -> None:
    quality = handler_result_quality(noodle.extract_config(build_elf()), 40_000)
    assert quality["tier_name"] == "decoded_configuration"
    assert quality["sufficient"] is True


def test_production_handler_is_automatic_and_preflight_eligible() -> None:
    spec = next(
        item
        for item in handler_catalog.discover_handlers()
        if item.family == "noodlerat" and item.callable_name == "extract_config"
    )
    assert spec.automatic is True
    assert spec.input_formats == ("elf",)
    result = handler_catalog.preflight_handler_for_assessment(
        spec, actual_format="elf", input_size=len(build_elf())
    )
    assert result["eligible"] is True, result["blockers"]
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False


def test_registry_detector_loads_by_file_location() -> None:
    path = FAMILY / "detect.py"
    spec = importlib.util.spec_from_file_location("unknown_batch_noodlerat_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.detect(build_elf())["matched"] is True


def test_reviewed_sha256_inventory_is_exact() -> None:
    assert noodle.REVIEWED_SHA256 == {
        "e6f73e0919bc69b64ee445164c1706f42147d6f81d39d0fd0d688db92ef82905",
        "a330d63e261b6f9808ef6a441a6434a18b89661e80630b78c24aa538aff38bf7",
        "fa69c05b78784ebe7ebc0d1219db0ce8aee0c9c047b1342a0dac67fb44294c50",
        "d1e5f12f83e5f428642708beef887892aed7527ca7cd5ddda6285fcef32e3e4d",
    }
