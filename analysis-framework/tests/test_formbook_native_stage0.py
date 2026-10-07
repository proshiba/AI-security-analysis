"""FormBook系ネイティブstage-0静的復元器を人工PEで検証する。"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

import pefile
import pytest

FRAMEWORK = Path(__file__).parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from classifiers.classify_sample import detection_supports_family_attribution
from malware.formbook_loader import detect as detector
from malware.formbook_loader import extract_config as facade
from malware.formbook_loader import native_stage0

SECTION_RAW_OFFSET = 0x200
SECTION_RVA = 0x1000
SECTION_SIZE = 0x6000
DISPATCHER_OFFSET = 0x100
LOADER_ENTRY_OFFSET = 0x800
SOURCE_OFFSET = 0x1800
ENCRYPTED_LENGTH = 0x4000
BLOCK_SIZE = 0x400
STAGE_ENTRY_OFFSET = 0x1200
IMAGE_BASE = 0x400000


def _relative_call(source_rva: int, target_rva: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target_rva - (source_rva + 5))


def _stack_dword(displacement: int, value: int) -> bytes:
    return b"\xc7\x85" + struct.pack("<iI", displacement, value)


def _base_dword(displacement: int, value: int) -> bytes:
    return b"\xc7\x80" + struct.pack("<iI", displacement, value)


def _xor_key(material: bytes, *constants: int) -> bytes:
    mask = 0
    for constant in constants:
        mask ^= constant
    return b"".join(
        (value ^ mask).to_bytes(4, "little")
        for value in struct.unpack("<5I", material)
    )


def _block_rc4(data: bytes, key: bytes) -> bytes:
    return b"".join(
        native_stage0.rc4(data[offset:offset + BLOCK_SIZE], key)
        for offset in range(0, len(data), BLOCK_SIZE)
    )


def _pe_headers() -> bytearray:
    data = bytearray(SECTION_RAW_OFFSET + SECTION_SIZE)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, SECTION_RVA + LOADER_ENTRY_OFFSET)
    struct.pack_into("<I", data, optional + 20, SECTION_RVA)
    struct.pack_into("<I", data, optional + 28, IMAGE_BASE)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x8000)
    struct.pack_into("<I", data, optional + 60, SECTION_RAW_OFFSET)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<I", data, section + 8, SECTION_SIZE)
    struct.pack_into("<I", data, section + 12, SECTION_RVA)
    struct.pack_into("<I", data, section + 16, SECTION_SIZE)
    struct.pack_into("<I", data, section + 20, SECTION_RAW_OFFSET)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    return data


def _fixture(*, xor_selector: int = 0x3D) -> tuple[bytes, bytes, bytes, bytes]:
    raw_key_1 = bytes.fromhex("00112233445566778899aabbccddeeff10213243")
    raw_key_2 = bytes.fromhex("ffeeddccbbaa9988776655443322110001234567")
    constant_1 = 0xA1B2C3D4
    constant_2 = 0x10293847
    constant_3 = 0x55667788
    key_1 = _xor_key(raw_key_1, constant_1, constant_2)
    key_2 = _xor_key(raw_key_2, constant_3)

    dispatcher = bytearray(b"\x55\x8b\xec")
    for index, value in enumerate(struct.unpack("<5I", raw_key_1)):
        dispatcher.extend(_stack_dword(-0x100 + index * 4, value))
    for index, value in enumerate(struct.unpack("<5I", raw_key_2)):
        dispatcher.extend(_stack_dword(-0x140 + index * 4, value))
    dispatcher.extend(_stack_dword(-0x180, ENCRYPTED_LENGTH))
    dispatcher.extend(_stack_dword(-0x184, ENCRYPTED_LENGTH))
    dispatcher.extend(b"\x69\xd2" + struct.pack("<I", BLOCK_SIZE))
    dispatcher.extend(_base_dword(0x26E, BLOCK_SIZE))
    dispatcher.extend(_stack_dword(-0x188, SOURCE_OFFSET))
    dispatcher.extend(b"\x8b\x95" + struct.pack("<i", -0x188))
    dispatcher.extend(b"\x03\x90\x00\x02\x00\x00")
    dispatcher.extend(_base_dword(0x491, xor_selector))
    dispatcher.extend(_base_dword(0x184, constant_3))
    call_rva = SECTION_RVA + DISPATCHER_OFFSET + len(dispatcher)
    dispatcher.extend(_relative_call(call_rva, SECTION_RVA + DISPATCHER_OFFSET))
    dispatcher.extend(b"\x81\xc2" + struct.pack("<I", STAGE_ENTRY_OFFSET))
    dispatcher.extend(b"\x89\x95" + struct.pack("<i", -0x18C))
    dispatcher.extend(b"\x8b\x85" + struct.pack("<i", -0x18C))
    dispatcher.extend(b"\xff\xd0\xc3")

    entry = bytearray(b"\x55\x8b\xec")
    for constant in (constant_1, constant_2):
        entry.extend(_stack_dword(-0x37, xor_selector))
        entry.extend(_stack_dword(-0x344, constant))
        call_rva = SECTION_RVA + LOADER_ENTRY_OFFSET + len(entry)
        entry.extend(_relative_call(call_rva, SECTION_RVA + DISPATCHER_OFFSET))
    for opcode in (0x66, 0x5F):
        entry.extend(_stack_dword(-0x37, opcode))
        call_rva = SECTION_RVA + LOADER_ENTRY_OFFSET + len(entry)
        entry.extend(_relative_call(call_rva, SECTION_RVA + DISPATCHER_OFFSET))
    entry.extend(b"\xc3")

    stage = bytearray(b"\x90" * ENCRYPTED_LENGTH)
    stage[STAGE_ENTRY_OFFSET:STAGE_ENTRY_OFFSET + 16] = (
        b"\x55\x8b\xec\x83\xec\x20\xe8\x05\x00\x00\x00\x8b\xe5\x5d\xc3\x90"
    )
    encrypted = native_stage0.rc4(_block_rc4(bytes(stage), key_2), key_1)

    data = _pe_headers()
    dispatcher_raw = SECTION_RAW_OFFSET + DISPATCHER_OFFSET
    entry_raw = SECTION_RAW_OFFSET + LOADER_ENTRY_OFFSET
    source_raw = SECTION_RAW_OFFSET + SOURCE_OFFSET
    data[dispatcher_raw:dispatcher_raw + len(dispatcher)] = dispatcher
    data[entry_raw:entry_raw + len(entry)] = entry
    data[source_raw:source_raw + len(encrypted)] = encrypted
    return bytes(data), bytes(stage), key_1, key_2


def test_recovers_two_stage_rc4_analysis_pe_without_execution() -> None:
    sample, expected_stage, key_1, key_2 = _fixture()

    result = native_stage0.recover_native_stage0(sample)

    assert result.decrypted_stage == expected_stage
    assert result.profile.source_offset == SOURCE_OFFSET
    assert result.profile.encrypted_length == ENCRYPTED_LENGTH
    assert result.profile.block_size == BLOCK_SIZE
    assert result.profile.stage_entry_offset == STAGE_ENTRY_OFFSET
    assert result.profile.first_key == key_1
    assert result.profile.second_key == key_2
    assert result.profile.xor_selector == 0x3D
    image = pefile.PE(data=result.analysis_pe, fast_load=True)
    assert image.OPTIONAL_HEADER.AddressOfEntryPoint == (
        SECTION_RVA + SOURCE_OFFSET + STAGE_ENTRY_OFFSET
    )
    source_raw = SECTION_RAW_OFFSET + SOURCE_OFFSET
    assert result.analysis_pe[source_raw:source_raw + ENCRYPTED_LENGTH] == expected_stage


def test_recovers_rotated_xor_selector_without_fixed_opcode() -> None:
    sample, expected_stage, _key_1, _key_2 = _fixture(xor_selector=0xB0)

    result = native_stage0.recover_native_stage0(sample)

    assert result.decrypted_stage == expected_stage
    assert result.profile.xor_selector == 0xB0
    assert result.report["profile"]["xor_selector"] == 0xB0


def test_public_report_contains_hashes_but_not_key_material() -> None:
    sample, _stage, key_1, key_2 = _fixture()
    result = native_stage0.recover_native_stage0(sample)
    rendered = json.dumps(result.report, sort_keys=True)

    assert hashlib.sha256(key_1).hexdigest() in rendered
    assert hashlib.sha256(key_2).hexdigest() in rendered
    assert key_1.hex() not in rendered
    assert key_2.hex() not in rendered
    assert key_1.hex() not in repr(result.profile)
    assert key_2.hex() not in repr(result.profile)
    assert result.report["attribution"] == {
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "scope": "component_unpacker_route",
    }
    assert result.report["safety"]["sample_executed"] is False
    assert result.report["safety"]["network_contacted"] is False


def test_corrupted_inner_entry_fails_closed() -> None:
    sample, _stage, _key_1, _key_2 = _fixture()
    damaged = bytearray(sample)
    encrypted_entry = SECTION_RAW_OFFSET + SOURCE_OFFSET + STAGE_ENTRY_OFFSET
    damaged[encrypted_entry] ^= 0x01

    with pytest.raises(native_stage0.NativeStage0NoEvidence, match="妥当な二段RC4"):
        native_stage0.recover_native_stage0(bytes(damaged))


def test_non_x86_or_random_data_is_rejected() -> None:
    with pytest.raises(native_stage0.NativeStage0NoEvidence):
        native_stage0.recover_native_stage0(b"not-a-pe")


def test_20_to_32_byte_runs_yield_only_dword_aligned_20_byte_windows() -> None:
    values = {-0x80 + index: index + 1 for index in range(32)}

    candidates = native_stage0._contiguous_runs(values)

    assert candidates == tuple(
        sorted(
            bytes(range(start + 1, start + 21))
            for start in (0, 4, 8, 12)
        )
    )


def test_candidate_product_is_rejected_before_any_rc4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample, _stage, _key_1, _key_2 = _fixture()
    layout = native_stage0._parse_layout(sample)
    dispatcher_raw, _count, entry, dispatcher = (
        native_stage0._discover_dispatcher(sample, layout)
    )
    monkeypatch.setattr(
        native_stage0,
        "_contiguous_runs",
        lambda _values: tuple(bytes([index + 1]) * 20 for index in range(8)),
    )
    monkeypatch.setattr(
        native_stage0,
        "_key_xor_constant_sets",
        lambda _groups, _dispatcher: ((0x3D, (1, 2, 3, 4, 5, 6)),),
    )
    monkeypatch.setattr(
        native_stage0,
        "rc4",
        lambda _data, _key: pytest.fail("候補積の拒否前にRC4が呼ばれました"),
    )

    with pytest.raises(native_stage0.NativeStage0NoEvidence, match="候補積"):
        native_stage0._candidate_profiles(
            sample,
            layout,
            dispatcher_raw,
            entry,
            dispatcher,
        )


def test_first_rc4_is_cached_and_full_second_stage_is_deferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample, _stage, _key_1, _key_2 = _fixture()
    original_rc4 = native_stage0.rc4
    original_second = native_stage0._decrypt_second_stage
    first_stage_calls = 0
    full_second_stage_calls = 0

    def counted_rc4(data: bytes, key: bytes) -> bytes:
        nonlocal first_stage_calls
        if len(data) == ENCRYPTED_LENGTH:
            first_stage_calls += 1
        return original_rc4(data, key)

    def counted_second(data: bytes, key: bytes, block_size: int) -> bytes:
        nonlocal full_second_stage_calls
        full_second_stage_calls += 1
        return original_second(data, key, block_size)

    monkeypatch.setattr(native_stage0, "rc4", counted_rc4)
    monkeypatch.setattr(native_stage0, "_decrypt_second_stage", counted_second)

    result = native_stage0.recover_native_stage0(sample)

    assert 0 < first_stage_calls < result.report["candidate_evaluation"][
        "attempt_count"
    ]
    assert full_second_stage_calls == 1


def test_importless_i386_detector_is_route_only_and_does_not_decrypt() -> None:
    sample, _stage, _key_1, _key_2 = _fixture()

    result = detector.detect(sample, Path("fixture.exe"))

    campaign = next(
        item
        for item in result["campaigns"]
        if item["campaign_type"] == "formbook_native_importless_i386_route"
    )
    probe = result["observations"]["native_importless_i386_route"]
    assert probe["status"] == "route_candidate"
    assert probe["decryption_attempted"] is False
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["c2_confirmed"] is False
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
    assert detection_supports_family_attribution(result) is False


def test_import_directory_or_non_i386_prevents_native_route() -> None:
    sample, _stage, _key_1, _key_2 = _fixture()
    with_imports = bytearray(sample)
    optional = 0x98
    struct.pack_into("<II", with_imports, optional + 104, SECTION_RVA, 40)
    x64 = bytearray(sample)
    struct.pack_into("<H", x64, 0x84, 0x8664)

    assert detector._probe_importless_i386_pe(bytes(with_imports))["status"] == (
        "not_candidate"
    )
    assert detector._probe_importless_i386_pe(bytes(x64))["status"] == (
        "not_candidate"
    )


def test_importless_stage0_route_precedes_terminal_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stage-0候補を暗号化前の像としてinventoryへ重複走査しない。"""

    sample, _stage, _key_1, _key_2 = _fixture()
    original = facade._extract_native_xloader_inventory
    scanned_sha256: list[str] = []

    def tracked_inventory(candidate: bytes) -> dict[str, object]:
        scanned_sha256.append(hashlib.sha256(candidate).hexdigest())
        return original(candidate)

    monkeypatch.setattr(
        facade,
        "_extract_native_xloader_inventory",
        tracked_inventory,
    )

    result = facade.extract_config(sample)

    assert result["variant"] == "native_x86_two_stage_rc4"
    assert scanned_sha256 == [result["native_stage0"]["analysis_pe_sha256"]]


def test_output_writer_rejects_existing_path_and_input_alias(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    existing = tmp_path / "existing.bin"
    existing.write_bytes(b"existing")

    with pytest.raises(native_stage0.NativeStage0Error, match="既に存在"):
        native_stage0._write_exclusive(existing, b"output", inputs=(source,))
    with pytest.raises(native_stage0.NativeStage0Error, match="同じfile"):
        native_stage0._write_exclusive(source, b"output", inputs=(source,))


@pytest.mark.skipif(
    not os.environ.get("FORMBOOK_NATIVE_STAGE0_TEST_SAMPLE"),
    reason="repo外のFormBook native stage-0実検体が未指定です",
)
def test_private_real_sample_recovers_rotated_selector_and_analysis_pe() -> None:
    """private実検体でselector変更と復元像をhashだけで回帰する。"""

    sample_path = Path(os.environ["FORMBOOK_NATIVE_STAGE0_TEST_SAMPLE"])
    sample = sample_path.read_bytes()

    result = native_stage0.recover_native_stage0(sample)

    assert hashlib.sha256(sample).hexdigest() == (
        "6ce8fef06be0f57c89b07c2ee65f46ff4b4d2e646d5c58943aad55b43b53f91e"
    )
    assert result.profile.xor_selector == 0xB0
    assert result.profile.dispatcher_rva == 0x10F0
    assert result.profile.dispatcher_call_count == 25
    evaluation = result.report["candidate_evaluation"]
    assert 0 < evaluation["attempt_count"] <= native_stage0.MAX_PROFILE_ATTEMPTS
    assert evaluation["accepted_distinct_stage_count"] == 1
    assert evaluation["selected_unique"] is True
    assert hashlib.sha256(result.decrypted_stage).hexdigest() == (
        "c3cb73201ff9fbf90efeb4aae2b5cb04825b775a3802abe8288d9e417916f5f6"
    )
    assert hashlib.sha256(result.analysis_pe).hexdigest() == (
        "99c4fd3405d0eed00ec04ad3cbe336831055ae89337c4b6936f693df36149c6e"
    )
    assert result.report["safety"]["sample_executed"] is False
    assert result.report["safety"]["cpu_emulation_used"] is False
    assert result.report["safety"]["network_contacted"] is False


@pytest.mark.skipif(
    not os.environ.get("FORMBOOK_NATIVE_STAGE0_COHORT_ROOT"),
    reason="repo外のFormBook native stage-0 cohortが未指定です",
)
def test_private_six_sample_cohort_stays_below_handler_budget() -> None:
    """review済み6検体を実行せず、復元hashと30秒予算を回帰する。"""

    pyzipper = pytest.importorskip("pyzipper")
    root = Path(os.environ["FORMBOOK_NATIVE_STAGE0_COHORT_ROOT"])
    expected = {
        "0ccda5fb8da309f4ca1af9510db9bbcbf8d91c6a12758f2ff05bfc885d46e764": "75c8d9e3800b250639998f2c022546f8b6f498fefa7b8e78659be7368853eb40",
        "2a4e92f9ceeafddef77dbdba62c0a9bd2711ce7be586994ba810712067c0e4fa": "7c4866d542ee4ac9e211c0d5e40f6453ebaa3c14ca1a2df6264f8d0ed07681fe",
        "0b81936f0bc1aaf3d55932e910e8a1cdbd80f276e59f80690a80f8f9e6550a93": "5b8711a72c6da9af1d9476b32c253a6245624addbae793f7e8808f9c7d138096",
        "5d010b50c9cfd89d091aa90acf4b1ffc8f1659e89d1993dd54f76498fed3cf67": "37100dbda773ef3df475380fb621005b0b361876c1d92fca5dbbe1222edcbc37",
        "21eed78ef28f13581985a98514ec70fe1d8bfb9dce22900c9cff07796bbf2ade": "9091c0b5b7db31594c533faeda6da52c4725c9bfe7a64c50e94037dbe6297264",
        "04a6e7e0ebdb93b20b3de6905562665d5b884d9a9f45008d9634d506e6fc39b2": "39d7b308f80531ba10a79694fe9f7166d016cb98b113ecae1344d4f71882d5fb",
    }
    for sample_sha256, analysis_sha256 in expected.items():
        archive = root / sample_sha256 / f"{sample_sha256}.zip"
        with pyzipper.AESZipFile(archive) as bundle:
            names = [name for name in bundle.namelist() if not name.endswith("/")]
            assert len(names) == 1
            data = bundle.read(names[0], pwd=b"infected")
        assert hashlib.sha256(data).hexdigest() == sample_sha256
        started = time.perf_counter()
        result = facade.extract_config(data)
        elapsed = time.perf_counter() - started
        assert result["variant"] == "native_x86_two_stage_rc4"
        assert result["native_stage0"]["analysis_pe_sha256"] == analysis_sha256
        assert isinstance(result["supports_family_attribution"], bool)
        assert result["terminal_family_confirmed"] is False
        assert elapsed < 30.0
