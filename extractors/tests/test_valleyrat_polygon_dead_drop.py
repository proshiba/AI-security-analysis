"""ValleyRAT Polygon dead-drop profileの静的復元を合成fixtureで検証する。"""

from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from extractors.valleyrat import extractor
from extractors.valleyrat import polygon_dead_drop as profile

_IMAGE_BASE = 0x180000000
_FILE_ALIGNMENT = 0x200
_SECTION_ALIGNMENT = 0x1000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _pe64(sections: list[tuple[bytes, bytes, int]]) -> bytes:
    """name、content、characteristicsから最小file-layout PE32+を作る。"""

    headers_size = 0x400
    section_rows: list[tuple[bytes, bytes, int, int, int, int]] = []
    raw_offset = headers_size
    virtual_address = 0x1000
    for name, content, characteristics in sections:
        raw_size = _align(len(content), _FILE_ALIGNMENT)
        section_rows.append(
            (name, content, characteristics, raw_offset, virtual_address, raw_size)
        )
        raw_offset += raw_size
        virtual_address += _align(max(1, len(content)), _SECTION_ALIGNMENT)
    image = bytearray(raw_offset)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        0x8664,
        len(section_rows),
        0,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<Q", image, optional + 24, _IMAGE_BASE)
    struct.pack_into(
        "<II", image, optional + 32, _SECTION_ALIGNMENT, _FILE_ALIGNMENT
    )
    struct.pack_into("<I", image, optional + 56, virtual_address)
    struct.pack_into("<I", image, optional + 60, headers_size)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 108, 16)
    table = optional + 0xF0
    for index, row in enumerate(section_rows):
        name, content, characteristics, raw, rva, raw_size = row
        header = table + index * 40
        image[header : header + 8] = name.ljust(8, b"\x00")[:8]
        struct.pack_into("<IIII", image, header + 8, len(content), rva, raw_size, raw)
        struct.pack_into("<I", image, header + 36, characteristics)
        image[raw : raw + len(content)] = content
    return bytes(image)


def _xor_wide(value: str) -> bytes:
    raw = value.encode("utf-16le")
    output = bytearray()
    for offset in range(0, len(raw), 2):
        output.extend((struct.unpack_from("<H", raw, offset)[0] ^ 0x4B).to_bytes(2, "little"))
    return bytes(output) + b"\x00\x00"


def _lea_rip(instruction_rva: int, target_rva: int) -> bytes:
    displacement = target_rva - (instruction_rva + 7)
    return b"\x48\x8d\x05" + struct.pack("<i", displacement)


def _aes_config(key: bytes, iv: bytes) -> bytes:
    clear = (
        "|p1:c2.example|o1:443|t1:1|p2:|o2:|t2:0|p3:|o3:|t3:0|"
        "dd:1|ur:https://update.example/cfg|"
    )[::-1].encode("utf-16le")
    padding = 16 - len(clear) % 16
    padded = clear + bytes([padding]) * padding
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return b"CFG!" + struct.pack("<I", len(clear)) + iv + ciphertext


def _terminal_fixture(
    *,
    omit_abi_signature: bool = False,
    duplicate_contract: bool = False,
    reference_providers: bool = True,
) -> bytes:
    key = bytes(range(1, 17))
    iv = bytes(range(16, 32))
    rdata = bytearray(0x1000)
    cursor = 0

    def put(value: bytes) -> int:
        nonlocal cursor
        offset = cursor
        rdata[offset : offset + len(value)] = value
        cursor = _align(offset + len(value) + 2, 8)
        return 0x2000 + offset

    template_rva = put(profile._JSON_TEMPLATE + b"\x00")
    result_rva = put(profile._RESULT_MARKER + b"\x00")
    selector_rva = put(b"0x12345678\x00")
    put(b"0x" + b"a" * 40 + b"\x00")
    if duplicate_contract:
        put(b"0x" + b"b" * 40 + b"\x00")
    provider_rvas = []
    for host in (
        "polygon-one.example",
        "polygon-two.example",
        "polygon-three.example",
    ):
        provider_rvas.append(put(_xor_wide(host)))
    put(_xor_wide("https://resolver.example/value"))
    put(b"KDBM\x01\x00\x00\x00\x10\x00\x00\x00" + key)
    config_rva = put(_aes_config(key, iv))

    targets = (
        template_rva,
        result_rva,
        selector_rva,
        config_rva,
        config_rva + 4,
        config_rva + 8,
        *(provider_rvas if reference_providers else []),
    )
    code = bytearray()
    for target in targets:
        code.extend(_lea_rip(0x1000 + len(code), target))
    code.extend(b"\x90" * 8)
    signatures = list(profile._ABI_MACHINE_SIGNATURES)
    if omit_abi_signature:
        signatures.pop()
    for signature in signatures:
        code.extend(signature)
        code.extend(b"\x90" * 3)
    code.extend(b"\xC3")
    return _pe64(
        [
            (b".text", bytes(code), 0x60000020),
            (b".rdata", bytes(rdata), 0x40000040),
        ]
    )


def _lz4_literals(value: bytes) -> bytes:
    literal_size = len(value)
    output = bytearray([min(literal_size, 15) << 4])
    if literal_size >= 15:
        remaining = literal_size - 15
        while remaining >= 255:
            output.append(255)
            remaining -= 255
        output.append(remaining)
    output.extend(value)
    return bytes(output)


def _encrypt_xtea_variant(value: bytes, key: bytes) -> bytes:
    words = struct.unpack("<4I", key)
    output = bytearray(value)
    final_sum = (
        profile._XTEA_INITIAL_SUM + 32 * profile._XTEA_DELTA
    ) & 0xFFFFFFFF
    for offset in range(0, len(output), 8):
        left, right = struct.unpack_from("<2I", output, offset)
        total = final_sum
        for _ in range(32):
            left = (
                left
                + (
                    ((words[total & 3] + total) & 0xFFFFFFFF)
                    ^ ((((right >> 9) ^ (right << 13)) + right) & 0xFFFFFFFF)
                )
            ) & 0xFFFFFFFF
            total = (total - profile._XTEA_DELTA) & 0xFFFFFFFF
            right = (
                right
                + (
                    ((words[(total >> 9) & 3] + total) & 0xFFFFFFFF)
                    ^ ((((left >> 9) ^ (left << 13)) + left) & 0xFFFFFFFF)
                )
            ) & 0xFFFFFFFF
        struct.pack_into("<2I", output, offset, left, right)
    return bytes(output)


def _custom_encode(value: bytes) -> bytes:
    assert len(value) % 3 == 0
    output = bytearray()
    for offset in range(0, len(value), 3):
        packed = int.from_bytes(value[offset : offset + 3], "big")
        sextets = (
            (packed >> 18) & 0x3F,
            (packed >> 12) & 0x3F,
            (packed >> 6) & 0x3F,
            packed & 0x3F,
        )
        output.extend(
            (sextets[index] + 0x21) ^ profile._CODEC_XOR[index]
            for index in range(4)
        )
    return bytes(output)


def _outer_fixture(*, flags: int = 0x101) -> bytes:
    child = _terminal_fixture()
    header_offset = 32
    relative = 17
    shellcode = (
        b"\x90" * header_offset
        + b"\x00"
        + struct.pack("<IIII", 0, len(child), len(child), relative)
        + child
    )
    compressed = struct.pack("<I", len(shellcode)) + _lz4_literals(shellcode)
    xor_key = struct.pack("<I", profile._KEY_SEED)
    decrypted = bytes(
        value ^ xor_key[index & 3] for index, value in enumerate(compressed)
    )
    padding = 8 - len(decrypted) % 8
    padded = decrypted + bytes([padding]) * padding
    encrypted = _encrypt_xtea_variant(padded, profile._derived_key())
    trailer = struct.pack("<IHBB", flags, 0x100, 2, 1) + b"\x00\x00\x00\x00"
    record = (
        profile._RECORD_MARKER
        + struct.pack("<H", 1)
        + struct.pack("<I", 7)
        + b"fixture"
        + struct.pack("<I", 0)
        + struct.pack("<I", len(encrypted))
        + encrypted
        + b"\x00\x02"
        + struct.pack("<I", 0)
        + trailer
    )
    prefix_size = (-len(record)) % 3
    encoded = _custom_encode(b"P" * prefix_size + record)
    return _pe64([(b".cdata", encoded + b"\x00" * 64, 0x40000040)])


def _abi_result(value: str) -> str:
    raw = value.encode("utf-8")
    padded = raw + bytes((-len(raw)) % 32)
    return "0x" + f"{32:064x}{len(raw):064x}" + padded.hex()


def test_outer_lineage_recovers_resolver_embedded_c2_and_remote_injection() -> None:
    result = profile.analyze_polygon_dead_drop_lineage(_outer_fixture())

    assert result is not None
    assert result.embedded_endpoints == ("c2.example:443",)
    observation = result.observation
    assert observation["resolver"]["provider_node_count"] == 3
    assert all(
        item["role"] == "resolver_not_c2"
        for item in observation["resolver"]["provider_nodes"]
    )
    assert observation["resolver"]["contract_address"] == "0x" + "a" * 40
    assert observation["resolver"]["function_selector"] == "0x12345678"
    assert observation["resolver"]["request_body"] == {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {"to": "0x" + "a" * 40, "data": "0x12345678"},
            "latest",
        ],
        "id": 1,
    }
    assert observation["resolver"]["fallback_urls"] == []
    assert observation["resolver"]["unreferenced_url_literals"] == [
        {
            "url": "https://resolver.example/value",
            "role": "dormant_literal_not_ioc",
            "code_referenced": False,
            "promoted_to_network_ioc": False,
        }
    ]
    assert observation["execution_mode"]["selected_branch"] == "remote_process_injection"
    assert observation["execution_mode"]["target_process"] == "explorer.exe"
    assert observation["execution_mode"]["injection_api_sequence"] == [
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtResumeThread",
    ]
    assert observation["sample_executed"] is False
    assert observation["network_contacted"] is False


def test_shared_extractor_keeps_rpc_nodes_separate_from_embedded_c2() -> None:
    result = extractor.extract(_outer_fixture(), "synthetic.dll")

    assert result["config"]["variant"] == "polygon_eth_call_dead_drop_terminal"
    assert result["config"]["endpoints"] == ["c2.example:443"]
    assert result["config"]["static_config_recovered"] is True
    assert {
        item["value"]
        for item in result["findings"]
        if item["role"] == "resolver_not_c2" and item["kind"] == "network.domain"
    } == {
        "polygon-one.example",
        "polygon-two.example",
        "polygon-three.example",
    }
    assert "https://resolver.example/value" not in result["config"]["urls"]
    assert all(
        item["value"] != "https://resolver.example/value"
        for item in result["findings"]
    )
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_terminal_rejects_missing_abi_parser_or_ambiguous_contract() -> None:
    assert profile.probe_polygon_dead_drop(
        _terminal_fixture(omit_abi_signature=True)
    )["matched"] is False
    assert profile.probe_polygon_dead_drop(
        _terminal_fixture(duplicate_contract=True)
    )["matched"] is False
    assert profile.probe_polygon_dead_drop(
        _terminal_fixture(reference_providers=False)
    )["matched"] is False


def test_corrupt_outer_and_size_limit_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    corrupted = bytearray(_outer_fixture())
    image = profile._load_pe(bytes(corrupted))
    assert image is not None
    try:
        raw = int(image.sections[0].PointerToRawData)
    finally:
        image.close()
    corrupted[raw + 80] ^= 0x80
    assert profile.analyze_polygon_dead_drop_lineage(bytes(corrupted)) is None

    monkeypatch.setattr(profile, "MAXIMUM_INPUT_SIZE", 128)
    assert profile.analyze_polygon_dead_drop_lineage(b"MZ" + bytes(127)) is None


def test_abi_dynamic_string_enforces_offset_length_padding_and_boundaries() -> None:
    assert profile.decode_abi_dynamic_string(_abi_result("node.example:443")) == "node.example:443"
    assert profile.decode_abi_dynamic_string("0x" + f"{64:064x}{1:064x}" + "41" + "00" * 31) is None
    assert profile.decode_abi_dynamic_string(_abi_result("A" * 128)) is None
    valid = _abi_result("ok")
    assert profile.decode_abi_dynamic_string(valid[:-2] + "01") is None
    assert profile.decode_abi_dynamic_string("0xzz") is None


def test_trailer_boolean_selects_alternate_in_process_branch() -> None:
    result = profile.analyze_polygon_dead_drop_lineage(_outer_fixture(flags=0x001))

    assert result is not None
    execution = result.observation["execution_mode"]
    assert execution["worker_remote_injection_flag"] is False
    assert execution["selected_branch"] == "in_process_loader"
    assert execution["alternate_branch"] == "remote_process_injection"
    assert execution["target_process"] is None
