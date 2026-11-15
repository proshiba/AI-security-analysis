"""Salat設定の純粋な復号・認証・境界とwrapperを無害な合成値で検証する。"""

from __future__ import annotations

import importlib
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FRAMEWORK = Path(__file__).resolve().parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

profile = importlib.import_module("malware.salatstealer.static_profile")
detector = importlib.import_module("malware.salatstealer.detect")
extractor = importlib.import_module("malware.salatstealer.extract_config")


def _rol(value: int, shift: int) -> int:
    shift &= 31
    return ((value << shift) | (value >> ((32 - shift) & 31))) & 0xFFFFFFFF


def _word_table(data: bytes) -> bytes:
    assert 1 <= len(data) <= 512
    padded = data.rjust(512, b"\0")
    words = [len(data) ^ 0xA5A5A5A5]
    for index in range(128):
        value = int.from_bytes(padded[index * 4:index * 4 + 4], "big")
        words.append(_rol(value ^ (index * 4) ^ 0x9E3779B9, index * 4))
    return struct.pack("<129I", *words)


@pytest.mark.parametrize("size", [1, 31, 128, 511, 512])
def test_word_table_roundtrip(size: int) -> None:
    value = bytes(index % 251 for index in range(size))
    assert profile.decode_word_table(_word_table(value)) == value


@pytest.mark.parametrize("raw", [b"", b"x" * 515, b"x" * 517, struct.pack("<129I", *([0xA5A5A5A5] + [0] * 128))])
def test_word_table_rejects_size_or_zero_length(raw: bytes) -> None:
    with pytest.raises(profile.ProfileError):
        profile.decode_word_table(raw)


def test_gcm_requires_authentication_and_bounds() -> None:
    key = b"synthetic-key-01"
    nonce = b"testnonce123"
    plaintext = b"non-operational fixture"
    ciphertext = nonce + AESGCM(key).encrypt(nonce, plaintext, None)
    assert profile.decrypt_gcm(ciphertext, key) == plaintext
    broken = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with pytest.raises(profile.ProfileError, match="authentication"):
        profile.decrypt_gcm(broken, key)
    for value in (b"", b"x" * 27, b"x" * 4097):
        with pytest.raises(profile.ProfileError, match="size"):
            profile.decrypt_gcm(value, key)


class _TableImage:
    def __init__(self, table: bytes):
        self.table = table

    def bytes_at(self, _va: int, size: int) -> bytes:
        assert size == 516
        return self.table


def _encoded_endpoint(endpoint: str) -> tuple[_TableImage, int, bytes, bytes]:
    key = b"synthetic-key-01"
    xor_key = b"synthetic-xor-key"
    # 合成算術fixture。外部検体や実運用RSA秘密鍵を使わない。
    modulus = 3 ** 2584
    private_exponent = pow(65537, -1, 2 * 3 ** 2583)
    for counter in range(10):
        nonce = counter.to_bytes(12, "big")
        ciphertext = nonce + AESGCM(key).encrypt(nonce, endpoint.encode("ascii"), None)
        wanted = bytes(value ^ xor_key[index % len(xor_key)] for index, value in enumerate(ciphertext.hex().encode("ascii")))
        inverse = bytes(value if index == 0 else value ^ wanted[index - 1] for index, value in enumerate(wanted))
        message = int.from_bytes(inverse.hex().encode("ascii"), "big")
        if message % 3:
            encrypted = pow(message, private_exponent, modulus)
            table = _word_table(encrypted.to_bytes((encrypted.bit_length() + 7) // 8, "big"))
            return _TableImage(table), modulus, key, xor_key
    raise AssertionError("合成fixtureの算術条件を満たせません")


def test_full_endpoint_crypto_chain_with_synthetic_value() -> None:
    image, modulus, key, xor_key = _encoded_endpoint("https://example.invalid/test/")
    assert profile._decode_endpoint(image, 123, modulus, key, xor_key) == "https://example.invalid/test/"
    with pytest.raises(profile.ProfileError):
        profile._decode_endpoint(image, 123, modulus, key, b"different-xor-key")
    with pytest.raises(profile.ProfileError):
        profile._decode_endpoint(image, 123, modulus, b"changed-key-00001", xor_key)


@pytest.mark.parametrize("endpoint", [
    "ftp://example.invalid/test/", "https://name:secret@example.invalid/test/",
    "https://example.invalid/test/?token=hidden", "https://example.invalid/test/#fragment",
    "https://example.invalid:99999/test/",
])
def test_endpoint_syntax_and_sensitive_fields_are_rejected(endpoint: str) -> None:
    image, modulus, key, xor_key = _encoded_endpoint(endpoint)
    with pytest.raises(profile.ProfileError):
        profile._decode_endpoint(image, 123, modulus, key, xor_key)


@pytest.mark.parametrize("data", [b"", b"MZ", b"Go build ID: main.getEp main.Steal", b"MZ" + b"\0" * 1024])
def test_marker_only_and_invalid_formats_are_not_family_confirmation(data: bytes) -> None:
    assert detector.detect(data)["matched"] is False
    with pytest.raises(ValueError):
        extractor.extract_config(data)


def test_excessive_input_is_rejected() -> None:
    with pytest.raises(profile.ProfileError, match="size"):
        profile.recover(b"MZ" + b"\0" * profile.MAX_INPUT_BYTES)


def test_extractor_preserves_endpoint_role_and_no_key_material(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extractor, "recover", lambda _data: {
        "profile_id": profile.PROFILE_ID,
        "sample_sha256": "a" * 64,
        "endpoints": [{"role": "primary", "url": "https://example.invalid/test/"}, {"role": "backup", "url": "https://backup.invalid/test/"}],
        "structure": {"format": "PE32", "architecture": "x86"},
        "evidence": {"raw_key_material_included": False},
    })
    result = extractor.extract_config(b"synthetic")
    assert result["static_config_recovered"] is True
    assert [item["configuration_role"] for item in result["config_endpoints"]] == ["primary", "backup"]
    assert all(item["port"] == 443 for item in result["config_endpoints"])
    assert [item["array_index"] for item in result["config_endpoints"]] == [0, 0]
    assert [item["configuration_order"] for item in result["config_endpoints"]] == [0, 1]
    assert result["safety"]["raw_key_material_included"] is False
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False


def _synthetic_go32_image() -> tuple[bytes, SimpleNamespace, dict[str, int]]:
    """RETだけの無害な関数と最小pclntabを持つfile-backed imageを作る。"""
    names = list(profile.REQUIRED_FUNCTIONS)
    name_bytes = b"".join(name.encode() + b"\0" for name in names)
    data = bytearray(0x5000)
    data[:2] = b"MZ"
    start = 0x2100
    name_offset = 64
    cu = (name_offset + len(name_bytes) + 15) & ~15
    table = cu + 64
    data[start:start + 8] = profile.PCLNTAB_MAGIC
    struct.pack_into("<8I", data, start + 8, len(names), 1, 0x401000, name_offset, cu, cu + 16, cu + 32, table)
    data[start + name_offset:start + name_offset + len(name_bytes)] = name_bytes
    records = table + len(names) * 8 + 4
    cursor = 0
    for index, name in enumerate(names):
        relative_record = records - table + index * 8
        struct.pack_into("<II", data, start + table + index * 8, index, relative_record)
        struct.pack_into("<Ii", data, start + records + index * 8, index, cursor)
        cursor += len(name) + 1
        data[0x1000 + index] = 0xC3
    struct.pack_into("<I", data, start + table + len(names) * 8, len(names))
    sections = [
        SimpleNamespace(VirtualAddress=0x1000, PointerToRawData=0x1000, SizeOfRawData=0x1000, Characteristics=0x60000020),
        SimpleNamespace(VirtualAddress=0x2000, PointerToRawData=0x2000, SizeOfRawData=0x3000, Characteristics=0x40000040),
    ]
    pe = SimpleNamespace(FILE_HEADER=SimpleNamespace(Machine=0x14C), OPTIONAL_HEADER=SimpleNamespace(Magic=0x10B, ImageBase=0x400000), sections=sections)
    return bytes(data), pe, {"header": start, "record": start + records, "table": start + table}


def test_go32_function_inventory_accepts_only_consistent_file_backed_table(monkeypatch: pytest.MonkeyPatch) -> None:
    data, pe, _ = _synthetic_go32_image()
    monkeypatch.setattr(profile.pefile, "PE", lambda **_kwargs: pe)
    image = profile.Image(data)
    assert set(image.functions) == set(profile.REQUIRED_FUNCTIONS)
    assert all(function.size == 1 for function in image.functions.values())
    assert image.bytes_at(image.functions["main.getEp"].va, 1) == b"\xc3"
    with pytest.raises(profile.ProfileError, match="section"):
        image.bytes_at(0x400000, 1)
    with pytest.raises(profile.ProfileError, match="bounds"):
        image.bytes_at(0x401000, profile.MAX_INPUT_BYTES + 1)


@pytest.mark.parametrize("mutation", ["duplicate_magic", "function_limit", "negative_name", "record_before_table_end", "non_executable"])
def test_go32_inventory_rejects_ambiguity_corruption_and_non_code(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    raw, pe, offsets = _synthetic_go32_image()
    data = bytearray(raw)
    if mutation == "duplicate_magic":
        data[0x2400:0x2408] = profile.PCLNTAB_MAGIC
    elif mutation == "function_limit":
        struct.pack_into("<I", data, offsets["header"] + 8, profile.MAX_FUNCTIONS + 1)
    elif mutation == "negative_name":
        struct.pack_into("<i", data, offsets["record"] + 4, -1)
    elif mutation == "record_before_table_end":
        struct.pack_into("<I", data, offsets["table"] + 4, 8)
    else:
        pe.sections[0].Characteristics = 0x40000040
    monkeypatch.setattr(profile.pefile, "PE", lambda **_kwargs: pe)
    with pytest.raises(profile.ProfileError):
        profile.Image(bytes(data))


def _instruction(mnemonic: str, operands: str, address: int, *decoded) -> SimpleNamespace:
    return SimpleNamespace(mnemonic=mnemonic, op_str=operands, address=address, operands=list(decoded))


def _immediate(value: int) -> SimpleNamespace:
    return SimpleNamespace(type=profile.X86_OP_IMM, imm=value)


def _memory(address: int) -> SimpleNamespace:
    return SimpleNamespace(type=profile.X86_OP_MEM, mem=SimpleNamespace(base=0, index=0, disp=address))


def test_operand_linked_cumulative_loop_requires_exact_buffer_index_and_backedge() -> None:
    instructions = [_instruction(mnemonic, operands, 0x1000 + index) for index, (mnemonic, operands) in enumerate(profile.CUMULATIVE_XOR_LOOP)]
    instructions.append(_instruction("jg", "0x1000", 0x1008, _immediate(0x1000)))
    profile._validate_cumulative_loop(instructions)
    for index, changed in ((0, "ebx, byte ptr [edx + ebx]"), (1, "ebp, byte ptr [edx + ecx + 1]"), (4, "byte ptr [edx + ebx], al")):
        broken = list(instructions)
        broken[index] = _instruction(broken[index].mnemonic, changed, broken[index].address)
        with pytest.raises(profile.ProfileError, match="operand_shape"):
            profile._validate_cumulative_loop(broken)
    broken = list(instructions)
    broken[-1] = _instruction("jg", "0x1001", 0x1008, _immediate(0x1001))
    with pytest.raises(profile.ProfileError, match="branch"):
        profile._validate_cumulative_loop(broken)


def test_periodic_xor_loop_requires_key_pointer_length_and_hwid_store_binding() -> None:
    text = [
        ("mov", "edi, dword ptr [0x5000]"),
        ("movzx", "edi, byte ptr [edx + edi]"), ("xor", "edi, ebp"),
        ("mov", "ebp, dword ptr [esp + 0x50]"), ("xchg", "edi, eax"),
        ("mov", "byte ptr [ebx + ebp], al"), ("xchg", "edi, eax"),
        ("lea", "eax, [ebp + 1]"), ("mov", "edx, esi"), ("cmp", "edx, eax"),
        ("jle", "0x2000"), ("mov", "ecx, dword ptr [0x5004]"),
        ("movzx", "ebp, byte ptr [eax + ebx]"), ("test", "ecx, ecx"),
        ("je", "0x3000"), ("mov", "dword ptr [esp + 0x50], eax"),
        ("mov", "esi, edx"), ("cdq", ""), ("idiv", "ecx"),
        ("cmp", "ecx, edx"), ("ja", "0x1000"), ("jmp", "0x3000"),
    ]
    instructions = [_instruction(mnemonic, operands, 0x1000 + index) for index, (mnemonic, operands) in enumerate(text)]
    instructions[0].operands = [SimpleNamespace(type=profile.X86_OP_REG), _memory(0x5000)]
    instructions[11].operands = [SimpleNamespace(type=profile.X86_OP_REG), _memory(0x5004)]
    for index, target in ((10, 0x2000), (14, 0x3000), (20, 0x1000)):
        instructions[index].operands = [_immediate(target)]
    instructions.extend([_instruction("ret", "", 0x2000), _instruction("call", "panic", 0x3000)])
    writes = [_instruction("mov", f"dword ptr [{hex(address)}], {register}", index, _memory(address), SimpleNamespace(type=profile.X86_OP_REG)) for index, (address, register) in enumerate(((0x5000, "edx"), (0x5004, "eax"), (0x5008, "ecx")))]
    profile._validate_periodic_loop(instructions, writes)
    broken = list(instructions)
    broken[2] = _instruction("add", "edi, ebp", broken[2].address)
    with pytest.raises(profile.ProfileError, match="periodic"):
        profile._validate_periodic_loop(broken, writes)
    with pytest.raises(profile.ProfileError, match="periodic"):
        profile._validate_periodic_loop(instructions, writes[:-1])
    broken = list(instructions)
    broken[11] = _instruction("mov", "eax, dword ptr [0x5004]", broken[11].address, SimpleNamespace(type=profile.X86_OP_REG), _memory(0x5004))
    with pytest.raises(profile.ProfileError, match="periodic"):
        profile._validate_periodic_loop(broken, writes)


def _rsa_exponent_instructions(exponent: int, pointer_register: int = 0x9C) -> tuple[list, SimpleNamespace]:
    import capstone

    start = 0x10000
    code = bytearray(b"\xe8\x00\x00\x00\x00")
    code += b"\xc7\x84\x24" + struct.pack("<II", 0x40, exponent)
    code += b"\xba\x01\x00\x00\x00"
    code += b"\x8d\x9c\x24" + struct.pack("<I", 0x40)
    code += b"\x89" + bytes([pointer_register]) + b"\x24" + struct.pack("<I", 0x104)
    code += b"\x8d\x84\x24" + struct.pack("<I", 0x100)
    code += b"\x89\x44\x24\x08"
    call_address = start + len(code)
    code += b"\xe8" + struct.pack("<i", 0x20000 - call_address - 5)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(bytes(code), start))
    return instructions, SimpleNamespace(by_va={0x20000: "math/big.(*Int).exp"})


def test_rsa_exponent_is_bound_to_bigint_limb_and_call_argument() -> None:
    instructions, image = _rsa_exponent_instructions(65537)
    profile._validate_rsa_exponents(image, instructions, [(0, 123)])
    broken, image = _rsa_exponent_instructions(65539)
    with pytest.raises(profile.ProfileError, match="65537"):
        profile._validate_rsa_exponents(image, broken, [(0, 123)])
    broken, image = _rsa_exponent_instructions(65537, pointer_register=0x8C)
    with pytest.raises(profile.ProfileError, match="limb_pointer"):
        profile._validate_rsa_exponents(image, broken, [(0, 123)])
