"""Polygon ``eth_call`` dead-drop型terminalを実行せずに復元する。

このmoduleは、固有hash、file名、既知IOCへ依存しない。外層 ``.cdata`` の
codec、record境界、暗号／圧縮、shellcode内PE境界、terminalのJSON-RPC
producer／ABI consumerを同じlineageで検証する。RPC nodeは共有resolverで
ありC2ではないため、埋込み設定から復元したC2と必ず分離して返す。
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_INVALID,
    X86_REG_RIP,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAXIMUM_INPUT_SIZE = 64 * 1024 * 1024
MAXIMUM_SECTION_SIZE = 32 * 1024 * 1024
MAXIMUM_DECODED_CONTAINER_SIZE = 32 * 1024 * 1024
MAXIMUM_TERMINAL_SIZE = 16 * 1024 * 1024
MAXIMUM_RECORD_NAME_SIZE = 255
MAXIMUM_PROVIDER_COUNT = 3
MAXIMUM_FALLBACK_URLS = 4
MAXIMUM_ABI_STRING_SIZE = 127

_SECTION_NAME = b".cdata"
_CODEC_XOR = (0xDA, 0x32, 0x9B, 0xE5)
_RECORD_MARKER = bytes.fromhex("856f8a69")
_KEY_SEED = 0x621CB55D
_XTEA_INITIAL_SUM = 0xF68880E0
_XTEA_DELTA = 0x4BBBF9
_WIDE_XOR = 0x4B
_JSON_TEMPLATE = (
    b'{"jsonrpc":"2.0","method":"eth_call","params":'
    b'[{"to":"%s","data":"%s"},"latest"],"id":1}'
)
_RESULT_MARKER = b'"result":"'
_SELECTOR_RE = re.compile(rb"0x[0-9A-Fa-f]{8}\x00")
_CONTRACT_RE = re.compile(rb"0x[0-9A-Fa-f]{40}")
_HOST_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", re.IGNORECASE)
_URL_RE = re.compile(
    r"https?://(?:[a-z0-9-]+\.)+[a-z]{2,63}(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9._~!$&'()*+,;=:@%/?-]*)?",
    re.IGNORECASE,
)
_ABI_MACHINE_SIGNATURES = (
    bytes.fromhex("4981f880000000"),  # hex長がABI head 64 bytes以上
    bytes.fromhex("4d8d4a79"),  # 第2word末尾のlength 8 hex桁
    bytes.fromhex("4983ea80"),  # dynamic dataは128 hex桁後
    bytes.fromhex("83f87e"),  # 1..127 bytesだけを許可
    bytes.fromhex("41c6043b00"),  # 復号結果をNUL終端
)


@dataclass(frozen=True)
class PolygonDeadDropLineage:
    """公開可能な観測とfollow-on専用terminal PEを保持する。"""

    observation: dict[str, object]
    terminal_component: bytes
    embedded_endpoints: tuple[str, ...]
    embedded_urls: tuple[str, ...]


@dataclass(frozen=True)
class _Trailer:
    flags: int
    exec_flags: int
    mode: int
    option_length: int
    option: bytes

    @property
    def remote_injection_selected(self) -> bool:
        # parserはflagsの各byteを8-byte boolean tableへ展開する。
        # workerが読む2番目のbooleanはflags bits 8..15に対応する。
        return bool((self.flags >> 8) & 0xFF)


@dataclass(frozen=True)
class _Record:
    encrypted: bytes
    key_material: bytes
    trailer: _Trailer


@dataclass(frozen=True)
class _OuterRecovery:
    terminal_shellcode: bytes
    terminal_pe: bytes
    fragment_count: int
    trailer: _Trailer


@dataclass(frozen=True)
class _TerminalProfile:
    contract: str
    selector: str
    provider_hosts: tuple[str, ...]
    fallback_urls: tuple[str, ...]
    unreferenced_url_literals: tuple[str, ...]
    embedded_endpoints: tuple[str, ...]
    embedded_urls: tuple[str, ...]


def _load_pe(data: bytes) -> pefile.PE | None:
    if not isinstance(data, bytes) or not data.startswith(b"MZ"):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (OSError, pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= len(image.sections) <= 96:
        image.close()
        return None
    return image


def _read_va(image: pefile.PE, data: bytes, address: int, size: int) -> bytes | None:
    if size < 0 or size > MAXIMUM_SECTION_SIZE:
        return None
    try:
        rva = address - int(image.OPTIONAL_HEADER.ImageBase)
        offset = int(image.get_offset_from_rva(rva))
    except (AttributeError, pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return None
    if not 0 <= offset <= len(data) - size:
        return None
    return data[offset : offset + size]


def _valid_quad(value: bytes) -> bool:
    return len(value) == 4 and all(
        0 <= ((value[index] ^ _CODEC_XOR[index]) - 0x21) <= 0x3F
        for index in range(4)
    )


def _encoded_fragments(section: bytes, phase: int) -> tuple[bytes, ...]:
    fragments: list[bytes] = []
    start: int | None = None
    offset = phase
    while offset + 4 <= len(section):
        if _valid_quad(section[offset : offset + 4]):
            start = offset if start is None else start
        elif start is not None:
            if offset - start >= 64:
                fragments.append(section[start:offset])
            start = None
        offset += 4
    if start is not None and offset - start >= 64:
        fragments.append(section[start:offset])
    return tuple(fragments)


def _decode_codec(encoded: bytes) -> bytes | None:
    if not encoded or len(encoded) % 4 or len(encoded) > MAXIMUM_DECODED_CONTAINER_SIZE * 2:
        return None
    output = bytearray()
    for offset in range(0, len(encoded), 4):
        values = tuple(
            (encoded[offset + index] ^ _CODEC_XOR[index]) - 0x21
            for index in range(4)
        )
        if any(value < 0 or value > 0x3F for value in values):
            return None
        packed = (
            (values[0] << 18)
            | (values[1] << 12)
            | (values[2] << 6)
            | values[3]
        )
        output.extend(packed.to_bytes(3, "big"))
        if len(output) > MAXIMUM_DECODED_CONTAINER_SIZE:
            return None
    return bytes(output)


def _u32(data: bytes, offset: int) -> tuple[int, int] | None:
    if not 0 <= offset <= len(data) - 4:
        return None
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def _bounded_field(
    data: bytes,
    offset: int,
    *,
    maximum: int,
) -> tuple[bytes, int] | None:
    length_item = _u32(data, offset)
    if length_item is None:
        return None
    length, offset = length_item
    if length > maximum or not 0 <= offset <= len(data) - length:
        return None
    return data[offset : offset + length], offset + length


def _parse_record(data: bytes, marker: int) -> _Record | None:
    offset = marker + len(_RECORD_MARKER)
    if not 0 <= offset <= len(data) - 2:
        return None
    version = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if version != 1:
        return None
    name_item = _bounded_field(data, offset, maximum=MAXIMUM_RECORD_NAME_SIZE)
    if name_item is None:
        return None
    name, offset = name_item
    if not name or any(value < 0x20 or value > 0x7E for value in name):
        return None
    first_item = _bounded_field(data, offset, maximum=MAXIMUM_TERMINAL_SIZE)
    if first_item is None:
        return None
    first, offset = first_item
    encrypted_item = _bounded_field(data, offset, maximum=MAXIMUM_TERMINAL_SIZE)
    if encrypted_item is None:
        return None
    encrypted, offset = encrypted_item
    if (
        first
        or not encrypted
        or len(encrypted) % 8
        or offset > len(data) - 2
        or data[offset] != 0
        or data[offset + 1] != 2
    ):
        return None
    offset += 2
    key_item = _bounded_field(data, offset, maximum=32)
    if key_item is None:
        return None
    key_material, offset = key_item
    if len(key_material) not in {0, 16} or len(data) - offset != 12:
        return None
    flags, exec_flags, mode, option_length = struct.unpack_from("<IHBB", data, offset)
    option = data[offset + 8 : offset + 12]
    if option_length > len(option):
        return None
    return _Record(
        encrypted=encrypted,
        key_material=key_material,
        trailer=_Trailer(flags, exec_flags, mode, option_length, option[:option_length]),
    )


def _unique_record(data: bytes) -> _Record | None:
    records: list[_Record] = []
    offset = 0
    while True:
        marker = data.find(_RECORD_MARKER, offset)
        if marker < 0:
            break
        record = _parse_record(data, marker)
        if record is not None:
            records.append(record)
        offset = marker + 1
    return records[0] if len(records) == 1 else None


def _derived_key() -> bytes:
    seed = struct.pack("<I", _KEY_SEED)
    state = 0x87
    output = bytearray()
    for index in range(16):
        state = (state * 0x6D + 0x4F) & 0xFF
        output.append(state ^ index ^ seed[index & 3] ^ 0x87)
    return bytes(output)


def _decrypt_xtea_variant(value: bytes, key: bytes) -> bytes | None:
    if not value or len(value) % 8 or len(key) != 16:
        return None
    words = struct.unpack("<4I", key)
    output = bytearray(value)
    for offset in range(0, len(output), 8):
        left, right = struct.unpack_from("<2I", output, offset)
        total = _XTEA_INITIAL_SUM
        for _ in range(32):
            right = (
                right
                - (
                    ((words[(total >> 9) & 3] + total) & 0xFFFFFFFF)
                    ^ ((((left >> 9) ^ (left << 13)) + left) & 0xFFFFFFFF)
                )
            ) & 0xFFFFFFFF
            total = (total + _XTEA_DELTA) & 0xFFFFFFFF
            left = (
                left
                - (
                    ((words[total & 3] + total) & 0xFFFFFFFF)
                    ^ ((((right >> 9) ^ (right << 13)) + right) & 0xFFFFFFFF)
                )
            ) & 0xFFFFFFFF
        struct.pack_into("<2I", output, offset, left, right)
    padding = output[-1]
    if not 1 <= padding <= 8 or output[-padding:] != bytes([padding]) * padding:
        return None
    return bytes(output[:-padding])


def _xor_stage(value: bytes) -> bytes:
    key = struct.pack("<I", _KEY_SEED)
    return bytes(item ^ key[index & 3] for index, item in enumerate(value))


def _lz4_raw(value: bytes, expected_size: int) -> bytes | None:
    if not 1 <= expected_size <= MAXIMUM_TERMINAL_SIZE:
        return None
    source = 0
    output = bytearray()
    while source < len(value):
        token = value[source]
        source += 1
        literal_size = token >> 4
        if literal_size == 0xF:
            while True:
                if source >= len(value):
                    return None
                extra = value[source]
                source += 1
                literal_size += extra
                if extra != 0xFF:
                    break
        if source + literal_size > len(value) or len(output) + literal_size > expected_size:
            return None
        output.extend(value[source : source + literal_size])
        source += literal_size
        if source == len(value):
            break
        if source + 2 > len(value):
            return None
        distance = struct.unpack_from("<H", value, source)[0]
        source += 2
        if distance == 0 or distance > len(output):
            return None
        match_size = token & 0xF
        if match_size == 0xF:
            while True:
                if source >= len(value):
                    return None
                extra = value[source]
                source += 1
                match_size += extra
                if extra != 0xFF:
                    break
        match_size += 4
        if len(output) + match_size > expected_size:
            return None
        for _ in range(match_size):
            output.append(output[-distance])
    return bytes(output) if len(output) == expected_size else None


def _valid_pe(value: bytes) -> bool:
    image = _load_pe(value)
    if image is None:
        return False
    try:
        return (
            int(image.FILE_HEADER.Machine) == 0x8664
            and int(image.OPTIONAL_HEADER.Magic) == 0x20B
            and int(image.OPTIONAL_HEADER.SizeOfHeaders) <= len(value)
        )
    finally:
        image.close()


def _embedded_pe(shellcode: bytes) -> bytes | None:
    candidates: list[bytes] = []
    for offset in range(max(0, len(shellcode) - 17)):
        if shellcode[offset] != 0:
            continue
        decoder_offset, unpacked_size, stored_size, relative = struct.unpack_from(
            "<4I", shellcode, offset + 1
        )
        child_offset = offset + relative
        child_end = child_offset + stored_size
        if (
            decoder_offset != 0
            or not 1 <= stored_size <= MAXIMUM_TERMINAL_SIZE
            or unpacked_size != stored_size
            or relative < 17
            or child_end != len(shellcode)
            or not 0 <= child_offset <= len(shellcode) - stored_size
        ):
            continue
        child = shellcode[child_offset:child_end]
        if _valid_pe(child):
            candidates.append(child)
    unique = {candidate for candidate in candidates}
    return next(iter(unique)) if len(unique) == 1 else None


def _recover_outer(data: bytes) -> _OuterRecovery | None:
    image = _load_pe(data)
    if image is None:
        return None
    try:
        sections = [
            bytes(section.get_data())
            for section in image.sections
            if bytes(section.Name).rstrip(b"\x00") == _SECTION_NAME
            and 0 < int(section.SizeOfRawData) <= MAXIMUM_SECTION_SIZE
        ]
    finally:
        image.close()
    if len(sections) != 1:
        return None
    recoveries: list[_OuterRecovery] = []
    for phase in range(4):
        fragments = _encoded_fragments(sections[0], phase)
        if not fragments or len(fragments) > 128:
            continue
        decoded = _decode_codec(b"".join(fragments))
        record = _unique_record(decoded) if decoded is not None else None
        if record is None:
            continue
        decrypted = _decrypt_xtea_variant(
            record.encrypted,
            record.key_material or _derived_key(),
        )
        if decrypted is None:
            continue
        compressed = _xor_stage(decrypted)
        if len(compressed) < 5:
            continue
        expected_size = struct.unpack_from("<I", compressed)[0]
        shellcode = _lz4_raw(compressed[4:], expected_size)
        child = _embedded_pe(shellcode) if shellcode is not None else None
        if shellcode is not None and child is not None:
            recoveries.append(
                _OuterRecovery(
                    terminal_shellcode=shellcode,
                    terminal_pe=child,
                    fragment_count=len(fragments),
                    trailer=record.trailer,
                )
            )
    unique = {item.terminal_pe: item for item in recoveries}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _disassemble(image: pefile.PE) -> tuple[tuple[object, ...], ...] | None:
    if int(image.FILE_HEADER.Machine) != 0x8664:
        return None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    groups: list[tuple[object, ...]] = []
    count = 0
    try:
        for section in image.sections:
            if not int(section.Characteristics) & 0x20000000:
                continue
            raw = bytes(section.get_data())
            if len(raw) > MAXIMUM_SECTION_SIZE:
                return None
            address = int(image.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
            instructions = tuple(decoder.disasm(raw, address))
            count += len(instructions)
            if count > 250_000:
                return None
            groups.append(instructions)
    except (CsError, AttributeError, TypeError, ValueError, OverflowError):
        return None
    return tuple(groups)


def _rip_targets(groups: tuple[tuple[object, ...], ...]) -> set[int]:
    targets: set[int] = set()
    for instructions in groups:
        for instruction in instructions:
            for operand in instruction.operands:
                if (
                    operand.type == X86_OP_MEM
                    and operand.mem.base == X86_REG_RIP
                    and operand.mem.index == X86_REG_INVALID
                ):
                    targets.add(instruction.address + instruction.size + operand.mem.disp)
    return targets


def _canonical_register(instruction: object, register: int) -> str:
    name = str(instruction.reg_name(register)).casefold()
    aliases = {
        "al": "rax",
        "ax": "rax",
        "eax": "rax",
        "cl": "rcx",
        "cx": "rcx",
        "ecx": "rcx",
        "r9b": "r9",
        "r9w": "r9",
        "r9d": "r9",
    }
    return aliases.get(name, name)


def _constructed_contracts(
    image: pefile.PE,
    data: bytes,
    groups: tuple[tuple[object, ...], ...],
) -> set[str]:
    writes: dict[int, bytes] = {}
    tails: set[bytes] = set()
    for instructions in groups:
        xmm: dict[str, bytes] = {}
        pointers: dict[str, tuple[int, int]] = {}
        for index, instruction in enumerate(instructions):
            operands = instruction.operands
            mnemonic = instruction.mnemonic.casefold()
            if mnemonic == "ret":
                xmm.clear()
                pointers.clear()
                continue
            if mnemonic == "lea" and len(operands) == 2 and operands[0].type == X86_OP_REG:
                source = operands[1]
                name = _canonical_register(instruction, operands[0].reg)
                if (
                    source.type == X86_OP_MEM
                    and source.mem.base == X86_REG_RIP
                    and source.mem.index == X86_REG_INVALID
                ):
                    pointers[name] = (
                        instruction.address + instruction.size + source.mem.disp,
                        index,
                    )
                else:
                    pointers.pop(name, None)
            if mnemonic in {"movdqu", "movups"} and len(operands) == 2:
                destination, source = operands
                if destination.type == X86_OP_REG and source.type == X86_OP_MEM:
                    if source.mem.base == X86_REG_RIP and source.mem.index == X86_REG_INVALID:
                        raw = _read_va(
                            image,
                            data,
                            instruction.address + instruction.size + source.mem.disp,
                            16,
                        )
                        if raw is not None:
                            xmm[_canonical_register(instruction, destination.reg)] = raw
                elif (
                    destination.type == X86_OP_MEM
                    and source.type == X86_OP_REG
                    and destination.mem.base == X86_REG_RIP
                    and destination.mem.index == X86_REG_INVALID
                ):
                    raw = xmm.get(_canonical_register(instruction, source.reg))
                    if raw is not None:
                        writes[
                            instruction.address
                            + instruction.size
                            + destination.mem.disp
                        ] = raw
            elif mnemonic == "pxor" and len(operands) == 2:
                destination, source = operands
                if (
                    destination.type == X86_OP_REG
                    and source.type == X86_OP_MEM
                    and source.mem.base == X86_REG_RIP
                    and source.mem.index == X86_REG_INVALID
                ):
                    name = _canonical_register(instruction, destination.reg)
                    left = xmm.get(name)
                    right = _read_va(
                        image,
                        data,
                        instruction.address + instruction.size + source.mem.disp,
                        16,
                    )
                    if left is not None and right is not None:
                        xmm[name] = bytes(a ^ b for a, b in zip(left, right, strict=True))
            if mnemonic != "movzx" or len(operands) != 2 or operands[1].type != X86_OP_MEM:
                continue
            memory = operands[1].mem
            source_pointer: tuple[int, int] | None = None
            for register in (memory.base, memory.index):
                if register != X86_REG_INVALID:
                    supplied = pointers.get(_canonical_register(instruction, register))
                    if supplied is not None and index - supplied[1] <= 32:
                        source_pointer = supplied
                        break
            if source_pointer is None:
                continue
            xor_key: int | None = None
            for following in instructions[index + 1 : index + 6]:
                if (
                    following.mnemonic.casefold() == "xor"
                    and len(following.operands) == 2
                    and following.operands[0].type == X86_OP_REG
                    and following.operands[1].type == X86_OP_IMM
                    and _canonical_register(following, following.operands[0].reg) == "rax"
                ):
                    xor_key = int(following.operands[1].imm) & 0xFF
                    break
            if xor_key is None:
                continue
            raw = _read_va(image, data, source_pointer[0] + int(memory.disp), 10)
            if raw is not None:
                tails.add(bytes(value ^ xor_key for value in raw))
    prefixes = {
        writes[address] + writes[address + 16]
        for address in tuple(writes)
        if address + 16 in writes
        and (writes[address] + writes[address + 16]).startswith(b"0x")
        and re.fullmatch(rb"0x[0-9A-Fa-f]{30}", writes[address] + writes[address + 16])
    }
    return {
        candidate.decode("ascii")
        for prefix in prefixes
        for tail in tails
        if (candidate := prefix + tail) and _CONTRACT_RE.fullmatch(candidate)
    }


def _wide_decoded_items(data: bytes) -> set[tuple[str, int]]:
    items: set[tuple[str, int]] = set()
    for phase in (0, 1):
        for xor_key in (0, _WIDE_XOR):
            current: list[str] = []
            current_start = phase
            offset = phase
            while offset + 2 <= len(data):
                raw_word = struct.unpack_from("<H", data, offset)[0]
                # XOR対象は文字本体だけで、後続のwide NUL／zero paddingは
                # runtime loopの範囲外である。zeroを ``K`` と誤復号して
                # 隣接するproviderやURLを連結しない。
                if xor_key and raw_word == 0:
                    if len(current) >= 8:
                        items.add(("".join(current), current_start))
                    current = []
                    offset += 2
                    current_start = offset
                    continue
                codepoint = raw_word ^ xor_key
                if 0x20 <= codepoint <= 0x7E:
                    if not current:
                        current_start = offset
                    current.append(chr(codepoint))
                else:
                    if len(current) >= 8:
                        items.add(("".join(current), current_start))
                    current = []
                offset += 2
            if len(current) >= 8:
                items.add(("".join(current), current_start))
    return items


def _wide_decoded_texts(data: bytes) -> set[str]:
    return {text for text, _offset in _wide_decoded_items(data)}


def _abi_parser_proven(image: pefile.PE) -> bool:
    candidates = 0
    for section in image.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw = bytes(section.get_data())
        first = _ABI_MACHINE_SIGNATURES[0]
        offset = 0
        while True:
            start = raw.find(first, offset)
            if start < 0:
                break
            window = raw[start : start + 0x240]
            if all(signature in window for signature in _ABI_MACHINE_SIGNATURES[1:]):
                candidates += 1
            offset = start + 1
    return candidates == 1


def _extract_dynamic_keys(
    image: pefile.PE,
    data: bytes,
    groups: tuple[tuple[object, ...], ...],
) -> set[bytes]:
    keys: set[bytes] = set()
    marker = b"KDBM\x01\x00\x00\x00\x10\x00\x00\x00"
    offset = 0
    while True:
        found = data.find(marker, offset)
        if found < 0:
            break
        if found <= len(data) - len(marker) - 16:
            keys.add(data[found + len(marker) : found + len(marker) + 16])
        offset = found + 1
    for instructions in groups:
        for index, instruction in enumerate(instructions):
            operands = instruction.operands
            if (
                instruction.mnemonic.casefold() != "mov"
                or len(operands) != 2
                or operands[0].type != X86_OP_MEM
                or operands[1].type != X86_OP_IMM
                or (int(operands[1].imm) & 0xFFFFFFFF) != 0x4D42444B
            ):
                continue
            immediate_values = {
                int(candidate.operands[1].imm) & 0xFFFFFFFF
                for candidate in instructions[index : index + 24]
                if candidate.mnemonic.casefold() == "mov"
                and len(candidate.operands) == 2
                and candidate.operands[0].type == X86_OP_MEM
                and candidate.operands[1].type == X86_OP_IMM
            }
            if not {1, 16}.issubset(immediate_values):
                continue
            references: list[int] = []
            for candidate in instructions[max(0, index - 80) : index]:
                supplied = candidate.operands
                if (
                    candidate.mnemonic.casefold() == "mov"
                    and len(supplied) == 2
                    and supplied[0].type == X86_OP_REG
                    and _canonical_register(candidate, supplied[0].reg) == "rax"
                    and supplied[1].type == X86_OP_MEM
                    and supplied[1].mem.base == X86_REG_RIP
                    and supplied[1].mem.index == X86_REG_INVALID
                ):
                    references.append(
                        candidate.address + candidate.size + supplied[1].mem.disp
                    )
            if len(references) >= 2:
                first = _read_va(image, data, references[-2], 8)
                second = _read_va(image, data, references[-1], 8)
                if first is not None and second is not None:
                    keys.add(first + second)
    return {key for key in keys if len(key) == 16 and any(key)}


def _valid_host(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return bool(
            len(value) <= 253
            and _HOST_RE.fullmatch(value)
            and all(len(label) <= 63 for label in value.split("."))
        )
    return not address.is_unspecified and not address.is_multicast


def _parse_reversed_config(value: bytes) -> tuple[str, str | None] | None:
    if len(value) < 64 or len(value) % 2:
        return None
    try:
        text = value.decode("utf-16le")
    except UnicodeDecodeError:
        return None
    candidates = (text, text[::-1])
    parsed: list[tuple[str, str | None]] = []
    for candidate in candidates:
        if not candidate.startswith("|") or not candidate.endswith("|"):
            continue
        fields: dict[str, str] = {}
        valid = True
        for item in candidate.strip("|").split("|"):
            if ":" not in item:
                valid = False
                break
            key, supplied = item.split(":", 1)
            if not re.fullmatch(r"[a-z0-9]{1,4}", key) or key in fields:
                valid = False
                break
            fields[key] = supplied
        if not valid or len(fields) < 10 or not {"p1", "o1", "t1"}.issubset(fields):
            continue
        host = fields["p1"].strip().casefold()
        try:
            port = int(fields["o1"], 10)
        except ValueError:
            continue
        if not _valid_host(host) or not 1 <= port <= 65535 or fields["t1"] not in {"0", "1"}:
            continue
        update_url = fields.get("ur") or None
        if update_url is not None:
            parts = urlsplit(update_url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                continue
        parsed.append((f"{host}:{port}", update_url))
    unique = set(parsed)
    return next(iter(unique)) if len(unique) == 1 else None


def _embedded_configs(
    image: pefile.PE,
    data: bytes,
    groups: tuple[tuple[object, ...], ...],
) -> set[tuple[str, str | None]]:
    keys = _extract_dynamic_keys(image, data, groups)
    if len(keys) != 1:
        return set()
    key = next(iter(keys))
    referenced = _rip_targets(groups)
    headers = {
        address
        for address in referenced
        if address + 4 in referenced and address + 8 in referenced
    }
    recovered: set[tuple[str, str | None]] = set()
    for address in headers:
        header = _read_va(image, data, address, 24)
        if header is None:
            continue
        plaintext_size = struct.unpack_from("<I", header, 4)[0]
        if not 64 <= plaintext_size <= 4_000 or plaintext_size % 2:
            continue
        cipher_size = plaintext_size - (plaintext_size % 16) + 16
        ciphertext = _read_va(image, data, address + 24, cipher_size)
        if ciphertext is None or len(ciphertext) % 16:
            continue
        try:
            decryptor = Cipher(algorithms.AES(key), modes.CBC(header[8:24])).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
        except ValueError:
            continue
        if not padded:
            continue
        padding = padded[-1]
        if not 1 <= padding <= 16 or padded[-padding:] != bytes([padding]) * padding:
            continue
        plaintext = padded[:-padding]
        if len(plaintext) != plaintext_size:
            continue
        parsed = _parse_reversed_config(plaintext)
        if parsed is not None:
            recovered.add(parsed)
    return recovered


def _terminal_profile(data: bytes) -> _TerminalProfile | None:
    if _JSON_TEMPLATE not in data or _RESULT_MARKER not in data:
        return None
    image = _load_pe(data)
    if image is None:
        return None
    try:
        if int(image.FILE_HEADER.Machine) != 0x8664 or int(image.OPTIONAL_HEADER.Magic) != 0x20B:
            return None
        groups = _disassemble(image)
        if groups is None or not _abi_parser_proven(image):
            return None
        locations: list[int] = []
        for needle in (_JSON_TEMPLATE, _RESULT_MARKER):
            first = data.find(needle)
            if first < 0 or data.find(needle, first + 1) >= 0:
                return None
            try:
                locations.append(
                    int(image.OPTIONAL_HEADER.ImageBase)
                    + int(image.get_rva_from_offset(first))
                )
            except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
                return None
        selectors = {
            match.group(0)[:-1].decode("ascii").casefold()
            for match in _SELECTOR_RE.finditer(data)
        }
        if len(selectors) != 1:
            return None
        selector = next(iter(selectors))
        selector_offset = data.find((selector + "\x00").encode("ascii"))
        try:
            selector_va = int(image.OPTIONAL_HEADER.ImageBase) + int(
                image.get_rva_from_offset(selector_offset)
            )
        except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
            return None
        references = _rip_targets(groups)
        if any(address not in references for address in (*locations, selector_va)):
            return None
        contracts = {
            match.group(0).decode("ascii")
            for match in _CONTRACT_RE.finditer(data)
        }
        contracts.update(_constructed_contracts(image, data, groups))
        if len(contracts) != 1:
            return None
        decoded_items: set[tuple[str, int]] = set()
        provider_sources: dict[str, set[int]] = {}
        url_locations: list[tuple[str, int]] = []
        for section in image.sections:
            if int(section.SizeOfRawData) <= MAXIMUM_SECTION_SIZE:
                section_items = _wide_decoded_items(bytes(section.get_data()))
                decoded_items.update(section_items)
                section_va = int(image.OPTIONAL_HEADER.ImageBase) + int(
                    section.VirtualAddress
                )
                for text, offset in section_items:
                    for host in _HOST_RE.findall(text):
                        normalized = host.casefold()
                        if normalized.startswith("polygon"):
                            provider_sources.setdefault(normalized, set()).add(
                                section_va + offset
                            )
                    for match in _URL_RE.finditer(text):
                        host = (urlsplit(match.group(0)).hostname or "").casefold()
                        if not host.startswith("polygon"):
                            url_locations.append(
                                (
                                    match.group(0),
                                    section_va + offset + match.start() * 2,
                                )
                            )
        provider_hosts = set(provider_sources)
        url_literals = {url for url, _address in url_locations}
        fallback_urls = {
            url for url, address in url_locations if address in references
        }
        unreferenced_url_literals = url_literals - fallback_urls
        if (
            len(provider_hosts) != MAXIMUM_PROVIDER_COUNT
            or any(not (sources & references) for sources in provider_sources.values())
            or not 1 <= len(url_literals) <= MAXIMUM_FALLBACK_URLS
        ):
            return None
        embedded = _embedded_configs(image, data, groups)
        if len(embedded) > 1:
            return None
        embedded_endpoints = tuple(sorted(item[0] for item in embedded))
        embedded_urls = tuple(sorted({item[1] for item in embedded if item[1]}))
        return _TerminalProfile(
            contract=next(iter(contracts)),
            selector=selector,
            provider_hosts=tuple(sorted(provider_hosts)),
            fallback_urls=tuple(sorted(fallback_urls)),
            unreferenced_url_literals=tuple(sorted(unreferenced_url_literals)),
            embedded_endpoints=embedded_endpoints,
            embedded_urls=embedded_urls,
        )
    finally:
        image.close()


def decode_abi_dynamic_string(value: str) -> str | None:
    """標準ABI dynamic string resultを上限付きで復号する。"""

    if not isinstance(value, str):
        return None
    encoded = value.removeprefix("0x")
    if (
        len(encoded) < 128
        or len(encoded) % 2
        or not re.fullmatch(r"[0-9A-Fa-f]+", encoded)
    ):
        return None
    try:
        offset = int(encoded[:64], 16)
        length = int(encoded[64:128], 16)
    except ValueError:
        return None
    if offset != 32 or not 1 <= length <= MAXIMUM_ABI_STRING_SIZE:
        return None
    padded = ((length + 31) // 32) * 32
    if len(encoded) != 128 + padded * 2:
        return None
    try:
        raw = bytes.fromhex(encoded[128 : 128 + length * 2])
        padding = bytes.fromhex(encoded[128 + length * 2 :])
        decoded = raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
    if any(padding) or "\x00" in decoded or any(ord(character) < 0x20 for character in decoded):
        return None
    return decoded


def analyze_polygon_dead_drop_lineage(data: bytes) -> PolygonDeadDropLineage | None:
    """外層またはterminal PEからPolygon resolver profileを静的に解析する。"""

    if not isinstance(data, bytes) or not 1 <= len(data) <= MAXIMUM_INPUT_SIZE:
        return None
    outer = _recover_outer(data) if _SECTION_NAME in data[:0x10000] else None
    terminal = outer.terminal_pe if outer is not None else data
    profile = _terminal_profile(terminal)
    if profile is None:
        return None
    if outer is not None:
        execution = {
            "trailer_schema": "flags_u32_exec_flags_u16_mode_u8_length_u8_option4",
            "flags": outer.trailer.flags,
            "exec_flags": outer.trailer.exec_flags,
            "mode": outer.trailer.mode,
            "option_length": outer.trailer.option_length,
            "worker_remote_injection_flag": outer.trailer.remote_injection_selected,
            "selected_branch": (
                "remote_process_injection"
                if outer.trailer.remote_injection_selected
                else "in_process_loader"
            ),
            "target_process": (
                "explorer.exe" if outer.trailer.remote_injection_selected else None
            ),
            "injection_api_sequence": (
                ["NtCreateThreadEx", "NtQueueApcThread", "NtResumeThread"]
                if outer.trailer.remote_injection_selected
                else []
            ),
            "alternate_branch": (
                "in_process_loader"
                if outer.trailer.remote_injection_selected
                else "remote_process_injection"
            ),
        }
    else:
        execution = {
            "trailer_schema": None,
            "selected_branch": "not_available_for_terminal_only_input",
        }
    config_recovered = bool(profile.embedded_endpoints)
    observation: dict[str, object] = {
        "schema_version": 1,
        "status": "validated_polygon_dead_drop_terminal_profile",
        "matched": True,
        "profile": "cdata_xtea_lz4_polygon_eth_call_terminal",
        "outer_loader_recovered": outer is not None,
        "loader_fragment_count": outer.fragment_count if outer is not None else 0,
        "static_config_recovered": config_recovered,
        "candidate_config_recovered": not config_recovered,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "terminal_network_lineage_proven": False,
        "terminal_protocol_lineage_proven": False,
        "attribution_scope": "reviewed_terminal_profile_route",
        "resolver_network_lineage_proven": True,
        "resolver": {
            "transport": "https_json_rpc",
            "method": "eth_call",
            "provider_nodes": [
                {
                    "host": host,
                    "role": "resolver_not_c2",
                    "shared_infrastructure": True,
                }
                for host in profile.provider_hosts
            ],
            "provider_node_count": len(profile.provider_hosts),
            "contract_address": profile.contract,
            "function_selector": profile.selector,
            "block_tag": "latest",
            "request_body": {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": profile.contract,
                        "data": profile.selector,
                    },
                    "latest",
                ],
                "id": 1,
            },
            "response_member": "result",
            "abi_result_type": "dynamic_string",
            "maximum_decoded_string_size": MAXIMUM_ABI_STRING_SIZE,
            "fallback_urls": [
                {"url": url, "role": "resolver_not_c2"}
                for url in profile.fallback_urls
            ],
            "unreferenced_url_literals": [
                {
                    "url": url,
                    "role": "dormant_literal_not_ioc",
                    "code_referenced": False,
                    "promoted_to_network_ioc": False,
                }
                for url in profile.unreferenced_url_literals
            ],
            "resolved_value_observed": False,
            "provider_nodes_are_c2": False,
        },
        "embedded_config": {
            "recovered": config_recovered,
            "endpoints": list(profile.embedded_endpoints),
            "urls": list(profile.embedded_urls),
            "key_included": False,
            "raw_config_included": False,
        },
        "execution_mode": execution,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    return PolygonDeadDropLineage(
        observation=observation,
        terminal_component=terminal,
        embedded_endpoints=profile.embedded_endpoints,
        embedded_urls=profile.embedded_urls,
    )


def probe_polygon_dead_drop(data: bytes) -> dict[str, object]:
    """raw payloadを含めないmachine-readable probe結果を返す。"""

    result = analyze_polygon_dead_drop_lineage(data)
    if result is None:
        return {
            "schema_version": 1,
            "status": "not_matched",
            "matched": False,
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "static_config_recovered": False,
            "sample_executed": False,
            "network_contacted": False,
        }
    return dict(result.observation)


__all__ = [
    "MAXIMUM_INPUT_SIZE",
    "PolygonDeadDropLineage",
    "analyze_polygon_dead_drop_lineage",
    "decode_abi_dynamic_string",
    "probe_polygon_dead_drop",
]
