"""検証済みnativeコード形から、BSS初期化型の設定を静的に復元する。

検体、CPU命令、ネットワーク要求を実行しない。入力SHAによる特例はない。
key/nonce/selector/XOR/RVAはコード参照から取得する。未対応compiler形を拒否し、
既存memory extractorの条件は変更しない。ファミリー帰属と稼働確認は別判定。
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from itertools import pairwise
from urllib.parse import urlsplit, urlunsplit

import capstone
import pefile
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from remus_memory_config import _parse_endpoint_slot

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_SECTION_BYTES = 16 * 1024 * 1024
MAX_CODE_BYTES = 4 * 1024 * 1024
MAX_SECONDS = 8.0
MAX_CANDIDATES = 4
SLOT_SIZE = 64
SLOT_COUNT = 3

# 値は関数命令形のdigestであり、検体全体SHAではない。算術命令と内部branchを
# 保持し、RIP relative pointerとdirect call relocationだけを正規化する。
# branch3は外部resolverのmetadataであり、取得しない限り最終C2値は不明。
PROFILE_SIZES = {
    "initializer": 0x187,
    "stream": 0x695,
    "copy": 0x11C,
    "selector": 0x61B,
    "assign": 0x2AB,
    "transport": 0x67B,
    "http": 0xF6E,
}
VERIFIED_CODE_PROFILE = {
    "initializer": "361db0776df89adac481bcdbf60ad38395498f13dc2d9561aa4320f00896d485",
    "stream": "435e4f01b18512e529d3545cbbf05c01f5ef1b777a4ce04f7890b34499692000",
    "copy": "3574a00828ab9ac276d9c45e6efa5b7d4df9179812d5b6b0d44d1c896a328da1",
    "selector": "f59657cf74d72f91f35ad15eb6af17a4fd4ec0356e7b2e35a98a21b9a7a6da74",
    "assign": "04c9ce9b195d9beafcf4c588458574ae4d242fed023b41b2ecc8ba26501f5383",
    "http": "555461d0fa47e0644d28ee4cbfcf2de2db6fc01b0d687b6439d365f70bf137b5",
    "transport": "6a5370fd5627d07ceac4ce6abe3b4399376c8569bdac9ca493999a7a01e78d41",
    "dispatch_data": "c4d7c0556671de713b565c09d954bbf0d04dcd4671bc188b5d754f1f32425568",
}

INIT_CALL = re.compile(
    rb"\x48\x83\xec\x28\x48\x8d\x0d(?P<state>.{4})"
    rb"\x48\x8d\x15(?P<key>.{4})\x4c\x8d\x05(?P<nonce>.{4})"
    rb"\x45\x31\xc9\xe8(?P<init>.{4})\xb0\x01\x48\x83\xc4\x28\xc3",
    re.S,
)
SELECT_CALL = re.compile(
    rb"\x0f\xb6\x05(?P<selector>.{4})\x83\xf0(?P<mask>.)\xc1\xe0\x06"
    rb"\x48\x8d\x15(?P<cipher>.{4})\x48\x01\xc2"
    rb"\x48\x8d\x0d(?P<state>.{4})\x4c\x8d\x84\x24\x10\x01\x00\x00"
    rb"\xe8(?P<stream>.{4})",
    re.S,
)


class RemusDiskConfigError(ValueError):
    """静的コード形・参照範囲・設定値の検証に失敗した。"""


class RemusDiskConfigLimitError(RemusDiskConfigError):
    """制約超過を非一致へ丸めず、呼出し全体の失敗として返す。"""

    def __init__(self, constraint, observed, limit):
        self.constraint, self.observed, self.limit = constraint, observed, limit
        super().__init__(f"制約超過: {constraint} ({observed} > {limit})")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _pe_sections(data: bytes, *, input_limit: int = MAX_INPUT_BYTES):
    """単一の有界AMD64 PEを解析し、巨大overlayへ展開しない。"""
    if type(data) is not bytes or len(data) > input_limit or data[:2] != b"MZ":
        raise RemusDiskConfigError("入力サイズまたはMZが不正です")
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise RemusDiskConfigError("PEヘッダーを検証できません") from exc
    if image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Magic != 0x20B:
        raise RemusDiskConfigError("AMD64 PEではありません")
    declared_sections = int(image.FILE_HEADER.NumberOfSections)
    if not 1 <= declared_sections <= 32 or len(image.sections) != declared_sections:
        raise RemusDiskConfigError("section数が不正です")
    image_size = int(image.OPTIONAL_HEADER.SizeOfImage)
    headers = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    if not 0 < headers <= min(len(data), image_size) or image_size > MAX_SECTION_BYTES:
        raise RemusDiskConfigError("PE image/headerサイズが上限外です")
    section_table_end = (
        int(image.DOS_HEADER.e_lfanew) + 24 + int(image.FILE_HEADER.SizeOfOptionalHeader) + 40 * declared_sections
    )
    if section_table_end > headers:
        raise RemusDiskConfigError("section tableがheader範囲外です")
    raw_ranges, virtual_ranges = [], []
    raw_total, code_total = 0, 0
    for section in image.sections:
        size = int(section.SizeOfRawData)
        offset = int(section.PointerToRawData)
        rva = int(section.VirtualAddress)
        span = max(size, int(section.Misc_VirtualSize))
        if span <= 0 or rva < headers or rva + span > image_size:
            raise RemusDiskConfigError("section仮想範囲が不正です")
        virtual_ranges.append((rva, rva + span))
        if size:
            if offset < headers or offset + size > len(data):
                raise RemusDiskConfigError("section raw範囲が不正です")
            raw_ranges.append((offset, offset + size))
            raw_total += size
            if section.Characteristics & 0x20000000:
                code_total += size
    if raw_total > MAX_SECTION_BYTES or code_total > MAX_CODE_BYTES:
        raise RemusDiskConfigError("section/code総量が上限外です")
    for ranges in (raw_ranges, virtual_ranges):
        ordered = sorted(ranges)
        if any(before[1] > after[0] for before, after in pairwise(ordered)):
            raise RemusDiskConfigError("section範囲が重複しています")
    _section(image, int(image.OPTIONAL_HEADER.AddressOfEntryPoint), 1, executable=True)
    return image


def _section(image, rva, length, *, executable=None):
    """raw-backedな単一sectionの範囲・実行属性を検証する。"""
    if rva < 0 or length <= 0:
        raise RemusDiskConfigError("RVA/lengthが不正です")
    hits = [
        section
        for section in image.sections
        if int(section.VirtualAddress) <= rva
        and rva + length <= int(section.VirtualAddress) + int(section.SizeOfRawData)
    ]
    if len(hits) != 1:
        raise RemusDiskConfigError("参照が単一のfile-backed section内にありません")
    if executable is not None and bool(hits[0].Characteristics & 0x20000000) != executable:
        raise RemusDiskConfigError("参照先sectionの実行属性が不正です")
    return hits[0]


def _read(data, image, rva, length, *, executable=None):
    """検証済みsectionから入力bytesだけを切り出し、fileを開かない。"""
    section = _section(image, rva, length, executable=executable)
    offset = int(section.PointerToRawData) + rva - int(section.VirtualAddress)
    if offset < 0 or offset + length > len(data):
        raise RemusDiskConfigError("raw readの範囲が不正です")
    return data[offset : offset + length]


def _virtual_section(image, rva, size, *, executable=None):
    hits = [
        s
        for s in image.sections
        if int(s.VirtualAddress) <= rva
        and rva + size <= int(s.VirtualAddress) + max(int(s.SizeOfRawData), int(s.Misc_VirtualSize))
    ]
    if len(hits) != 1 or size <= 0 or rva < 0:
        raise RemusDiskConfigError("仮想参照が単一sectionの範囲内ではありません")
    if executable is not None and bool(hits[0].Characteristics & 0x20000000) != executable:
        raise RemusDiskConfigError("仮想参照の実行属性が不正です")
    return hits[0]


def _instructions(data, image, rva, size):
    raw = _read(data, image, rva, size, executable=True)
    machine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    machine.detail = True
    instructions = list(machine.disasm(raw, rva))
    if sum(x.size for x in instructions) != size or len(instructions) > 4096:
        raise RemusDiskConfigError("関数命令境界が未検証です")
    return raw, instructions


def _profile_digest(data, image, rva, kind):
    """固定した算術/内部branchと可変pointerを区別する。"""
    raw, instructions = _instructions(data, image, rva, PROFILE_SIZES[kind])
    normalized = bytearray(raw)
    for ins in instructions:
        relative = ins.address - rva
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                target = ins.address + ins.size + op.mem.disp
                _virtual_section(image, target, max(1, op.size))
                # Capstone 5は一部MOVDQAのdisp_sizeを2と報告するため、x64 RIP
                # の必須disp32を実bytesとdecoded displacementの一致で検証する。
                if (
                    ins.disp_offset <= 0
                    or ins.disp_offset + 4 > ins.size
                    or struct.unpack_from("<i", ins.bytes, ins.disp_offset)[0] != op.mem.disp
                ):
                    raise RemusDiskConfigError("RIP displacementが未対応です")
                normalized[relative + ins.disp_offset : relative + ins.disp_offset + 4] = b"\0" * 4
        variable_call = (
            kind == "stream"
            or kind == "selector"
            and relative in {0xE5, 0x19A, 0x43A}
            or kind == "transport"
            and relative in {0x5A, 0xE6, 0x2F6}
        )
        if variable_call and ins.mnemonic == "call" and len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM:
            _section(image, int(ins.operands[0].imm), 1, executable=True)
            if ins.imm_size != 4:
                raise RemusDiskConfigError("direct call relocationが未対応です")
            normalized[relative + ins.imm_offset : relative + ins.imm_offset + 4] = b"\0" * 4
    if kind == "selector":
        # selector XORと後段XORの二つの定数だけを可変parameterにする。
        for relative, mnemonic in ((0x11, "and"), (0x18, "add"), (0xC6, "xor"), (0xFC, "mov"), (0x125, "imul")):
            ins = next((x for x in instructions if x.address - rva == relative), None)
            if ins is None or ins.mnemonic != mnemonic or not ins.imm_size:
                raise RemusDiskConfigError("可変XOR引数の命令形が不正です")
            normalized[relative + ins.imm_offset : relative + ins.imm_offset + ins.imm_size] = b"\0" * ins.imm_size
    if kind == "transport":
        for relative, mnemonic in ((0xCE, "and"), (0xD2, "mov"), (0xD6, "and"), (0xD8, "add"), (0xDB, "and")):
            ins = next((x for x in instructions if x.address - rva == relative), None)
            if ins is None or ins.mnemonic != mnemonic or ins.imm_size != 1:
                raise RemusDiskConfigError("selector rotationの可変parameterが不正です")
            normalized[relative + ins.imm_offset] = 0
    return _sha(bytes(normalized)), instructions


def _dispatch_digest(data, image, selector_rva):
    """CFF jump tableなどを含むdataを固定し、任意のsink経路差替えを拒否する。"""
    section = _section(image, selector_rva, 2, executable=False)
    if not section.Characteristics & 0x80000000:
        raise RemusDiskConfigError("selectorがwritable data内ではありません")
    normalized = bytearray(section.get_data())
    selected_offset = selector_rva - int(section.VirtualAddress)
    normalized[selected_offset : selected_offset + 2] = b"\0\0"
    base = int(image.OPTIONAL_HEADER.ImageBase)
    executable = [s for s in image.sections if s.Characteristics & 0x20000000]
    # compiler profileは、8byte alignmentのimage-internal code pointerだけを持つ。
    for offset in range(0, len(normalized) - 7, 8):
        value = struct.unpack_from("<Q", normalized, offset)[0]
        matches = [
            s
            for s in executable
            if base + int(s.VirtualAddress) <= value < base + int(s.VirtualAddress) + int(s.SizeOfRawData)
        ]
        if len(matches) == 1:
            struct.pack_into("<Q", normalized, offset, value - base - int(matches[0].VirtualAddress))
    return _sha(bytes(normalized))


def _verify(data, image, rva, kind):
    digest, instructions = _profile_digest(data, image, rva, kind)
    if digest != VERIFIED_CODE_PROFILE.get(kind):
        raise RemusDiskConfigError(f"{kind}が検証済みcompiler形と一致しません")
    return instructions


def _rip(ins):
    values = [
        ins.address + ins.size + op.mem.disp
        for op in ins.operands
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
    ]
    if len(values) != 1:
        raise RemusDiskConfigError("RIP参照が一意ではありません")
    return values[0]


def _call(ins):
    if ins.mnemonic != "call" or len(ins.operands) != 1 or ins.operands[0].type != X86_OP_IMM:
        raise RemusDiskConfigError("direct callの根拠がありません")
    return int(ins.operands[0].imm)


def _at(instructions, start, relative):
    value = next((x for x in instructions if x.address == start + relative), None)
    if value is None:
        raise RemusDiskConfigError("関数相対命令位置が不正です")
    return value


def _imm(ins):
    values = [int(op.imm) for op in ins.operands if op.type == X86_OP_IMM]
    if len(values) != 1:
        raise RemusDiskConfigError("即値が一意ではありません")
    return values[0]


def _validate_rotation(instructions, start, mask):
    d, c, m1, m2, n = (_imm(_at(instructions, start, r)) & 255 for r in (0xCE, 0xD2, 0xD6, 0xD8, 0xDB))
    if m1 != mask or m2 != mask or n != (mask ^ 255):
        raise RemusDiskConfigError("selector rotationと復号maskが一致しません")
    for selected in range(4):
        encoded = selected ^ mask
        intermediate = ((encoded ^ 1) - ((encoded * 2) & d)) & 255
        following = ((c - intermediate) & 255 & m1) | ((intermediate + m2) & 255 & n)
        if following != ((selected + 1) ^ mask):
            raise RemusDiskConfigError("selectorの0→1→2→resolver3切替式が一致しません")


def _search(data, image, pattern):
    matches = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        code = section.get_data()
        for match in pattern.finditer(code):
            if len(matches) >= MAX_CANDIDATES:
                raise RemusDiskConfigError("候補数上限を超えています")
            matches.append((int(section.VirtualAddress) + match.start(), match))
    return matches


def _chacha_slots(cipher, key, nonce):
    """64bit counter=0から連続3blockの暗号数式だけを計算する。"""
    if len(cipher) != SLOT_SIZE * SLOT_COUNT or len(key) != 32 or len(nonce) != 8:
        raise RemusDiskConfigError("暗号parameterの長さが不正です")
    transform = Cipher(algorithms.ChaCha20(key, b"\0" * 8 + nonce), mode=None).decryptor()
    return transform.update(cipher) + transform.finalize()


def _wide(data, multiplier):
    if len(data) % 2 or len(data) > 512:
        raise RemusDiskConfigError("wide XOR入力が上限外です")
    plain = b"".join(
        struct.pack("<H", value ^ (((index + 1) * multiplier) & 65535))
        for index, value in enumerate(struct.unpack("<" + "H" * (len(data) // 2), data))
    )
    text = plain.decode("utf-16le").rstrip("\0")
    if any(ord(x) < 0x20 and x not in "\r\n\t" for x in text):
        raise RemusDiskConfigError("wide XOR出力に不正文字があります")
    return text


def _resolver_metadata(data, image, selector_rva, instructions, url_rva, http_rva):
    # compiler profileがこのbranch全体のXOR算術、長さ、POST引数とresponse処理を含む。
    body_rva = _rip(_at(instructions, selector_rva, 0x1EB))
    body_cipher = _read(data, image, body_rva, 0x89, executable=False)
    body = bytes(v ^ (((i + 1) * 0x2C) & 255) for i, v in enumerate(body_cipher)).rstrip(b"\0")
    request = json.loads(body.decode("ascii"))
    if not isinstance(request, dict) or request.get("method") != "eth_call" or request.get("jsonrpc") != "2.0":
        raise RemusDiskConfigError("resolver JSON-RPC構造が不正です")
    params = request.get("params")
    if not isinstance(params, list) or len(params) != 2 or params[1] != "latest" or not isinstance(params[0], dict):
        raise RemusDiskConfigError("resolver paramsが未対応です")
    contract, call_data = params[0].get("to"), params[0].get("data")
    if not isinstance(contract, str) or re.fullmatch(r"0x[0-9a-fA-F]{40}", contract) is None:
        raise RemusDiskConfigError("resolver contractが不正です")
    if not isinstance(call_data, str) or re.fullmatch(r"0x[0-9a-fA-F]{8}", call_data) is None:
        raise RemusDiskConfigError("resolver function selectorが不正です")
    uri_rva = _rip(_at(instructions, selector_rva, 0x39F))
    uri = _wide(_read(data, image, uri_rva, 48, executable=False) + struct.pack("<I", 0x117A4266), 0xCF71)
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RemusDiskConfigError("resolver URIが安全な形式ではありません")
    if _call(_at(instructions, selector_rva, 0x43A)) != http_rva:
        raise RemusDiskConfigError("resolver HTTP sinkが共通sinkと一致しません")
    if (
        _rip(_at(instructions, selector_rva, 0x52B)) != url_rva
        or _rip(_at(instructions, selector_rva, 0x5D7)) != url_rva
    ):
        raise RemusDiskConfigError("resolver出力が同じURL bufferへ渡されません")
    return {
        "selector_value": 3,
        "role": "blockchain_c2_resolver_not_c2",
        "uri": uri,
        "method": "POST",
        "jsonrpc_method": "eth_call",
        "contract": contract,
        "call_data": call_data,
        "block_tag": "latest",
        "response_field": "result",
        "response_transform": "last_64_hex_characters_to_32_ascii_bytes_then_utf16",
        "final_c2_recovered": False,
        "network_contacted": False,
        "limitation_ja": "外部RPCに接続していないため、その時点で返されるC2は未取得です。",
    }


def _candidate(data, image, start, init_match, selector_start, selector_match, deadline):
    state = start + 11 + struct.unpack("<i", init_match.group("state"))[0]
    key = start + 18 + struct.unpack("<i", init_match.group("key"))[0]
    nonce = start + 25 + struct.unpack("<i", init_match.group("nonce"))[0]
    initializer = start + 33 + struct.unpack("<i", init_match.group("init"))[0]
    selector = selector_start + 7 + struct.unpack("<i", selector_match.group("selector"))[0]
    cipher = selector_start + 20 + struct.unpack("<i", selector_match.group("cipher"))[0]
    selected_state = selector_start + 30 + struct.unpack("<i", selector_match.group("state"))[0]
    stream = selector_start + 43 + struct.unpack("<i", selector_match.group("stream"))[0]
    if selected_state != state:
        raise RemusDiskConfigError("初期化stateと復号stateが一致しません")
    _virtual_section(image, state, 64, executable=False)
    # BSS stateがゼロなのはon-diskの仕様。literal runtime stateを要求しない。
    _read(data, image, key, 32, executable=False)
    _read(data, image, nonce, 8, executable=False)
    _verify(data, image, initializer, "initializer")
    stream_instructions = _verify(data, image, stream, "stream")
    copies = {_call(ins) for ins in stream_instructions if ins.mnemonic == "call"}
    if len(copies) != 1:
        raise RemusDiskConfigError("stream外部calleeが一意ではありません")
    copy = copies.pop()
    _verify(data, image, copy, "copy")
    selector_function = selector_start - 0xBF
    instructions = _verify(data, image, selector_function, "selector")
    mask = selector_match.group("mask")[0]
    if (
        mask > 127
        or _imm(_at(instructions, selector_function, 0x11)) != (mask ^ 255)
        or _imm(_at(instructions, selector_function, 0x18)) != mask
    ):
        raise RemusDiskConfigError("selector前段MBAとXOR maskが一致しません")
    selected = _read(data, image, selector, 1, executable=False)[0] ^ mask
    if selected != 0:
        raise RemusDiskConfigError("初回counter=0のon-disk profileでは初期selector0だけを検証済みです")
    if _dispatch_digest(data, image, selector) != VERIFIED_CODE_PROFILE.get("dispatch_data"):
        raise RemusDiskConfigError("CFF dispatch dataが検証済みprofileと一致しません")
    xor_value = (
        _imm(_at(instructions, selector_function, 0xFC)) ^ _imm(_at(instructions, selector_function, 0x125))
    ) & 0xFFFFFFFF
    xor_key = struct.pack("<I", xor_value)
    url = _rip(_at(instructions, selector_function, 0x183))
    _virtual_section(image, url, 128, executable=False)
    assign = _call(_at(instructions, selector_function, 0x19A))
    _verify(data, image, assign, "assign")
    http = _call(_at(instructions, selector_function, 0x43A))
    _verify(data, image, http, "http")
    # transportのentry位置はselectorを呼ぶ既知compiler形から動的に決める。
    transports = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        code = section.get_data()
        for offset in range(len(code) - 4):
            if offset % 4096 == 0:
                observed = time.monotonic() - (deadline - MAX_SECONDS)
                if observed > MAX_SECONDS:
                    raise RemusDiskConfigLimitError("wall_seconds", observed, MAX_SECONDS)
            if code[offset] != 0xE8:
                continue
            call_rva = int(section.VirtualAddress) + offset
            if call_rva + 5 + struct.unpack_from("<i", code, offset + 1)[0] != selector_function:
                continue
            candidate = call_rva - 0x5A
            try:
                ti = _verify(data, image, candidate, "transport")
                if _rip(_at(ti, candidate, 0x81)) != url or _call(_at(ti, candidate, 0x2F6)) != http:
                    continue
                _validate_rotation(ti, candidate, mask)
                transports.append(candidate)
            except RemusDiskConfigError:
                continue
    if len(transports) != 1:
        raise RemusDiskConfigError("URL→POST HTTPsinkが一意に検証できません")
    intermediate = _chacha_slots(
        _read(data, image, cipher, 192, executable=False),
        _read(data, image, key, 32, executable=False),
        _read(data, image, nonce, 8, executable=False),
    )
    plaintext = bytes(v ^ xor_key[i % 4] for i, v in enumerate(intermediate))
    endpoints = []
    for index in range(3):
        block = plaintext[index * 64 : (index + 1) * 64]
        endpoint = _parse_endpoint_slot(block, index)
        if endpoint is None or endpoint["sentinel"]:
            raise RemusDiskConfigError("3slotのURL構造が不正またはsentinelです")
        parsed = urlsplit(endpoint["uri"])
        endpoint["uri"] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        endpoint["plaintext_sha256"] = _sha(block)
        endpoint["counter"] = index
        endpoint["role"] = "selected_c2_configuration" if index == selected else "fallback_c2_configuration"
        endpoint["confidence"] = "confirmed_static_code_usage_not_liveness"
        endpoints.append(endpoint)
    resolver = _resolver_metadata(data, image, selector_function, instructions, url, http)
    return {
        "endpoints": endpoints,
        "selected_index": selected,
        "resolver": resolver,
        "evidence": {
            "initializer_call_rva": start,
            "initializer_rva": initializer,
            "stream_rva": stream,
            "copy_rva": copy,
            "selector_rva": selector,
            "selector_function_rva": selector_function,
            "key_rva": key,
            "nonce_rva": nonce,
            "cipher_rva": cipher,
            "state_rva": state,
            "url_buffer_rva": url,
            "assign_rva": assign,
            "transport_rva": transports[0],
            "http_rva": http,
            "selector_xor_mask": mask,
            "state_source": "on_disk_bss_initializer_code",
            "slot_counter_mode": "continuous_64_bit_counter_0_1_2",
            "post_xor_value_sha256": _sha(xor_key),
            "code_profile": VERIFIED_CODE_PROFILE,
        },
    }


def extract_remus_disk_config(data: bytes) -> dict:
    """静的configを抽出するが、family確認や能動profile生成は行わない。"""
    started = time.monotonic()
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        raise RemusDiskConfigError("入力形式または容量が上限外です")
    try:
        image = _pe_sections(data, input_limit=MAX_INPUT_BYTES)
        initializers = _search(data, image, INIT_CALL)
        selectors = _search(data, image, SELECT_CALL)
        results = []
        for start, init_match in initializers:
            for selector_start, selector_match in selectors:
                if time.monotonic() - started > MAX_SECONDS:
                    raise RemusDiskConfigLimitError("wall_seconds", time.monotonic() - started, MAX_SECONDS)
                try:
                    results.append(
                        _candidate(
                            data, image, start, init_match, selector_start, selector_match, started + MAX_SECONDS
                        )
                    )
                except RemusDiskConfigLimitError:
                    raise
                except (RemusDiskConfigError, ValueError, struct.error, UnicodeError):
                    continue
        if time.monotonic() - started > MAX_SECONDS:
            raise RemusDiskConfigLimitError("wall_seconds", time.monotonic() - started, MAX_SECONDS)
        if len(results) != 1:
            raise RemusDiskConfigError("一意の検証済みon-disk configがありません")
        return {
            "schema_version": 1,
            "status": "extracted",
            "sample_sha256": _sha(data),
            "sample_size": len(data),
            "profile": "native_token_task_bss_chacha20_postxor_v1",
            "config": results[0],
            "family_attribution_confirmed": False,
            "c2_liveness_confirmed": False,
            "active_profile_generated": False,
            "safety": {
                "sample_executed": False,
                "cpu_emulation_used": False,
                "network_contacted": False,
                "keys_published": False,
                "credentials_published": False,
            },
            "limitations_ja": [
                "未対応compiler形と複数config候補は拒否します。",
                "復号configとHTTP利用の静的根拠は、現在の稼働確認とは異なります。",
                "resolver経由の現在のC2は未取得です。",
                "ファミリー帰属は独立detectorで補強する必要があります。",
            ],
        }
    except pefile.PEFormatError as exc:
        raise RemusDiskConfigError(str(exc)) from exc
