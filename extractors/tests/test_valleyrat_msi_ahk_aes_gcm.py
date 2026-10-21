"""MSI／AHK／AES-GCM終端復元器を実値なしの合成fixtureで検証する。"""

from __future__ import annotations

import base64
import struct

from Cryptodome.Cipher import AES

from extractors.valleyrat.msi_ahk_aes_gcm import (
    INNER_MAGIC,
    INNER_VERSION,
    _ahk_script,
    _bound_msi_cabinet_stream,
    _CabMember,
    _changes_rsp_basis,
    _function_instructions,
    _msi_file_records,
    _msi_media_record,
    _MsiFileRecord,
    _recover_from_cab_members,
    _recover_shellcode,
    probe_msi_ahk_aes_gcm,
    public_recovery_summary,
)


def _relative32(source_next: int, target: int) -> bytes:
    """合成x64 fixture用の符号付きrel32を返す。"""

    return struct.pack("<i", target - source_next)


def _put(blob: bytearray, offset: int, value: bytes) -> None:
    """固定offsetへ範囲内で合成byte列を配置する。"""

    blob[offset : offset + len(value)] = value


def _call(source: int, target: int) -> bytes:
    """合成x64 fixture用direct callを生成する。"""

    return b"\xe8" + _relative32(source + 5, target)


def _lea_rip(opcode: bytes, source: int, target: int) -> bytes:
    """指定opcodeのRIP相対leaを生成する。"""

    return opcode + _relative32(source + len(opcode) + 4, target)


def _xor_wide_stack_run(text: str, base: int, key: int = 0x5D) -> bytes:
    """stack byte storeでASCII/XOR-key対を構築する。"""

    result = bytearray()
    encoded = b"".join(bytes((value ^ key, key)) for value in text.encode("ascii"))
    for index, value in enumerate(encoded):
        result += bytes((0xC6, 0x44, 0x24, base + index, value))
    return bytes(result)


def _synthetic_shellcode(
    *,
    corrupt_tag: bool = False,
    dead_network_evidence: bool = False,
    replace_getaddrinfo_hash: bool = False,
    break_config_argument_flow: bool = False,
    mutually_exclusive_parser_chain: bool = False,
    clobber_r9d: bool = False,
    overwrite_indirect_api_slot: str | None = None,
    rebase_rsp_before_api_call: bool = False,
    mutually_exclusive_decryptor_chain: bool = False,
) -> bytes:
    """実検体値を含まないentry／GCM／network lineageを構造合成する。"""

    magic_offset = 0x100
    container_offset = 0x200
    lowercase_helper = 0x600
    fnv_helper = 0x700
    export_resolver = 0x800
    xor_helper = 0xA00
    initializer = 0xB00
    magic_validator = 0x1400
    key_derivation = 0x1500
    decryptor = 0x1600
    network_worker = 0x2000
    network_caller = 0x2400
    parser = 0x2800
    main = 0x2A00
    blob = bytearray(b"\x90" * 0x3000)

    magic = b"SYNTHETIC-GCMv1!"
    first_seed = bytes((index * 7 + 3) & 0xFF for index in range(0x20))
    second_seed = bytes((index * 11 + 9) & 0xFF for index in range(0x20))
    key = bytes(
        left ^ right for left, right in zip(first_seed, second_seed, strict=True)
    )
    _put(blob, magic_offset, magic + first_seed + second_seed)

    host = b"fixture.example.net"
    fields = (host, b"alpha", b"", b"omega")
    plaintext = struct.pack(
        "<IHHHHHHB",
        INNER_MAGIC,
        INNER_VERSION,
        443,
        *(len(field) for field in fields),
        1,
    ) + b"".join(fields)
    nonce = bytes((index * 13 + 5) & 0xFF for index in range(0x0C))
    aad = magic + struct.pack("<HHI", 1, 0x34, len(plaintext)) + nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=0x10)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    if corrupt_tag:
        tag = tag[:-1] + bytes((tag[-1] ^ 1,))
    _put(blob, container_offset, aad + tag + ciphertext)

    validator = bytearray(bytes.fromhex("48837c240810"))
    validator += _lea_rip(
        bytes.fromhex("488d15"), magic_validator + len(validator), magic_offset
    )
    validator += bytes.fromhex("31c809c839c0c3")
    _put(blob, magic_validator, bytes(validator))

    key_loop = bytearray(bytes.fromhex("83f9207400"))
    key_loop += _lea_rip(
        bytes.fromhex("488d05"), key_derivation + len(key_loop), magic_offset + 0x10
    )
    key_loop += bytes.fromhex("0fb60408")
    key_loop += _lea_rip(
        bytes.fromhex("488d15"), key_derivation + len(key_loop), magic_offset + 0x30
    )
    key_loop += bytes.fromhex("0fb6140a31d088040bffc1")
    loop_jump = len(key_loop)
    key_loop += b"\xeb\x00"
    done = len(key_loop)
    key_loop += b"\xc3"
    key_loop[4] = done - 5
    key_loop[loop_jump + 1] = (-(loop_jump + 2)) & 0xFF
    _put(blob, key_derivation, bytes(key_loop))

    lowercase = bytes.fromhex("80f94180f95a80c120c3")
    _put(blob, lowercase_helper, lowercase)

    fnv = bytearray(b"\xb8" + struct.pack("<I", 0x811C9DC5))
    fnv += _call(fnv_helper + len(fnv), lowercase_helper)
    fnv += bytes.fromhex("31c869c093010001c3")
    _put(blob, fnv_helper, bytes(fnv))

    resolver = bytearray(bytes.fromhex("6681394d5a"))
    resolver += bytes.fromhex("81793c50450000")
    resolver += bytes.fromhex("8b81880000008b41188b411c8b41208b4124")
    resolver += _call(export_resolver + len(resolver), fnv_helper)
    resolver += b"\xc3"
    _put(blob, export_resolver, bytes(resolver))

    xor_copy = bytearray(bytes.fromhex("31c041880183fa00740541c6410100c3"))
    _put(blob, xor_helper, bytes(xor_copy))

    init = bytearray(bytes.fromhex("48894c24084881ec00010000"))
    module = b"ws2_32.dll"
    module_key = 0x5A
    for index, value in enumerate(module):
        init += bytes.fromhex("c64424") + bytes((0x30 + index, value ^ module_key))
    init += bytes.fromhex("48c7442420") + struct.pack("<I", len(module) + 1)
    init += bytes.fromhex("4c8d4c245041b0") + bytes((module_key,))
    init += b"\xba" + struct.pack("<I", len(module))
    init += bytes.fromhex("488d4c2430")
    init += _call(initializer + len(init), xor_helper)
    init += bytes.fromhex(
        "488b842408010000488b004889442470488d4c2450ff5424704889442478"
    )
    hashes = {
        0xA0: 0x1C80EC1F,
        0xA8: 0x9012766C,
        0xB8: 0xAAE0CCF9,
        0xE0: 0x9467F52C ^ (1 if replace_getaddrinfo_hash else 0),
        0xE8: 0x36BC6608,
    }
    for slot, digest in hashes.items():
        init += b"\xba" + struct.pack("<I", digest)
        init += bytes.fromhex("488b4c2478")
        init += _call(initializer + len(init), export_resolver)
        init += bytes.fromhex("488b8c2408010000")
        init += bytes.fromhex("488981") + struct.pack("<I", slot)
    init += bytes.fromhex("4881c400010000c3")
    _put(blob, initializer, bytes(init))

    function = bytearray()
    function += _call(decryptor + len(function), magic_validator)
    function += _call(decryptor + len(function), key_derivation)
    decryptor_call_end = len(function)
    function += bytes.fromhex("0fb7401083f801")
    function += bytes.fromhex("0fb740124883f834")
    function += bytes.fromhex("8b40144883f811")
    function += bytes.fromhex("4881f8cc070000")
    for text, base in (
        ("AES", 0x08),
        ("ChainingModeGCM", 0x20),
        ("ChainingMode", 0x40),
        ("ObjectLength", 0x58),
    ):
        function += _xor_wide_stack_run(text, base)
        function += b"\x90"
    gcm_layout_start = len(function)
    function += bytes.fromhex("c744240858000000")
    function += bytes.fromhex("c744240c01000000")
    function += bytes.fromhex("4883c018")
    function += bytes.fromhex("c74424100c000000")
    function += bytes.fromhex("c744241424000000")
    function += bytes.fromhex("4883c024")
    function += bytes.fromhex("c744241810000000")
    function += bytes.fromhex("4883c034")
    function += b"\x3d" + struct.pack("<I", INNER_MAGIC)
    function += bytes.fromhex("83f807")
    for value in (0x100, 0x110, 0x200, 0x210, 0x310):
        function += bytes.fromhex("4805") + struct.pack("<I", value)
    function += bytes.fromhex("888810050000")
    function += bytes.fromhex("b90a000000f7f1c3")
    if mutually_exclusive_decryptor_chain:
        call_prefix = function[:decryptor_call_end]
        schema_and_strings = function[decryptor_call_end:gcm_layout_start]
        layout_and_inner = function[gcm_layout_start:]
        branched = bytearray(call_prefix)
        branched += bytes.fromhex("85c00f84")
        conditional_displacement = len(branched)
        branched += b"\x00" * 4
        branched += schema_and_strings
        branched += b"\xe9"
        branch_end_displacement = len(branched)
        branched += b"\x00" * 4
        layout_branch = len(branched)
        branched += layout_and_inner
        branch_end = len(branched)
        branched += b"\xc3"
        branched[conditional_displacement : conditional_displacement + 4] = _relative32(
            decryptor + conditional_displacement + 4,
            decryptor + layout_branch,
        )
        branched[branch_end_displacement : branch_end_displacement + 4] = _relative32(
            decryptor + branch_end_displacement + 4,
            decryptor + branch_end,
        )
        function = branched
    _put(blob, decryptor, bytes(function))

    network = bytearray(
        bytes.fromhex("4c894c24204c89442418488954241048894c24084881ec00020000")
    )
    if dead_network_evidence:
        network += b"\xe9\x00\x00\x00\x00"
        dead_jump_offset = len(network) - 4
    network += bytes.fromhex("c744244400000000")
    network += bytes.fromhex("c744244801000000")
    network += bytes.fromhex("c744244c06000000")
    network += bytes.fromhex("488b842408020000488b80e00000004889442460")
    network += bytes.fromhex("488b842410020000480500010000")
    network += bytes.fromhex("4c8d4c24684c8d4424404889c2")
    host_slot = 0x218 if break_config_argument_flow else 0x220
    network += bytes.fromhex("488b8c24") + struct.pack("<I", host_slot)
    network += bytes.fromhex("ff542460")
    for slot, function_slot in ((0xA8, 0x70), (0xB8, 0x78), (0xE8, 0x80)):
        network += bytes.fromhex("488b842408020000488b80") + struct.pack("<I", slot)
        if function_slot < 0x80:
            network += bytes.fromhex("48894424") + bytes((function_slot,))
            if slot == 0xA8 and overwrite_indirect_api_slot == "rcx":
                network += bytes.fromhex("48894c24") + bytes((function_slot,))
            elif slot == 0xA8 and overwrite_indirect_api_slot == "immediate":
                network += bytes.fromhex("48c74424") + bytes((function_slot,))
                network += struct.pack("<I", 0x44332211)
            elif slot == 0xA8 and overwrite_indirect_api_slot == "other_register":
                network += bytes.fromhex("48895424") + bytes((function_slot,))
            if slot == 0xA8 and rebase_rsp_before_api_call:
                network += bytes.fromhex("4883ec204883c420")
            network += bytes.fromhex("ff5424") + bytes((function_slot,))
        else:
            network += bytes.fromhex("48898424") + struct.pack("<I", function_slot)
            network += bytes.fromhex("ff9424") + struct.pack("<I", function_slot)
    network += bytes.fromhex("4881c400020000c3")
    if dead_network_evidence:
        target = len(network) - 1
        struct.pack_into(
            "<i", network, dead_jump_offset, target - (dead_jump_offset + 4)
        )
    _put(blob, network_worker, bytes(network))

    caller = bytearray(bytes.fromhex("4c89442418488954241048894c24084881ec00010000"))
    caller += bytes.fromhex("488b8424100100004989c1")
    if clobber_r9d:
        caller += bytes.fromhex("41b911223344")
    caller += bytes.fromhex("4c8b842418010000")
    caller += bytes.fromhex("488b942410010000488b8c2408010000")
    caller += _call(network_caller + len(caller), network_worker)
    caller += bytes.fromhex("4881c400010000c3")
    _put(blob, network_caller, bytes(caller))

    parser_code = bytearray(bytes.fromhex("48894c24084881ec00040000"))
    if mutually_exclusive_parser_chain:
        parser_code += bytes.fromhex("85c00f84")
        conditional_displacement = len(parser_code)
        parser_code += b"\x00" * 4
        parser_code += bytes.fromhex("488d4c2440")
        parser_code += _call(parser + len(parser_code), initializer)
        parser_code += b"\xe9"
        branch_end_displacement = len(parser_code)
        parser_code += b"\x00" * 4
        decrypt_branch = len(parser_code)
        parser_code += bytes.fromhex("4c8d842400020000488b942410040000488d4c2440")
        parser_code += _call(parser + len(parser_code), decryptor)
        parser_code += bytes.fromhex("488b8424e00000004889442420")
        parser_code += bytes.fromhex("488d94240003000066b90202ff542420")
        parser_code += bytes.fromhex("4c8d442430488d942400020000488d4c2440")
        parser_code += _call(parser + len(parser_code), network_caller)
        branch_end = len(parser_code)
        parser_code[conditional_displacement : conditional_displacement + 4] = (
            _relative32(parser + conditional_displacement + 4, parser + decrypt_branch)
        )
        parser_code[branch_end_displacement : branch_end_displacement + 4] = (
            _relative32(parser + branch_end_displacement + 4, parser + branch_end)
        )
    else:
        parser_code += bytes.fromhex("488d4c2440")
        parser_code += _call(parser + len(parser_code), initializer)
        parser_code += bytes.fromhex("4c8d842400020000488b942410040000488d4c2440")
        parser_code += _call(parser + len(parser_code), decryptor)
        parser_code += bytes.fromhex("488b8424e00000004889442420")
        parser_code += bytes.fromhex("488d94240003000066b90202ff542420")
        parser_code += bytes.fromhex("4c8d442430488d942400020000488d4c2440")
        parser_code += _call(parser + len(parser_code), network_caller)
    parser_code += bytes.fromhex("4881c400040000c3")
    _put(blob, parser, bytes(parser_code))

    main_code = bytearray(bytes.fromhex("4883ec28"))
    main_code += _lea_rip(
        bytes.fromhex("488d0d"), main + len(main_code), container_offset
    )
    main_code += _call(main + len(main_code), parser)
    loop_address = main + len(main_code)
    main_code += b"\xe9" + _relative32(loop_address + 5, loop_address)
    _put(blob, main, bytes(main_code))
    _put(blob, 0, b"\xe9" + _relative32(5, main))
    return bytes(blob)


def _synthetic_members(
    *,
    corrupt_tag: bool = False,
    carrier_name: str = "fixture-carrier.txt",
    duplicate_carrier: bool = False,
) -> tuple[_CabMember, ...]:
    """同一CAB相当のruntime、script、carrierを合成する。"""

    runtime = bytearray(b"MZ" + b"\x00" * (256 * 1024 - 2))
    runtime[0x100 : 0x100 + len(b"AutoHotkey")] = b"AutoHotkey"
    runtime[0x200:0x214] = "AutoHotkey".encode("utf-16le")
    runtime[0x300:0x306] = b"2.0.26"
    script = b"""#Requires AutoHotkey v2.0
payloadPath := "C:\\Fixture\\fixture-carrier.txt"
fileData := LoadLineChunks(payloadPath)
execMem := DllCall("Kernel32\\VirtualAlloc", "Ptr", 0, "UPtr", fileData.Size)
DllCall("Kernel32\\RtlMoveMemory", "Ptr", execMem, "Ptr", fileData.Ptr, "UPtr", fileData.Size)
DllCall("Kernel32\\FlushInstructionCache", "Ptr", 0, "Ptr", execMem, "UPtr", fileData.Size)
hThread := DllCall("Kernel32\\CreateThread", "Ptr", 0, "Ptr", execMem)
DllCall("Kernel32\\WaitForSingleObject", "Ptr", hThread)
LoadLineChunks(path) {
 chunks := []
 Loop Read, path {
  text := RegExReplace(A_LoopReadLine, "\\s")
  chunk := DecodeBase64Url(text)
  chunks.Push(chunk)
 }
 totalSize := 0
 for _, chunk in chunks
  totalSize += chunk.Size
 data := Buffer(totalSize)
 offset := 0
 for _, chunk in chunks {
  DllCall("Kernel32\\RtlMoveMemory", "Ptr", data.Ptr + offset, "Ptr", chunk.Ptr, "UPtr", chunk.Size)
  offset += chunk.Size
 }
 return data
}
DecodeBase64Url(text) {
 text := StrReplace(StrReplace(text, "-", "+"), "_", "/")
 DllCall("Crypt32\\CryptStringToBinaryW")
 return Buffer(1)
}
"""
    carrier = base64.urlsafe_b64encode(
        _synthetic_shellcode(corrupt_tag=corrupt_tag)
    ).rstrip(b"=")
    members = [
        _CabMember("RUNTIME", "fixture-runtime.exe", bytes(runtime)),
        _CabMember("SCRIPT", "fixture.ahk", script),
        _CabMember("CARRIER", carrier_name, carrier),
    ]
    if duplicate_carrier:
        members.append(_CabMember("SECOND", "other-carrier.txt", carrier))
    return tuple(members)


def _synthetic_msi_table_streams() -> dict[str, bytes]:
    """File/Media/Cabinet結合を持つ決定論的MSI tableを合成する。"""

    values = (
        "File",
        "Component_",
        "FileName",
        "FileSize",
        "Version",
        "Language",
        "Attributes",
        "Sequence",
        "Media",
        "DiskId",
        "LastSequence",
        "DiskPrompt",
        "Cabinet",
        "VolumeLabel",
        "Source",
        "CARRIER",
        "COMPONENT",
        "SHORT.TXT|fixture-carrier.txt",
        "#fixture.cab",
    )
    identifiers = {value: index for index, value in enumerate(values, start=1)}
    string_data = b"".join(value.encode("utf-8") for value in values)
    string_pool = bytearray(struct.pack("<HH", 65001, 0))
    for value in values:
        string_pool += struct.pack("<HH", len(value.encode("utf-8")), 1)
    column_rows = tuple(
        ("File", number, name, kind)
        for number, (name, kind) in enumerate(
            zip(
                values[:8],
                (0xAD48, 0x8D48, 0x8FFF, 0x8104, 0x9D48, 0x9D14, 0x9502, 0x8104),
                strict=True,
            ),
            start=1,
        )
    ) + tuple(
        ("Media", number, name, kind)
        for number, (name, kind) in enumerate(
            zip(
                values[9:15],
                (0xA502, 0x8104, 0x9F40, 0x9DFF, 0x9D20, 0x9D48),
                strict=True,
            ),
            start=1,
        )
    )
    columns_by_field = tuple(
        tuple(
            identifiers[row[0]]
            if field == 0
            else row[1] ^ 0x8000
            if field == 1
            else identifiers[row[2]]
            if field == 2
            else row[3]
            for row in column_rows
        )
        for field in range(4)
    )
    columns = b"".join(
        struct.pack("<H", value) for field in columns_by_field for value in field
    )
    file_table = b"".join(
        (
            struct.pack("<H", identifiers["CARRIER"]),
            struct.pack("<H", identifiers["COMPONENT"]),
            struct.pack("<H", identifiers["SHORT.TXT|fixture-carrier.txt"]),
            struct.pack("<I", 12_345 ^ 0x80000000),
            struct.pack("<H", 0),
            struct.pack("<H", 0),
            struct.pack("<H", 0 ^ 0x8000),
            struct.pack("<I", 1 ^ 0x80000000),
        )
    )
    media_table = b"".join(
        (
            struct.pack("<H", 1 ^ 0x8000),
            struct.pack("<I", 1 ^ 0x80000000),
            struct.pack("<H", 0),
            struct.pack("<H", identifiers["#fixture.cab"]),
            struct.pack("<H", 0),
            struct.pack("<H", 0),
        )
    )
    return {
        "!_StringPool": bytes(string_pool),
        "!_StringData": string_data,
        "!_Tables": struct.pack("<HH", identifiers["File"], identifiers["Media"]),
        "!_Columns": columns,
        "!File": file_table,
        "!Media": media_table,
    }


def test_synthetic_structure_recovers_manual_endpoint_candidate() -> None:
    recovery = _recover_from_cab_members(
        _synthetic_members(),
        source_size=600_000,
        msi_schema_validated=True,
    )

    assert recovery is not None
    assert recovery.endpoint == "fixture.example.net:443"
    assert recovery.evidence["gcm_authentication_succeeded"] is True
    assert recovery.evidence["inner_schema_validated"] is True
    assert recovery.evidence["config_to_getaddrinfo_tcp_sink"] is False
    assert recovery.evidence["config_host_service_def_use"] is False
    assert (
        recovery.evidence["msi_component_directory_install_path_binding_proven"]
        is False
    )
    assert (
        recovery.evidence["ahk_cryptstring_decode_arguments_and_buffer_size_proven"]
        is False
    )
    assert recovery.auxiliary_lengths == (5, 0, 5)


def test_msi_file_table_binds_key_installed_name_and_size() -> None:
    records = _msi_file_records(_synthetic_msi_table_streams())

    assert records == {"CARRIER": _MsiFileRecord("fixture-carrier.txt", 12_345, 1)}


def test_media_table_binds_embedded_cabinet_and_file_sequence() -> None:
    streams = _synthetic_msi_table_streams()
    records = _msi_file_records(streams)

    assert records is not None
    media = _msi_media_record(streams, records)
    assert media is not None
    assert media.cabinet_stream == "fixture.cab"
    assert media.last_sequence == 1
    assert (
        _bound_msi_cabinet_stream(streams, records, ("fixture.cab",)) == "fixture.cab"
    )


def test_media_cabinet_missing_mismatch_and_decoy_are_rejected() -> None:
    streams = _synthetic_msi_table_streams()
    records = _msi_file_records(streams)

    assert records is not None
    assert _bound_msi_cabinet_stream(streams, records, ()) is None
    assert _bound_msi_cabinet_stream(streams, records, ("other.cab",)) is None
    assert (
        _bound_msi_cabinet_stream(
            streams,
            records,
            ("fixture.cab", "decoy.cab"),
        )
        is None
    )

    without_media = dict(streams)
    without_media.pop("!Media")
    assert _bound_msi_cabinet_stream(without_media, records, ("fixture.cab",)) is None


def test_msi_file_table_rejects_modified_schema() -> None:
    streams = _synthetic_msi_table_streams()
    columns = bytearray(streams["!_Columns"])
    row_count = len(columns) // 8
    struct.pack_into("<H", columns, 2 * (2 * row_count + 3), 5)
    streams["!_Columns"] = bytes(columns)

    assert _msi_file_records(streams) is None


def test_cab_members_without_validated_msi_schema_are_rejected() -> None:
    recovery = _recover_from_cab_members(
        _synthetic_members(),
        source_size=600_000,
        msi_schema_validated=False,
    )

    assert recovery is None


def test_gcm_tag_tamper_is_fail_closed() -> None:
    recovery = _recover_from_cab_members(
        _synthetic_members(corrupt_tag=True),
        source_size=600_000,
        msi_schema_validated=True,
    )

    assert recovery is None


def test_shellcode_requires_network_sink_lineage() -> None:
    shellcode = _synthetic_shellcode(dead_network_evidence=True)

    assert _recover_shellcode(shellcode) is None


def test_dead_code_after_unconditional_jump_is_not_evidence() -> None:
    shellcode = _synthetic_shellcode(dead_network_evidence=True)

    assert _recover_shellcode(shellcode) is None


def test_replaced_getaddrinfo_hash_is_rejected() -> None:
    shellcode = _synthetic_shellcode(replace_getaddrinfo_hash=True)

    assert _recover_shellcode(shellcode) is None


def test_disconnected_config_to_getaddrinfo_argument_is_rejected() -> None:
    shellcode = _synthetic_shellcode(break_config_argument_flow=True)

    assert _recover_shellcode(shellcode) is None


def test_mutually_exclusive_parser_chain_is_rejected() -> None:
    shellcode = _synthetic_shellcode(mutually_exclusive_parser_chain=True)

    assert _recover_shellcode(shellcode) is None


def test_mutually_exclusive_decryptor_evidence_is_rejected() -> None:
    shellcode = _synthetic_shellcode(mutually_exclusive_decryptor_chain=True)

    assert _recover_shellcode(shellcode) is None


def test_r9d_partial_write_kills_r9_config_source() -> None:
    shellcode = _synthetic_shellcode(clobber_r9d=True)

    assert _recover_shellcode(shellcode) is None


def test_indirect_api_slot_overwrite_kills_resolved_identity() -> None:
    for overwrite in ("rcx", "immediate", "other_register"):
        shellcode = _synthetic_shellcode(overwrite_indirect_api_slot=overwrite)
        assert _recover_shellcode(shellcode) is None


def test_rsp_rebase_kills_indirect_api_slot_identity() -> None:
    shellcode = _synthetic_shellcode(rebase_rsp_before_api_call=True)

    assert _recover_shellcode(shellcode) is None


def test_rsp_basis_change_aliases_are_rejected() -> None:
    opcodes = (
        bytes.fromhex("50"),
        bytes.fromhex("58"),
        bytes.fromhex("4883ec20"),
        bytes.fromhex("4883c420"),
        bytes.fromhex("488d642420"),
        bytes.fromhex("4889c4"),
        bytes.fromhex("89c4"),
        bytes.fromhex("4894"),
    )
    for opcode in opcodes:
        graph = _function_instructions(opcode + b"\xc3", 0)
        assert graph is not None
        assert _changes_rsp_basis(graph.instructions[0]) is True


def test_ahk_comment_only_markers_are_rejected() -> None:
    valid = _synthetic_members()[1].data.decode("utf-8")
    path_line = 'payloadPath := "C:\\Fixture\\fixture-carrier.txt"'
    line_commented = (
        path_line + "\n" + "\n".join("; " + line for line in valid.splitlines())
    )
    block_commented = path_line + "\n/*\n" + valid + "\n*/\n"

    assert _ahk_script(line_commented.encode()) is None
    assert _ahk_script(block_commented.encode()) is None


def test_ahk_comment_tokens_inside_string_literal_are_preserved() -> None:
    valid = _synthetic_members()[1].data.replace(
        b"fixture-carrier.txt",
        b"fixture;carrier.txt",
        1,
    )

    profile = _ahk_script(valid)
    assert profile is not None
    assert profile.carrier_basename == "fixture;carrier.txt"


def test_ahk_invalid_inline_comment_tokens_do_not_create_valid_statements() -> None:
    valid = _synthetic_members()[1].data.decode("utf-8")
    path_line = 'payloadPath := "C:\\Fixture\\fixture-carrier.txt"'
    inline_semicolon = valid.replace(path_line, path_line + ";not-a-comment", 1)
    inline_block = valid.replace(
        path_line,
        path_line + "/*not-a-line-boundary\n*/",
        1,
    )

    assert _ahk_script(inline_semicolon.encode()) is None
    assert _ahk_script(inline_block.encode()) is None


def test_script_carrier_filename_mismatch_is_rejected() -> None:
    recovery = _recover_from_cab_members(
        _synthetic_members(carrier_name="renamed-carrier.txt"),
        source_size=600_000,
        msi_schema_validated=True,
    )

    assert recovery is None


def test_multiple_terminal_carriers_are_rejected() -> None:
    recovery = _recover_from_cab_members(
        _synthetic_members(duplicate_carrier=True),
        source_size=600_000,
        msi_schema_validated=True,
    )

    assert recovery is None


def test_public_summary_hides_crypto_material_and_network_value() -> None:
    recovery = _recover_from_cab_members(
        _synthetic_members(),
        source_size=600_000,
        msi_schema_validated=True,
    )

    assert recovery is not None
    summary = public_recovery_summary(recovery)
    assert summary["status"] == "manual_unverified_route_config_candidate"
    assert summary["candidate_only"] is True
    assert summary["automatic_route_eligible"] is False
    assert summary["supports_family_attribution"] is False
    assert summary["terminal_family_confirmed"] is False
    assert summary["static_config_recovered"] is False
    assert summary["c2_confirmed"] is False
    assert summary["command_c2_confirmed"] is False
    assert summary["qualified"] is False
    assert summary["used_for_resolution"] is False
    assert summary["used_for_family_resolution"] is False
    assert summary["used_for_c2_confirmation"] is False
    assert summary["configured_endpoint_count"] == 0
    assert summary["candidate_endpoint_count"] == 1
    assert summary["evidence_boundary"]["all_expected_fields_validated"] is False
    assert summary["raw_key_included"] is False
    assert summary["raw_nonce_included"] is False
    assert summary["raw_tag_included"] is False
    assert summary["raw_config_included"] is False
    assert summary["network_values_included"] is False
    assert "fixture.example.net" not in repr(summary)


def test_probe_rejects_non_msi_without_network_value() -> None:
    probe = probe_msi_ahk_aes_gcm(b"not-an-msi")

    assert probe["matched"] is False
    assert probe["candidate_recovered"] is False
    assert probe["automatic_route_eligible"] is False
    assert probe["supports_family_attribution"] is False
    assert probe["static_config_recovered"] is False
    assert probe["c2_confirmed"] is False
    assert probe["qualified"] is False
    assert probe["used_for_resolution"] is False
    assert probe["used_for_family_resolution"] is False
    assert probe["used_for_c2_confirmation"] is False
    assert probe["endpoint_count"] == 0
    assert "fixture.example.net" not in repr(probe)
