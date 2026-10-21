"""ZIPサイドロード用raw vvaS shellcode parserの汎化境界を検証する。"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
from types import SimpleNamespace

import pytest

import extractors.valleyrat.zip_sideload_shellcode as zip_shellcode
from extractors.valleyrat.extractor import _extract_raw_vvas_transport_shellcode
from extractors.valleyrat.zip_sideload_shellcode import (
    _ArchiveMember,
    _single_byte_xor_terminal,
    probe_raw_vvas_shellcode,
    probe_zip_sideload_shellcode,
    public_raw_shellcode_summary,
    recover_raw_vvas_shellcode,
    recover_zip_sideload_shellcode,
    recover_zip_sideload_shellcode_route,
)


def _synthetic_zip(records: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in records:
            archive.writestr(name, payload)
    return stream.getvalue()


def _copy_zip_with_records(
    data: bytes,
    records: list[tuple[str, bytes]],
) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(data))
    stream = io.BytesIO()
    with source, zipfile.ZipFile(
        stream,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as destination:
        for info in source.infolist():
            destination.writestr(info, source.read(info))
        for name, payload in records:
            destination.writestr(name, payload)
    return stream.getvalue()


def _zip64_eocd_with_declared_count(count: int) -> bytes:
    record = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        0,
        0,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, 0, 1)
    eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return record + locator + eocd


def _synthetic_shellcode(*, second_host: str = "198.51.100.27") -> bytes:
    """実検体値を含まない構造合成fixtureを返す。"""

    code = bytearray()
    code += bytes.fromhex("64a130000000")
    code += bytes.fromhex("685773325f")
    code += bytes.fromhex("6833322e64")
    code += bytes.fromhex("66686c6c")
    code += bytes.fromhex("6802020000")
    code += bytes.fromhex("6a066a016a02")
    code += bytes.fromhex("6833320000")
    code += bytes.fromhex("6a40")
    code += bytes.fromhex("6800300000")
    code += bytes.fromhex("ffd0") * 8
    for value in b"codemark":
        code += bytes((0x80, 0x7D, 0xFC, value))
    code += b"\x90" * (512 - len(code))

    first_host = "198.51.100.27"
    header = (
        b"codemark"
        + b"\0" * 0x18
        + struct.pack(
            "<IIIIII",
            len(first_host) + 1,
            443,
            1,
            len(second_host) + 1,
            0,
            1,
        )
        + first_host.encode("ascii")
        + b"\0"
        + second_host.encode("ascii")
        + b"\0"
    )
    config = (
        f"|p1:{first_host}|o1:0443|t1:1"
        f"|p2:{second_host}|o2:|t2:1"
        "|p3:127.0.0.1|o3:80|t3:1|"
    )
    return bytes(code) + header + config[::-1].encode("utf-16le")


def _synthetic_odaktomk_shellcode() -> bytes:
    """odaktomk resolver/hash variantを実値なしで構造合成する。"""

    code = bytearray(bytes.fromhex("64a118000000908b4030"))
    code += bytes.fromhex("685773325f6833322e6466686c6c")
    for value in (
        0x0148BE54,
        0x00293836,
        0x5EC13A5A,
        0xC18BC488,
        0x9816ABED,
        0xABCE366B,
        0xF9B83296,
        0x039BB598,
        0xF4178B7A,
    ):
        code += b"\x68" + struct.pack("<I", value)
    code += bytes.fromhex("68020200006a066a016a0268333200006a406800300000")
    code += b"\x68" + struct.pack("<I", 0x4B00E)
    code += b"\x68" + struct.pack("<I", 0x9D)
    code += bytes.fromhex("ffd0") * 8
    for value in b"odaktomk":
        code += bytes((0x80, 0x7D, 0xFC, value))
    code += b"\x90" * (512 - len(code))

    first_host = "198.51.100.27"
    second_host = "203.0.113.41"
    header = (
        b"odaktomk"
        + b"\0" * 0x18
        + struct.pack(
            "<IIIIII",
            len(first_host) + 1,
            443,
            1,
            len(second_host) + 1,
            8443,
            1,
        )
        + first_host.encode("ascii")
        + b"\0"
        + second_host.encode("ascii")
        + b"\0"
    )
    config = (
        f"|p1:{first_host}|o1:0443|t1:1"
        f"|p2:{second_host}|o2:8443|t2:1"
        "|v3:127.0.0.1|o3:80|t3:1|"
    )
    return bytes(code) + header + config[::-1].encode("utf-16le")


def test_zip_reader_caps_all_central_directory_records_including_directories() -> None:
    accepted = _synthetic_zip(
        [(f"directory-{index}/", b"") for index in range(125)]
        + [("host.exe", b"MZ"), ("loader.dll", b"MZ"), ("carrier.bin", b"x")]
    )
    members = zip_shellcode._read_archive_members(accepted)
    assert len(members) == zip_shellcode.MAXIMUM_MEMBER_COUNT
    assert sum(bool(member.data) for member in members) == 3

    rejected = _synthetic_zip(
        [(f"directory-{index}/", b"") for index in range(126)]
        + [("host.exe", b"MZ"), ("loader.dll", b"MZ"), ("carrier.bin", b"x")]
    )
    with pytest.raises(zip_shellcode.ZipSideloadShellcodeError):
        zip_shellcode._read_archive_members(rejected)


def test_zip_reader_rejects_oversized_zip64_count_before_archive_open(
    monkeypatch,
) -> None:
    data = _zip64_eocd_with_declared_count(
        zip_shellcode.MAXIMUM_MEMBER_COUNT + 1
    )

    def unexpected_open(*_args, **_kwargs):
        raise AssertionError("entry count上限超過後にZipFileを開いてはいけません")

    monkeypatch.setattr(zip_shellcode.zipfile, "ZipFile", unexpected_open)
    with pytest.raises(zip_shellcode.ZipSideloadShellcodeError):
        zip_shellcode._read_archive_members(data)


def test_zip_reader_counts_actual_directory_records_before_archive_open(
    monkeypatch,
) -> None:
    data = bytearray(
        _synthetic_zip(
            [(f"directory-{index}/", b"") for index in range(129)]
        )
    )
    eocd_offset = data.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    struct.pack_into("<HH", data, eocd_offset + 8, 1, 1)

    def unexpected_open(*_args, **_kwargs):
        raise AssertionError("実record上限超過後にZipFileを開いてはいけません")

    monkeypatch.setattr(zip_shellcode.zipfile, "ZipFile", unexpected_open)
    with pytest.raises(zip_shellcode.ZipSideloadShellcodeError):
        zip_shellcode._read_archive_members(bytes(data))


@pytest.mark.parametrize(
    "records",
    [
        [("Ａ.txt", b"a"), ("A.txt", b"b")],
        [("item.txt", b"a"), ("item.txt.", b"b")],
        [("item.txt", b"a"), ("item.txt:stream", b"b")],
        [("tree", b"a"), ("tree/child.bin", b"b")],
        [("host.exe/", b""), ("host.exe", b"MZ")],
        [("con.txt", b"a")],
    ],
)
def test_zip_reader_rejects_windows_namespace_aliases_and_collisions(
    records: list[tuple[str, bytes]],
) -> None:
    with pytest.raises(zip_shellcode.ZipSideloadShellcodeError):
        zip_shellcode._read_archive_members(_synthetic_zip(records))


def test_raw_shellcode_accepts_zero_padded_primary_and_excludes_defaults() -> None:
    data = _synthetic_shellcode()

    recovery = recover_raw_vvas_shellcode(data)

    assert recovery is not None
    assert recovery.endpoints == ("198.51.100.27:443",)
    assert [slot["state"] for slot in recovery.endpoint_slots] == [
        "configured_external",
        "incomplete_backup_without_port",
        "placeholder",
    ]
    assert recovery.shellcode_evidence["required_groups"] == {
        "bounded_cfg_complete": True,
        "instruction_floor": True,
        "instruction_coverage": True,
        "peb_fs30_resolver": True,
        "codemark_byte_compare": True,
        "winsock_library_constructed": True,
        "wsa_startup_version": True,
        "tcp_socket_arguments": True,
        "vvas_checkin_literal": True,
        "executable_allocation_constants": True,
        "indirect_api_calls": True,
    }


def test_raw_shellcode_rejects_portless_nonduplicate_backup() -> None:
    assert (
        recover_raw_vvas_shellcode(_synthetic_shellcode(second_host="backup.example"))
        is None
    )


def test_raw_probe_is_route_only_and_hides_network_values() -> None:
    probe = probe_raw_vvas_shellcode(_synthetic_shellcode())

    assert probe["matched"] is True
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["candidate_config_recovered"] is True
    assert probe["config"] == {
        "endpoint_count": 1,
        "raw_config_included": False,
        "raw_network_values_included": False,
    }
    assert "198.51.100.27" not in repr(probe)


def test_public_shellcode_summary_omits_target_derived_hashes() -> None:
    """artifact整合性は共通層へ委譲し、component/config SHAを公開しない。"""

    recovery = recover_raw_vvas_shellcode(_synthetic_shellcode())

    assert recovery is not None
    summary = public_raw_shellcode_summary(recovery)
    assert summary["shellcode_integrity_hash_included"] is False
    assert summary["configuration_identity_included"] is False
    assert "shellcode_sha256" not in summary
    assert "configuration_identity_sha256" not in summary


def test_raw_vvas_route_result_omits_configuration_identity_hash() -> None:
    result = _extract_raw_vvas_transport_shellcode(
        _synthetic_shellcode(),
        "synthetic.bin",
    )

    assert result is not None
    assert "configuration_identity_sha256" not in result["config"]


def test_odaktomk_variant_accepts_exclusive_v3_alias() -> None:
    recovery = recover_raw_vvas_shellcode(_synthetic_odaktomk_shellcode())

    assert recovery is not None
    assert recovery.endpoints == (
        "198.51.100.27:443",
        "203.0.113.41:8443",
    )
    assert recovery.endpoint_slots[2]["state"] == "placeholder"
    assert recovery.shellcode_evidence["marker_variant"] == "odaktomk"
    assert all(recovery.shellcode_evidence["required_groups"].values())


def test_single_byte_xor_carrier_requires_complete_terminal_structure() -> None:
    payload = _synthetic_odaktomk_shellcode()
    encrypted = bytes(byte ^ 0x5A for byte in payload)
    carrier = _ArchiveMember("carrier.bin", "", "carrier.bin", encrypted)

    recovery = _single_byte_xor_terminal(carrier, 0x5A)

    assert recovery is not None
    assert recovery.endpoints == (
        "198.51.100.27:443",
        "203.0.113.41:8443",
    )

    marker_only = b"A" * 700 + b"odaktomk" + b"B" * 700
    encrypted_marker_only = bytes(byte ^ 0x5A for byte in marker_only)
    rejected = _ArchiveMember(
        "candidate.bin", "", "candidate.bin", encrypted_marker_only
    )
    assert _single_byte_xor_terminal(rejected, 0x5A) is None
    assert _single_byte_xor_terminal(carrier, 0x59) is None


class _X86Builder:
    """strict loader fixtureに必要な最小x86 bytecodeを構築する。"""

    def __init__(self, base: int) -> None:
        self.base = base
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.rel8: list[tuple[int, str]] = []
        self.rel32: list[tuple[int, str]] = []

    def emit(self, value: bytes) -> None:
        self.code.extend(value)

    def label(self, name: str) -> None:
        self.labels[name] = len(self.code)

    def branch8(self, opcode: int, label: str) -> None:
        self.emit(bytes((opcode, 0)))
        self.rel8.append((len(self.code) - 1, label))

    def call_label(self, label: str) -> None:
        self.emit(b"\xe8\0\0\0\0")
        self.rel32.append((len(self.code) - 4, label))

    def finish(self) -> bytes:
        for offset, label in self.rel8:
            displacement = self.labels[label] - (offset + 1)
            assert -128 <= displacement <= 127
            self.code[offset] = displacement & 0xFF
        for offset, label in self.rel32:
            displacement = self.labels[label] - (offset + 4)
            struct.pack_into("<i", self.code, offset, displacement)
        return bytes(self.code)


def _strict_loader_bundle(
    monkeypatch,
    *,
    carrier_key_delta: int = 0,
    wrong_write_api: bool = False,
    wrong_creation_flag_position: bool = False,
    split_injection_function: bool = False,
    wrong_injection_order: bool = False,
    clobber_resolver_return: bool = False,
    duplicate_key_lineage: bool = False,
    duplicate_xor_lineage: bool = False,
    duplicate_context_write: bool = False,
    clobber_allocation_return: bool = False,
    self_zero_vector_xor: bool = False,
    weak_file_read_lineage: bool = False,
    cpp_stream_lineage: bool = False,
    immediate_basename_mismatch: bool = False,
    stream_buffer_mismatch: bool = False,
    stream_object_mismatch: bool = False,
    stream_success_mode: str = "read_result",
) -> bytes:
    """秘密値を持たないZIP・loader・carrierの合成fixtureを返す。"""

    image_base = 0x400000
    code_rva = 0x1000
    data_rva = 0x3000
    code_va = image_base + code_rva
    data_va = image_base + data_rva
    carrier_name_va = data_va + 0x100
    key_module_va = data_va + 0x120
    process_name_va = data_va + 0x140
    write_module_va = data_va + 0x160
    write_api_va = data_va + 0x180
    buffer_global = data_va + 0x600
    length_global = data_va + 0x604
    api_names = (
        "GetModuleHandleA",
        "GetModuleFileNameA",
        "CreateFileA",
        "GetFileSize",
        "ReadFile",
        "VirtualAlloc",
        "CreateProcessA",
        "GetThreadContext",
        "VirtualAllocEx",
        "GetProcAddress",
        "SetThreadContext",
        "ResumeThread",
    )
    api_addresses = {
        name: data_va + 0x800 + index * 4
        for index, name in enumerate(api_names)
    }

    builder = _X86Builder(code_va)

    def call_iat(name: str) -> None:
        builder.emit(bytes.fromhex("ff15") + struct.pack("<I", api_addresses[name]))

    def emit_key_derivation(suffix: str) -> None:
        builder.emit(b"\x68" + struct.pack("<I", key_module_va))
        call_iat("GetModuleHandleA")
        builder.emit(bytes.fromhex("6804010000"))
        builder.emit(bytes.fromhex("8d8d00ffffff51"))
        builder.emit(b"\x50")
        call_iat("GetModuleFileNameA")
        builder.emit(bytes.fromhex("8d8d00ffffff8d5101"))
        builder.label(f"nul_scan_{suffix}")
        builder.emit(bytes.fromhex("8a014184c0"))
        builder.branch8(0x75, f"nul_scan_{suffix}")
        builder.emit(bytes.fromhex("8b35") + struct.pack("<I", buffer_global))
        builder.emit(bytes.fromhex("2bca"))
        builder.emit(bytes.fromhex("8b15") + struct.pack("<I", length_global))
        builder.emit(bytes.fromhex("8955e0"))
        builder.emit(bytes.fromhex("0fbe840dfdfeffff"))
        builder.emit(bytes.fromhex("83e8308945fc"))

    def emit_xor_lineage(
        suffix: str,
        *,
        reload_key: bool = False,
        self_zero: bool = False,
    ) -> None:
        if reload_key:
            builder.emit(bytes.fromhex("8b45fc"))
        builder.emit(bytes.fromhex("660f6ec0660f70c000"))
        builder.emit(bytes.fromhex("660f67c0660f67c0"))
        builder.emit(bytes.fromhex("8d4608"))
        builder.emit(bytes.fromhex("0f2985c0feffff8bbdc0feffff"))
        if self_zero:
            builder.emit(bytes.fromhex("0f57c0") * 4)
        else:
            for encoded_offset in ("48f8", "48fc", "08", "4804"):
                builder.emit(bytes.fromhex("660f6e" + encoded_offset))
                builder.emit(bytes.fromhex("660f6ec70f57c8"))
                builder.emit(bytes.fromhex("660f7e" + encoded_offset))
        builder.label(f"scalar_xor_{suffix}")
        builder.emit(bytes.fromhex("8b55fc8d040e3010413b4de0"))
        builder.branch8(0x7C, f"scalar_xor_{suffix}")

    carrier_basename = "unit.bin" if cpp_stream_lineage else "carrier.bin"
    builder.emit(b"\x90" * 260)
    if not cpp_stream_lineage:
        builder.emit(b"\xa1" + struct.pack("<I", carrier_name_va))
        builder.emit(bytes.fromhex("8907"))
    if cpp_stream_lineage:
        stream_displacement = -0x200
        read_stream_displacement = (
            -0x240 if stream_object_mismatch else stream_displacement
        )
        built_basename = (
            "fake.bin" if immediate_basename_mismatch else carrier_basename
        ).encode("ascii") + b"\0"
        assert len(built_basename) == 9
        builder.emit(bytes.fromhex("8dbd60feffff"))
        builder.emit(bytes.fromhex("89bd60feffff"))
        builder.emit(bytes.fromhex("b904000000"))
        builder.emit(bytes.fromhex("c7040f") + built_basename[:4])
        builder.emit(bytes.fromhex("c7440f04") + built_basename[4:8])
        builder.emit(bytes.fromhex("c6440f08") + built_basename[8:9])
        builder.emit(bytes.fromhex("8d8560feffff83f9100f478560feffff"))
        builder.emit(bytes.fromhex("6a0150"))
        builder.emit(bytes.fromhex("8d8d00feffff"))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500100 - (code_va + len(builder.code) + 5))
        )
        builder.emit(bytes.fromhex("8d85e0fdffff50"))
        builder.emit(bytes.fromhex("8d8d00feffff"))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500120 - (code_va + len(builder.code) + 5))
        )
        builder.emit(bytes.fromhex("8b500803108b480c134804"))
        builder.emit(bytes.fromhex("52"))
        builder.emit(bytes.fromhex("8915") + struct.pack("<I", length_global))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500140 - (code_va + len(builder.code) + 5))
        )
        builder.emit(b"\xa3" + struct.pack("<I", buffer_global))
        builder.emit(bytes.fromhex("6a006a006a00"))
        builder.emit(bytes.fromhex("8d8d00feffff"))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500160 - (code_va + len(builder.code) + 5))
        )
        builder.emit(bytes.fromhex("6a00"))
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
        builder.emit(
            bytes.fromhex("8d8d")
            + struct.pack("<i", read_stream_displacement)
        )
        read_buffer = buffer_global + 8 if stream_buffer_mismatch else buffer_global
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", read_buffer))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500180 - (code_va + len(builder.code) + 5))
        )
        if stream_success_mode == "read_result":
            builder.emit(bytes.fromhex("85c0"))
        elif stream_success_mode == "unrelated_register":
            builder.emit(bytes.fromhex("39d2"))
        elif stream_success_mode == "clobbered_result":
            builder.emit(bytes.fromhex("31c085c0"))
        else:
            raise AssertionError("未知のstream success fixture modeです")
        builder.branch8(0x75, "stream_read_ok")
        builder.label("stream_read_ok")
    elif weak_file_read_lineage:
        builder.emit(bytes.fromhex("890d") + struct.pack("<I", length_global))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500000 - (code_va + len(builder.code) + 5))
        )
        builder.emit(b"\xa3" + struct.pack("<I", buffer_global))
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", buffer_global))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500020 - (code_va + len(builder.code) + 5))
        )
    else:
        builder.emit(bytes.fromhex("6a0068800000006a036a006a01"))
        builder.emit(b"\x68" + struct.pack("<I", 0x80000000))
        builder.emit(b"\x57")
        call_iat("CreateFileA")
        builder.emit(bytes.fromhex("8bd8"))
        builder.emit(bytes.fromhex("6a0053"))
        call_iat("GetFileSize")
        builder.emit(b"\xa3" + struct.pack("<I", length_global))
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
        builder.emit(
            b"\xe8"
            + struct.pack("<i", 0x500000 - (code_va + len(builder.code) + 5))
        )
        builder.emit(b"\xa3" + struct.pack("<I", buffer_global))
        builder.emit(bytes.fromhex("6a006a00"))
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
        builder.emit(bytes.fromhex("ff35") + struct.pack("<I", buffer_global))
        builder.emit(b"\x53")
        call_iat("ReadFile")
    emit_key_derivation("primary")
    if duplicate_key_lineage:
        emit_key_derivation("decoy")
    emit_xor_lineage("primary", self_zero=self_zero_vector_xor)
    if duplicate_xor_lineage:
        emit_xor_lineage("decoy", reload_key=True)

    if split_injection_function:
        builder.call_label("injection")
        builder.emit(b"\xc3")
        builder.label("injection")

    builder.emit(bytes.fromhex("6a406800300000"))
    builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
    builder.emit(bytes.fromhex("6a00"))
    call_iat("VirtualAlloc")
    if clobber_allocation_return:
        builder.emit(
            b"\xe8"
            + struct.pack(
                "<i",
                0x500080 - (code_va + len(builder.code) + 5),
            )
        )
    builder.emit(bytes.fromhex("8bf0"))
    builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
    builder.emit(bytes.fromhex("ff35") + struct.pack("<I", buffer_global))
    builder.emit(b"\x56")
    builder.emit(b"\xe8" + struct.pack("<i", 0x500040 - (code_va + len(builder.code) + 5)))
    if wrong_injection_order:
        builder.emit(bytes.fromhex("8d8500feffff50ff75c0"))
        call_iat("GetThreadContext")
    builder.emit(bytes.fromhex("8d45bc508d8578feffff50"))
    if wrong_creation_flag_position:
        builder.emit(bytes.fromhex("6a006a046a006a006a006a00"))
    else:
        builder.emit(bytes.fromhex("6a006a006a046a006a006a00"))
    builder.emit(b"\x68" + struct.pack("<I", process_name_va))
    builder.emit(bytes.fromhex("6a00"))
    call_iat("CreateProcessA")
    if not wrong_injection_order:
        builder.emit(bytes.fromhex("8d8500feffff50ff75c0"))
        call_iat("GetThreadContext")
    builder.emit(bytes.fromhex("6a406800300000"))
    builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
    builder.emit(bytes.fromhex("6a00ff75bc"))
    call_iat("VirtualAllocEx")
    builder.emit(bytes.fromhex("8bf8"))
    builder.emit(b"\x68" + struct.pack("<I", write_module_va))
    call_iat("GetModuleHandleA")
    builder.emit(b"\x68" + struct.pack("<I", write_api_va))
    builder.emit(b"\x50")
    call_iat("GetProcAddress")
    if clobber_resolver_return:
        builder.emit(
            b"\xe8"
            + struct.pack(
                "<i",
                0x500060 - (code_va + len(builder.code) + 5),
            )
        )
    builder.emit(bytes.fromhex("6a00"))
    builder.emit(bytes.fromhex("ff35") + struct.pack("<I", length_global))
    builder.emit(bytes.fromhex("5657ff75bcffd0"))
    builder.emit(bytes.fromhex("89bdb8feffff"))
    if duplicate_context_write:
        builder.emit(bytes.fromhex("89bdb8feffff"))
    builder.emit(bytes.fromhex("8d8500feffff50ff75c0"))
    call_iat("SetThreadContext")
    builder.emit(bytes.fromhex("ff75c0"))
    call_iat("ResumeThread")
    builder.emit(b"\xc3")
    code = builder.finish()

    raw = bytearray(0x3000)
    raw[:2] = b"MZ"
    raw[0x200 : 0x200 + len(code)] = code
    strings = {
        0x2120: b"kernel32.dll\0",
        0x2140: b"rundll32.exe\0",
        0x2160: b"ntdll.dll\0",
        0x2180: (
            b"NtReadVirtualMemory\0"
            if wrong_write_api
            else b"NtWriteVirtualMemory\0"
        ),
    }
    if not cpp_stream_lineage:
        strings[0x2100] = b"carrier.bin\0"
    for offset, value in strings.items():
        raw[offset : offset + len(value)] = value

    executable_section = SimpleNamespace(
        PointerToRawData=0x200,
        SizeOfRawData=0x1800,
        VirtualAddress=code_rva,
        Misc_VirtualSize=0x1800,
        Characteristics=0x20000000,
    )
    data_section = SimpleNamespace(
        PointerToRawData=0x2000,
        SizeOfRawData=0x1000,
        VirtualAddress=data_rva,
        Misc_VirtualSize=0x1000,
        Characteristics=0x40000000,
    )
    descriptor = SimpleNamespace(
        dll=b"KERNEL32.dll",
        imports=[
            SimpleNamespace(
                address=api_addresses[name],
                name=name.encode("ascii"),
                ordinal=None,
            )
            for name in api_names
        ],
    )
    loader_image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=code_rva),
        sections=[executable_section, data_section],
        DIRECTORY_ENTRY_IMPORT=[descriptor],
    )
    imported_symbols = tuple(
        zip_shellcode._ImportedSymbol(name, None)
        for name in ("first", "second", "third")
    )

    def fake_parse(member: _ArchiveMember):
        if member.basename == "host.exe":
            return zip_shellcode._PeMember(
                member=member,
                image=SimpleNamespace(),
                image_base=image_base,
                machine=0x14C,
                is_dll=False,
                imports={"loader.dll": imported_symbols},
                export_names=frozenset(),
                export_ordinals=frozenset(),
            )
        if member.basename == "loader.dll":
            return zip_shellcode._PeMember(
                member=member,
                image=loader_image,
                image_base=image_base,
                machine=0x14C,
                is_dll=True,
                imports={},
                export_names=frozenset(item.name for item in imported_symbols),
                export_ordinals=frozenset(),
            )
        return None

    monkeypatch.setattr(zip_shellcode, "_parse_pe_member", fake_parse)
    terminal = _synthetic_odaktomk_shellcode()
    loader_key = ord("D") - ord("0")
    carrier_key = (loader_key + carrier_key_delta) & 0xFF
    encrypted = bytes(value ^ carrier_key for value in terminal)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("host.exe", b"MZ-host")
        archive.writestr("loader.dll", bytes(raw))
        archive.writestr(carrier_basename, encrypted)
    return stream.getvalue()


def test_direct_xor_end_to_end_zip_requires_loader_key_and_injection(
    monkeypatch,
) -> None:
    data = _strict_loader_bundle(monkeypatch)
    recovery = recover_zip_sideload_shellcode(data)

    assert isinstance(recovery, zip_shellcode.ZipDirectXorShellcodeRecovery)
    assert recover_zip_sideload_shellcode_route(data) is None
    assert recovery.shellcode.shellcode_evidence["marker_variant"] == "odaktomk"
    assert recovery.xor_evidence["derived_key_matches_carrier_transform"] is True
    assert recovery.xor_evidence["dominator_ordered_injection_path"] is True


def test_direct_xor_accepts_immediate_basename_and_cpp_stream_handoff(
    monkeypatch,
) -> None:
    recovery = recover_zip_sideload_shellcode(
        _strict_loader_bundle(monkeypatch, cpp_stream_lineage=True)
    )

    assert isinstance(recovery, zip_shellcode.ZipDirectXorShellcodeRecovery)
    assert recovery.xor_evidence["carrier_read_lineage_mode"] == "cpp_stream"
    assert recovery.xor_evidence["carrier_immediate_built_basename_dataflow"] is True
    assert (
        recovery.xor_evidence["carrier_cpp_stream_open_size_buffer_read_dataflow"]
        is True
    )
    assert recovery.xor_evidence["carrier_createfile_getfilesize_readfile_dataflow"] is False


def test_direct_xor_reports_complete_central_directory_record_count(
    monkeypatch,
) -> None:
    data = _copy_zip_with_records(
        _strict_loader_bundle(monkeypatch),
        [("support/", b"")],
    )

    recovery = recover_zip_sideload_shellcode(data)

    assert isinstance(recovery, zip_shellcode.ZipDirectXorShellcodeRecovery)
    assert recovery.member_count == 4


def test_direct_xor_rejects_mismatched_immediate_basename(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(
                monkeypatch,
                cpp_stream_lineage=True,
                immediate_basename_mismatch=True,
            )
        )
        is None
    )


def test_direct_xor_rejects_cpp_stream_buffer_mismatch(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(
                monkeypatch,
                cpp_stream_lineage=True,
                stream_buffer_mismatch=True,
            )
        )
        is None
    )


def test_direct_xor_rejects_cpp_stream_object_mismatch(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(
                monkeypatch,
                cpp_stream_lineage=True,
                stream_object_mismatch=True,
            )
        )
        is None
    )


@pytest.mark.parametrize(
    "stream_success_mode",
    ["unrelated_register", "clobbered_result"],
)
def test_direct_xor_rejects_cpp_stream_success_check_without_read_result_dataflow(
    monkeypatch,
    stream_success_mode: str,
) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(
                monkeypatch,
                cpp_stream_lineage=True,
                stream_success_mode=stream_success_mode,
            )
        )
        is None
    )


def test_direct_xor_zip_rejects_loader_and_carrier_key_mismatch(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, carrier_key_delta=1)
        )
        is None
    )


def test_direct_xor_zip_rejects_injection_split_into_another_function(
    monkeypatch,
) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, split_injection_function=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_injection_api_order_from_another_path(
    monkeypatch,
) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, wrong_injection_order=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_wrong_remote_write_api(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, wrong_write_api=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_call_clobber_after_getprocaddress(
    monkeypatch,
) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, clobber_resolver_return=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_call_clobber_before_allocation_return_save(
    monkeypatch,
) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(
                monkeypatch, clobber_allocation_return=True
            )
        )
        is None
    )


def test_direct_xor_zip_rejects_self_zero_vector_xor_decoy(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, self_zero_vector_xor=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_unattributed_generic_file_calls(
    monkeypatch,
) -> None:
    data = _strict_loader_bundle(monkeypatch, weak_file_read_lineage=True)

    assert recover_zip_sideload_shellcode(data) is None
    route = recover_zip_sideload_shellcode_route(data)
    assert isinstance(route, zip_shellcode.ZipDirectXorRouteRecovery)
    assert route.xor_evidence["carrier_literal_to_file_read_buffer_lineage"] is False
    assert route.xor_evidence["vector_key_broadcast_and_buffer_xor_dataflow"] is True
    assert route.xor_evidence["resolved_remote_memory_write"] is True

    probe = probe_zip_sideload_shellcode(data)
    assert probe["matched"] is True
    assert probe["family"] is None
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["static_config_recovered"] is False
    assert probe["candidate_config_recovered"] is True
    assert probe["used_for_family_resolution"] is False
    assert probe["used_for_c2_confirmation"] is False
    assert probe["command_c2_confirmed"] is False
    assert probe["final_rat_confirmed"] is False
    assert probe["c2_liveness_confirmed"] is False
    assert all(
        item["role"] == "command_c2_candidate"
        and item["contacted"] is False
        and item["liveness_confirmed"] is False
        and item["qualified"] is False
        for item in probe["c2_candidates"]
    )


def test_direct_xor_route_rejects_mismatched_carrier_key(monkeypatch) -> None:
    data = _strict_loader_bundle(
        monkeypatch,
        carrier_key_delta=1,
        weak_file_read_lineage=True,
    )

    assert recover_zip_sideload_shellcode_route(data) is None
    assert probe_zip_sideload_shellcode(data)["matched"] is False


def test_direct_xor_zip_rejects_multiple_key_scan_lineages(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, duplicate_key_lineage=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_multiple_xor_loop_lineages(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, duplicate_xor_lineage=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_multiple_context_eip_writes(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(monkeypatch, duplicate_context_write=True)
        )
        is None
    )


def test_direct_xor_zip_rejects_suspended_flag_in_wrong_argument(monkeypatch) -> None:
    assert (
        recover_zip_sideload_shellcode(
            _strict_loader_bundle(
                monkeypatch,
                wrong_creation_flag_position=True,
            )
        )
        is None
    )


def test_direct_xor_public_summary_omits_key_member_and_network_values(
    monkeypatch,
) -> None:
    recovery = recover_zip_sideload_shellcode(_strict_loader_bundle(monkeypatch))
    assert isinstance(recovery, zip_shellcode.ZipDirectXorShellcodeRecovery)

    summary = zip_shellcode.public_recovery_summary(recovery)

    assert summary["lineage_profile"] == (
        "sideload_loader_uniform_xor_suspended_process_injection"
    )
    assert summary["lineage"]["loader_to_carrier"]["raw_key_included"] is False
    assert summary["member_names_included"] is False
    assert summary["raw_network_values_included"] is False
    assert "198.51.100.27" not in repr(summary)
    assert "carrier.bin" not in repr(summary)


def test_verified_sibling_collection_rechecks_identity_and_provenance(
    monkeypatch,
) -> None:
    parent_data = _strict_loader_bundle(monkeypatch, cpp_stream_lineage=True)
    with zipfile.ZipFile(io.BytesIO(parent_data)) as archive:
        verified = tuple(
            zip_shellcode.VerifiedSiblingMember(
                path=info.filename,
                data=(blob := archive.read(info)),
                size=len(blob),
                sha256=hashlib.sha256(blob).hexdigest(),
            )
            for info in archive.infolist()
            if not info.is_dir()
        )

    result = zip_shellcode.recover_verified_sibling_shellcode(
        parent_data=parent_data,
        expected_parent_sha256=hashlib.sha256(parent_data).hexdigest(),
        members=verified,
        declared_member_count=len(verified),
        declared_total_size=sum(item.size for item in verified),
        collection_complete=True,
    )

    assert result is not None
    assert result.parent_sha256 == hashlib.sha256(parent_data).hexdigest()
    assert result.terminal_sha256 == hashlib.sha256(
        result.recovery.shellcode.data
    ).hexdigest()
    component_hashes = {
        result.host_sha256,
        result.loader_sha256,
        result.carrier_sha256,
    }
    assert len(component_hashes) == 3
    assert component_hashes.issubset({item.sha256 for item in verified})


def test_verified_sibling_parent_uses_sfx_aligned_size_boundary(monkeypatch) -> None:
    parent_data = _strict_loader_bundle(monkeypatch, cpp_stream_lineage=True)
    with zipfile.ZipFile(io.BytesIO(parent_data)) as archive:
        verified = tuple(
            zip_shellcode.VerifiedSiblingMember(
                path=info.filename,
                data=(blob := archive.read(info)),
                size=len(blob),
                sha256=hashlib.sha256(blob).hexdigest(),
            )
            for info in archive.infolist()
            if not info.is_dir()
        )
    monkeypatch.setattr(
        zip_shellcode,
        "MAXIMUM_ARCHIVE_SIZE",
        len(parent_data) - 1,
    )
    monkeypatch.setattr(
        zip_shellcode,
        "MAXIMUM_VERIFIED_PARENT_SIZE",
        len(parent_data),
    )

    result = zip_shellcode.recover_verified_sibling_shellcode(
        parent_data=parent_data,
        expected_parent_sha256=hashlib.sha256(parent_data).hexdigest(),
        members=verified,
        declared_member_count=len(verified),
        declared_total_size=sum(item.size for item in verified),
        collection_complete=True,
    )

    assert result is not None


def test_verified_sibling_collection_rejects_incomplete_or_mismatched_identity(
    monkeypatch,
) -> None:
    parent_data = _strict_loader_bundle(monkeypatch, cpp_stream_lineage=True)
    with zipfile.ZipFile(io.BytesIO(parent_data)) as archive:
        verified = tuple(
            zip_shellcode.VerifiedSiblingMember(
                path=info.filename,
                data=(blob := archive.read(info)),
                size=len(blob),
                sha256=hashlib.sha256(blob).hexdigest(),
            )
            for info in archive.infolist()
            if not info.is_dir()
        )
    arguments = {
        "parent_data": parent_data,
        "expected_parent_sha256": hashlib.sha256(parent_data).hexdigest(),
        "members": verified,
        "declared_member_count": len(verified),
        "declared_total_size": sum(item.size for item in verified),
    }

    assert (
        zip_shellcode.recover_verified_sibling_shellcode(
            **arguments,
            collection_complete=False,
        )
        is None
    )
    assert (
        zip_shellcode.recover_verified_sibling_shellcode(
            **{
                **arguments,
                "declared_total_size": arguments["declared_total_size"] + 1,
            },
            collection_complete=True,
        )
        is None
    )


def test_verified_sibling_collection_rejects_file_child_namespace_collision(
    monkeypatch,
) -> None:
    parent_data = b"P" * 22
    first = b"a"
    second = b"b"
    members = (
        zip_shellcode.VerifiedSiblingMember(
            path="tree",
            data=first,
            size=len(first),
            sha256=hashlib.sha256(first).hexdigest(),
        ),
        zip_shellcode.VerifiedSiblingMember(
            path="tree/child.bin",
            data=second,
            size=len(second),
            sha256=hashlib.sha256(second).hexdigest(),
        ),
    )

    def unexpected_parse(_member):
        raise AssertionError("namespace衝突後にPE parserを呼んではいけません")

    monkeypatch.setattr(zip_shellcode, "_parse_pe_member", unexpected_parse)
    assert (
        zip_shellcode.recover_verified_sibling_shellcode(
            parent_data=parent_data,
            expected_parent_sha256=hashlib.sha256(parent_data).hexdigest(),
            members=members,
            declared_member_count=len(members),
            declared_total_size=sum(item.size for item in members),
            collection_complete=True,
        )
        is None
    )
