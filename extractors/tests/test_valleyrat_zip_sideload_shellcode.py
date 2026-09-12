"""ZIPサイドロード用raw vvaS shellcode parserの汎化境界を検証する。"""

from __future__ import annotations

import struct

from extractors.valleyrat.extractor import _extract_raw_vvas_transport_shellcode
from extractors.valleyrat.zip_sideload_shellcode import (
    probe_raw_vvas_shellcode,
    public_raw_shellcode_summary,
    recover_raw_vvas_shellcode,
)


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
