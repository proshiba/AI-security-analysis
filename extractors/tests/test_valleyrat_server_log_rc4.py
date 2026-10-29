"""OIS報告型ValleyRAT ``Server.log`` routeを検証する。"""

from __future__ import annotations

import json
import struct

import pytest

from extractors.valleyrat import extractor
from extractors.valleyrat import server_log_rc4 as target

KEY = b"??Bid@locale@std"


def _rc4_reference(data: bytes, key: bytes = KEY) -> bytes:
    """fixture生成用の独立した標準RC4実装。"""

    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def _config(
    *,
    first_host: str = "8.8.8.8",
    third_host: str = "1.1.1.1",
    first_port: int = 9000,
) -> str:
    plaintext = (
        f"|p1:{first_host}|o1:{first_port}|t1:1"
        "|p2:|o2:|t2:1"
        f"|p3:{third_host}|o3:9001|t3:0"
        "|dd:3|cl:30|fz:fixture-group|bb:3.2|bz:fixture-remark"
        "|jp:0|bh:1|ll:0|dl:0|sh:0|kl:0|bd:0|"
    )
    return plaintext[::-1]


def _ois_config() -> str:
    """公開記事のfield形状を、無害化を戻したdomainで再現する。"""

    plaintext = (
        "|p1:ydbao8.cyou|o1:9000|t1:1"
        "|p2:|o2:|t2:1|p3:|o3:|t3:1"
        "|dd:1|cl:1|fz:LINE|bb:1.0|bz:2025. 8.31"
        "|jp:1|bh:0|ll:0|dl:1|sh:1|kl:1|bd:0|"
    )
    return plaintext[::-1]


def _pe(
    *,
    export_name: str = "NtHandleCallback",
    machine: int = 0x14C,
    dll: bool = True,
    rdata_raw_pointer: int = 0x400,
    configs: tuple[str, ...] | None = None,
) -> bytes:
    """検証対象と同じ構造条件を持つ非実行用の最小PE32 DLLを作る。"""

    total_size = 0xC00
    data = bytearray(total_size)
    data[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    characteristics = 0x0102 | (0x2000 if dll else 0)
    struct.pack_into(
        "<HHIIIHH",
        data,
        e_lfanew + 4,
        machine,
        2,
        0,
        0,
        0,
        0xE0,
        characteristics,
    )
    optional = e_lfanew + 24
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 0x04, 0x200)
    struct.pack_into("<I", data, optional + 0x08, 0x800)
    struct.pack_into("<I", data, optional + 0x10, 0x1000)
    struct.pack_into("<I", data, optional + 0x14, 0x1000)
    struct.pack_into("<I", data, optional + 0x18, 0x2000)
    struct.pack_into("<I", data, optional + 0x1C, 0x400000)
    struct.pack_into("<I", data, optional + 0x20, 0x1000)
    struct.pack_into("<I", data, optional + 0x24, 0x200)
    struct.pack_into("<I", data, optional + 0x38, 0x3000)
    struct.pack_into("<I", data, optional + 0x3C, 0x200)
    struct.pack_into("<H", data, optional + 0x44, 3)
    struct.pack_into("<I", data, optional + 0x5C, 16)
    struct.pack_into("<II", data, optional + 0x60, 0x2000, 0x100)

    text = optional + 0xE0
    data[text : text + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, text + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, text + 36, 0x60000020)
    rdata = text + 40
    data[rdata : rdata + 8] = b".rdata\0\0"
    struct.pack_into(
        "<IIII", data, rdata + 8, 0x800, 0x2000, 0x800, rdata_raw_pointer
    )
    struct.pack_into("<I", data, rdata + 36, 0x40000040)
    data[0x200] = 0xC3

    if rdata_raw_pointer + 0x800 <= len(data):
        base = rdata_raw_pointer
        struct.pack_into(
            "<IIHHIIIIIII",
            data,
            base,
            0,
            0,
            0,
            0,
            0x2040,
            1,
            1,
            1,
            0x2060,
            0x2064,
            0x2068,
        )
        data[base + 0x40 : base + 0x4C] = b"fixture.dll\0"
        struct.pack_into("<I", data, base + 0x60, 0x1000)
        struct.pack_into("<I", data, base + 0x64, 0x2070)
        struct.pack_into("<H", data, base + 0x68, 0)
        encoded_export = export_name.encode("ascii") + b"\0"
        data[base + 0x70 : base + 0x70 + len(encoded_export)] = encoded_export
        values = configs or (_config(),)
        for offset, value in zip((0x100, 0x500), values):
            encoded = value.encode("utf-16le") + b"\0\0"
            data[base + offset : base + offset + len(encoded)] = encoded
    return bytes(data)


def _server_log(**kwargs: object) -> tuple[bytes, bytes]:
    plaintext = _pe(**kwargs)
    return _rc4_reference(plaintext), plaintext


def test_recovers_strict_server_log_route_without_raw_material() -> None:
    encrypted, plaintext = _server_log()

    recovery = target.recover_server_log_rc4(encrypted)
    summary = recovery.public_summary()

    assert recovery.recovered_payload == plaintext
    assert summary["status"] == "validated_server_log_rc4_route_candidate"
    assert summary["terminal_family_confirmed"] is False
    assert summary["supports_family_attribution"] is False
    assert summary["command_c2_confirmed"] is False
    assert summary["recovered_pe"]["required_export"] == "NtHandleCallback"
    assert summary["config"]["endpoints"] == ["8.8.8.8:9000", "1.1.1.1:9001"]
    assert summary["config"]["slots"][1]["configured"] is False
    assert summary["config"]["slots"][2]["transport"] == "udp"
    serialized = json.dumps(summary, sort_keys=True)
    assert KEY.decode("ascii") not in serialized
    assert _config() not in serialized
    assert summary["safety"]["raw_pe_included"] is False
    assert "recovered_payload" not in summary


def test_shared_extractor_returns_route_only_payload_for_static_follow_on() -> None:
    encrypted, plaintext = _server_log()

    result = extractor.extract(encrypted, "Server.log")

    config = result["config"]
    assert config["variant"] == "ois_2026_server_log_rc4_candidate"
    assert config["candidate_config_recovered"] is True
    assert config["static_config_recovered"] is False
    assert config["terminal_family_confirmed"] is False
    assert config["endpoints"] == ["8.8.8.8:9000", "1.1.1.1:9001"]
    recovered = result["recovered_payload"]
    assert recovered["role"] == "recovered_payload"
    assert recovered["analysis_priority"] == 3
    assert recovered["source_name"] == recovered["name"]
    assert recovered["data"] == plaintext


def test_accepts_publicly_documented_ois_config_shape() -> None:
    encrypted, _plaintext = _server_log(configs=(_ois_config(),))

    summary = target.recover_server_log_rc4(encrypted).public_summary()

    assert summary["config"]["endpoints"] == ["ydbao8.cyou:9000"]
    assert [item["configured"] for item in summary["config"]["slots"]] == [
        True,
        False,
        False,
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"export_name": "NtHandleCallbacX"},
        {"machine": 0x8664},
        {"dll": False},
        {"rdata_raw_pointer": 0x1000},
    ],
)
def test_rejects_wrong_export_architecture_dll_and_section_bounds(kwargs) -> None:
    encrypted, _plaintext = _server_log(**kwargs)
    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(encrypted)


def test_rejects_ambiguous_reversed_configs() -> None:
    encrypted, _plaintext = _server_log(
        configs=(
            _config(),
            _config(first_host="9.9.9.9", first_port=9443),
        )
    )

    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(encrypted)


def test_rejects_private_only_or_malformed_config() -> None:
    encrypted, _plaintext = _server_log(
        configs=(_config(first_host="127.0.0.1", third_host="10.0.0.1"),)
    )

    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(encrypted)


def test_rejects_wrong_key_plain_container_and_non_bytes() -> None:
    encrypted, plaintext = _server_log()
    wrong = _rc4_reference(plaintext, b"wrong-fixture-key")

    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(wrong)
    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(plaintext)
    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(bytearray(encrypted))  # type: ignore[arg-type]


def test_rejects_input_over_configured_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    encrypted, _plaintext = _server_log()
    monkeypatch.setattr(target, "MAXIMUM_INPUT_SIZE", len(encrypted) - 1)

    with pytest.raises(target.ServerLogRc4Error):
        target.recover_server_log_rc4(encrypted)
