from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "malware" / "valleyrat" / "campaigns" / "signed_proxy_sideload"
sys.path.insert(0, str(MODULE_ROOT))
spec = importlib.util.spec_from_file_location("winos_pcap", MODULE_ROOT / "winos_pcap.py")
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
import winos_protocol as PROTOCOL  # noqa: E402

HEADER_CA00 = bytes.fromhex("9f25590e00000000ca00")
HEADER_CA01_NVML = bytes.fromhex("3800000000000000ca01")


def _row(
    timestamp: str,
    stream: int,
    sequence: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    payload: bytes,
) -> str:
    return "|".join(
        (
            timestamp,
            str(stream),
            str(sequence),
            source,
            str(source_port),
            destination,
            str(destination_port),
            payload.hex(),
        )
    )


def test_parse_endpoint_rejects_filter_injection() -> None:
    assert MODULE.parse_endpoint("121.127.253.206:8856") == ("121.127.253.206", 8856)
    with pytest.raises(ValueError):
        MODULE.parse_endpoint("121.127.253.206:8856 || tcp")


def test_reassemble_deduplicates_and_parses_stage_control() -> None:
    # 実観測と同形式のcommand 0x04フレーム。重複segmentは一度だけ採用する。
    payload = bytes.fromhex("100000009f25590e00000000ca00d1d5")
    row = _row(
        "1724500000.125000",
        48,
        1,
        "192.0.2.82",
        49930,
        "121.127.253.206",
        8856,
        payload,
    )
    result = MODULE.analyze_rows([row, row], [("121.127.253.206", 8856)])
    stream = result["streams"][0]
    assert stream["direction"] == "client_to_server"
    assert stream["parsed_frame_count"] == 1
    event = result["events"][0]
    assert event["tcp_stream"] == 48
    assert event["timestamp_epoch"] == 1724500000.125
    assert event["direction"] == "client_to_server"
    assert event["command"] == 4
    assert event["lengths"] == {
        "frame": 16,
        "framing_overhead": 14,
        "decrypted_payload": 2,
        "command_body": 1,
    }
    assert event["shape"]["command_has_body"] is True
    assert result["safety"]["pcap_replayed"] is False
    assert result["safety"]["payload_content_published"] is False

    serialized = json.dumps(result, ensure_ascii=False)
    assert "payload_utf16_preview" not in serialized
    assert "payload_hex" not in serialized
    assert "header_hex" not in serialized
    assert payload.hex() not in serialized


def test_reassemble_parses_ca01_fixed_xor_stage_frames() -> None:
    # 2026-08-20検体のca01 mode。payloadは固定0xCCでXORされる。
    control = bytes([0x04])
    metadata = bytes([0x05]) + "登录模块.dll_bin".encode("utf-16le")
    header = bytes.fromhex("74af580e00000000ca01")

    def frame(payload: bytes) -> bytes:
        encrypted = bytes(value ^ 0xCC for value in payload)
        return (14 + len(payload)).to_bytes(4, "little") + header + encrypted

    stream = frame(control) + frame(metadata)
    row = _row(
        "1724500001.500000",
        1,
        1,
        "10.0.0.2",
        50001,
        "170.62.130.47",
        449,
        stream,
    )
    result = MODULE.analyze_rows(
        [row],
        [("170.62.130.47", 449)],
        cipher_mode=PROTOCOL.CipherMode.FIXED_XOR_CC,
    )
    assert [item["command"] for item in result["events"]] == [4, 5]
    assert result["cipher_mode"] == "fixed_xor_cc"
    assert all(item["cipher_mode"] == "fixed_xor_cc" for item in result["events"])
    assert result["streams"][0]["cipher_mode"] == "fixed_xor_cc"
    assert result["events"][1]["shape"]["command_has_body"] is True
    serialized = json.dumps(result, ensure_ascii=False)
    assert "登录模块" not in serialized
    assert metadata.hex() not in serialized


def test_ca01_suffix_does_not_select_cipher_mode() -> None:
    # NVML PCAP実証値: header[0] 0x38 + 0x36 = 0x6e、0x68 ^ 0x6e = 0x06。
    raw_rolling = (15).to_bytes(4, "little") + HEADER_CA01_NVML + b"\x68"
    default_frame = PROTOCOL.parse_frame(raw_rolling)
    rolling_frame = PROTOCOL.parse_frame(
        raw_rolling,
        cipher_mode=PROTOCOL.CipherMode.ROLLING_HEADER_PLUS_0X36,
    )
    wrong_fixed_frame = PROTOCOL.parse_frame(
        raw_rolling,
        cipher_mode=PROTOCOL.CipherMode.FIXED_XOR_CC,
    )

    assert default_frame.command == 0x06
    assert rolling_frame.command == 0x06
    assert rolling_frame.cipher_mode == "rolling_header_plus_0x36"
    assert wrong_fixed_frame.command == 0xA4
    assert wrong_fixed_frame.cipher_mode == "fixed_xor_cc"

    rolling_row = _row(
        "1724500002.000000",
        2,
        1,
        "10.0.0.3",
        50002,
        "170.62.130.47",
        449,
        raw_rolling,
    )
    rolling_result = MODULE.analyze_rows(
        [rolling_row],
        [("170.62.130.47", 449)],
    )
    assert rolling_result["cipher_mode"] == "rolling_header_plus_0x36"
    assert rolling_result["events"][0]["command"] == 0x06
    assert rolling_result["events"][0]["cipher_mode"] == "rolling_header_plus_0x36"

    fixed_frame = PROTOCOL.build_frame(
        b"\x06",
        HEADER_CA01_NVML,
        cipher_mode=PROTOCOL.CipherMode.FIXED_XOR_CC,
    )
    assert fixed_frame[-1] == (0x06 ^ 0xCC)
    fixed_row = _row(
        "1724500003.000000",
        3,
        1,
        "10.0.0.4",
        50003,
        "170.62.130.47",
        449,
        fixed_frame,
    )
    fixed_result = MODULE.analyze_rows(
        [fixed_row],
        [("170.62.130.47", 449)],
        cipher_mode=PROTOCOL.CipherMode.FIXED_XOR_CC,
    )
    assert fixed_result["cipher_mode"] == "fixed_xor_cc"
    assert fixed_result["events"][0]["command"] == 0x06
    assert fixed_result["events"][0]["cipher_mode"] == "fixed_xor_cc"


def test_reassembly_stops_at_sequence_gap() -> None:
    first = "100000009f25590e00000000ca00d1d5"
    # timestamp列を持たない旧fixtureも互換入力として扱う。
    rows = [
        f"1|1|10.0.0.1|50000|121.127.253.206|8856|{first}",
        "1|100|10.0.0.1|50000|121.127.253.206|8856|41414141",
    ]
    streams = MODULE.reassemble_rows(rows)
    assert len(next(iter(streams.values()))) == 16


def test_correlates_bidirectional_events_by_timestamp_and_stream() -> None:
    client = PROTOCOL.build_frame(b"\x06", HEADER_CA00)
    server = PROTOCOL.build_frame(b"\xca", HEADER_CA00)
    rows = [
        _row(
            "1724500010.100000",
            7,
            1,
            "10.0.0.5",
            51000,
            "121.127.253.206",
            8868,
            client,
        ),
        _row(
            "1724500010.250000",
            7,
            1,
            "121.127.253.206",
            8868,
            "10.0.0.5",
            51000,
            server,
        ),
    ]
    result = MODULE.analyze_rows(rows, [("121.127.253.206", 8868)])

    assert len(result["events"]) == 2
    correlation = result["correlations"][0]
    assert correlation["tcp_stream"] == 7
    assert correlation["event_count"] == 2
    assert correlation["first_timestamp_epoch"] == 1724500010.1
    assert correlation["last_timestamp_epoch"] == 1724500010.25
    assert correlation["direction_counts"] == {
        "client_to_server": 1,
        "server_to_client": 1,
    }
    assert [item["direction"] for item in correlation["event_sequence"]] == [
        "client_to_server",
        "server_to_client",
    ]
    assert [item["command"] for item in correlation["event_sequence"]] == [
        0x06,
        0xCA,
    ]


def test_correlation_preserves_numeric_frame_order_when_timestamps_match() -> None:
    commands = list(range(0x10, 0x1C))
    stream = b"".join(PROTOCOL.build_frame(bytes([command]), HEADER_CA00) for command in commands)
    row = _row(
        "1724500015.000000",
        8,
        1,
        "10.0.0.6",
        51100,
        "121.127.253.206",
        8868,
        stream,
    )

    result = MODULE.analyze_rows([row], [("121.127.253.206", 8868)])

    assert [item["command"] for item in result["correlations"][0]["event_sequence"]] == commands


def test_private_payload_hex_requires_explicit_separate_api_and_is_bounded() -> None:
    payload = bytes([0x05]) + "登录模块.dll_bin".encode("utf-16le")
    frame = PROTOCOL.build_frame(payload, HEADER_CA00)
    row = _row(
        "1724500020.000000",
        9,
        1,
        "10.0.0.8",
        52000,
        "121.127.253.206",
        8856,
        frame,
    )

    public = MODULE.analyze_rows([row], [("121.127.253.206", 8856)])
    private = MODULE.analyze_rows_private(
        [row],
        [("121.127.253.206", 8856)],
        maximum_payload_bytes=4,
    )
    assert public["cipher_mode"] == "rolling_header_plus_0x36"
    assert public["events"][0]["cipher_mode"] == "rolling_header_plus_0x36"
    assert private["cipher_mode"] == "rolling_header_plus_0x36"
    assert private["events"][0]["cipher_mode"] == "rolling_header_plus_0x36"

    assert "payload_hex_prefix" not in json.dumps(public)
    private_event = private["events"][0]
    assert private_event["payload_hex_prefix"] == payload[:4].hex()
    assert private_event["payload_prefix_length"] == 4
    assert private_event["payload_length"] == len(payload)
    assert private_event["payload_truncated"] is True
    assert private["maximum_payload_prefix_bytes"] == 4


@pytest.mark.parametrize("limit", [0, MODULE.MAX_PRIVATE_PAYLOAD_BYTES + 1])
def test_private_payload_limit_fails_closed(limit: int) -> None:
    with pytest.raises(ValueError):
        MODULE.analyze_rows_private([], [], maximum_payload_bytes=limit)


def test_private_output_path_must_be_separate_and_outside_repository(
    tmp_path: Path,
) -> None:
    public = tmp_path / "public.json"
    private = tmp_path / "private.json"
    assert MODULE._private_output_path(private, public) == private.resolve()
    with pytest.raises(ValueError, match="別path"):
        MODULE._private_output_path(public, public)
    with pytest.raises(ValueError, match="repository外"):
        MODULE._private_output_path(MODULE_ROOT / "private.json", None)


def test_cli_writes_private_payload_only_to_explicit_separate_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = b"\x05private-content"
    frame = PROTOCOL.build_frame(
        payload,
        HEADER_CA01_NVML,
        cipher_mode=PROTOCOL.CipherMode.FIXED_XOR_CC,
    )
    row = _row(
        "1724500030.000000",
        10,
        1,
        "10.0.0.9",
        53000,
        "121.127.253.206",
        8856,
        frame,
    )
    pcap = tmp_path / "input.pcap"
    pcap.write_bytes(b"offline fixture")
    public_path = tmp_path / "public.json"
    private_path = tmp_path / "private.json"
    monkeypatch.setattr(MODULE, "tshark_rows", lambda *_args, **_kwargs: [row])

    assert (
        MODULE.main(
            [
                str(pcap),
                "--endpoint",
                "121.127.253.206:8856",
                "--output",
                str(public_path),
                "--private-output",
                str(private_path),
                "--private-max-payload-bytes",
                "4",
                "--cipher-mode",
                PROTOCOL.CipherMode.FIXED_XOR_CC.value,
            ]
        )
        == 0
    )

    public_text = public_path.read_text(encoding="utf-8")
    stdout_text = capsys.readouterr().out
    public_result = json.loads(public_text)
    private_result = json.loads(private_path.read_text(encoding="utf-8"))
    assert "payload_hex_prefix" not in public_text
    assert "payload_hex_prefix" not in stdout_text
    assert payload.hex() not in public_text
    assert private_result["events"][0]["payload_hex_prefix"] == payload[:4].hex()
    assert public_result["cipher_mode"] == "fixed_xor_cc"
    assert public_result["events"][0]["cipher_mode"] == "fixed_xor_cc"
    assert private_result["cipher_mode"] == "fixed_xor_cc"
    assert private_result["events"][0]["cipher_mode"] == "fixed_xor_cc"
