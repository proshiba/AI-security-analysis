"""ValleyRAT設定探索の計算量上限とIPv6正規化を検証する。"""

from __future__ import annotations

import json

import pytest

from extractors.valleyrat import extractor, nvml_dat


def _codemark_stage_with_ipv6() -> bytes:
    first_host = b"2001:0db8:0:0:0:0:0:1\0"
    second_host = b"198.51.100.24\0"
    header = bytearray(nvml_dat.CODEMARK_HEADER_SIZE)
    header[: len(nvml_dat.CODEMARK)] = nvml_dat.CODEMARK
    header[0x20:0x24] = len(first_host).to_bytes(4, "little")
    header[0x24:0x28] = (443).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(second_host).to_bytes(4, "little")
    header[0x30:0x34] = (8443).to_bytes(4, "little")
    header[0x34:0x38] = (1).to_bytes(4, "little")
    canonical = (
        "|p1:2001:db8::1|o1:443|t1:1"
        "|p2:198.51.100.24|o2:8443|t2:1"
        "|p3:2001:db8::3|o3:9443|t3:1|fz:默认|"
    )
    return bytes(header) + first_host + second_host + canonical[::-1].encode("utf-16le")


def test_xor_vvas_marker_discovery_has_one_bounded_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """8 MiB上限内の鍵候補探索を255回の全体走査へ戻さない。"""

    plaintext = b"\0" * 64_000 + b"odaktomk |6666:1o|061.3.911.301:1p|"
    encrypted = bytes(value ^ 0x14 for value in plaintext)
    original = extractor._xor_marker_candidate_keys
    calls = 0

    def counted(data: bytes, marker: bytes) -> tuple[list[int], int]:
        nonlocal calls
        calls += 1
        return original(data, marker)

    monkeypatch.setattr(extractor, "_xor_marker_candidate_keys", counted)
    recovered, endpoints, evidence = extractor._recover_xor_vvas(encrypted)

    assert calls == 1
    assert recovered == plaintext
    assert endpoints == {"endpoint_1": "103.119.3.160:6666"}
    assert evidence["marker_scan_passes"] == 1
    assert evidence["marker_scan_byte_count"] == len(encrypted) - len(extractor.VVAS_MARKER) + 1
    assert evidence["candidate_key_count"] == 1
    assert evidence["raw_key_included"] is False


def test_codemark_large_tail_is_scanned_completely_in_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """旧256 KiB窓より後ろの相関済みconfigも全tail走査で復元する。"""

    monkeypatch.setattr(nvml_dat, "TRAILING_SCAN_CHUNK_BYTES", 96)
    component = _codemark_stage_with_ipv6()
    marker_offset = component.index(nvml_dat.CODEMARK)
    first_length = int.from_bytes(component[0x20:0x24], "little")
    second_length = int.from_bytes(component[0x2C:0x30], "little")
    tail_offset = (
        marker_offset
        + nvml_dat.CODEMARK_HEADER_SIZE
        + first_length
        + second_length
    )
    stage = component[:tail_offset] + b"\0" * (300 * 1024) + component[tail_offset:]

    config = nvml_dat.parse_codemark_config(stage)

    assert config["endpoints"] == [
        "[2001:db8::1]:443",
        "198.51.100.24:8443",
        "[2001:db8::3]:9443",
    ]
    assert config["trailing_config_scanned_bytes"] == len(stage) - tail_offset
    assert config["trailing_config_scan_chunk_bytes"] == 96
    assert config["trailing_config_scanned_bytes"] > 256 * 1024
    assert config["trailing_config_scan_completed"] is True


def test_codemark_large_tail_rejects_late_conflicting_transport() -> None:
    """旧走査窓より後ろの相反transport候補を見落とさず拒否する。"""

    first = _codemark_stage_with_ipv6()
    second = first.replace(
        "|t3:1|"[::-1].encode("utf-16le"),
        "|t3:0|"[::-1].encode("utf-16le"),
    )
    first_length = int.from_bytes(first[0x20:0x24], "little")
    second_length = int.from_bytes(first[0x2C:0x30], "little")
    tail_offset = nvml_dat.CODEMARK_HEADER_SIZE + first_length + second_length
    stage = first + b"\0" * (300 * 1024) + second[tail_offset:]

    with pytest.raises(nvml_dat.NvmlDatError):
        nvml_dat.parse_codemark_config(stage)


def test_ipv4_ipv6_endpoint_parser_and_renderer_reject_ambiguity() -> None:
    """IPv6だけを角括弧で描画し、曖昧な非角括弧IPv6 endpointを拒否する。"""

    assert nvml_dat.render_endpoint("198.51.100.24", 443) == "198.51.100.24:443"
    assert nvml_dat.render_endpoint("Example.COM.", 8443) == "example.com:8443"
    assert nvml_dat.render_endpoint("2001:0DB8:0:0::1", 9443) == "[2001:db8::1]:9443"
    assert nvml_dat.parse_endpoint("[2001:0db8::1]:9443") == ("2001:db8::1", 9443)
    assert nvml_dat.parse_endpoint("198.51.100.24:443") == ("198.51.100.24", 443)
    assert nvml_dat.parse_endpoint("2001:db8::1:9443") is None
    assert nvml_dat.parse_endpoint("[2001:db8::1]9443") is None
    assert nvml_dat.parse_endpoint("[example.com]:443") is None
    assert nvml_dat.render_endpoint("fe80::1%eth0", 443) is None


def test_vvas_and_codemark_emit_bracketed_ipv6_without_leaking_probe_values() -> None:
    """vvaS、codemark、URLのIPv6 authorityを一貫して角括弧表現へ揃える。"""

    canonical = "|p1:2001:0db8:0:0::1|o1:8443|"
    stored = canonical[::-1]
    decoded = extractor.decode_vvas_reversed_config([stored])
    assert decoded == {"endpoint_1": "[2001:db8::1]:8443"}

    extracted = extractor.extract(b"odaktomk " + stored.encode("ascii"))
    assert extracted["config"]["endpoints"] == ["[2001:db8::1]:8443"]
    assert extracted["config"]["ipv4"] == []

    probe = extractor.probe_vvas_config(
        b"odaktomk " + stored.encode("ascii"), input_format="data"
    )
    assert probe["matched"] is True
    serialized = json.dumps(probe, sort_keys=True)
    assert "2001:db8" not in serialized

    codemark = nvml_dat.parse_codemark_config(_codemark_stage_with_ipv6())
    assert codemark["endpoints"] == [
        "[2001:db8::1]:443",
        "198.51.100.24:8443",
        "[2001:db8::3]:9443",
    ]
    assert extractor._public_urls(["https://[2001:0db8::1]:8443/stage.bin"]) == [
        "https://[2001:db8::1]:8443/stage.bin"
    ]
