"""ValleyRAT/Winos4 ``codecode``設定profileの回帰試験。"""

from __future__ import annotations

import json

import pytest

from extractors.valleyrat import codecode_config, extractor, nvml_dat


def _stage(
    *,
    architecture: str = "x86",
    xor_key: int = 0x2B,
    third_host: str = "backup.example",
    marker: bytes = nvml_dat.CODECODE,
    include_peb: bool = True,
    extra_request: bytes | None = None,
) -> bytes:
    first_host = b"primary.example\0"
    second_host = b"secondary.example\0"
    request = b"x32\0" if architecture == "x86" else b"x64\0"
    if architecture == "x86":
        peb = b"\x64\xa1\x30\x00\x00\x00"
    else:
        peb = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    code = peb if include_peb else b"\x90" * len(peb)
    code += b"\x68" + request
    if extra_request is not None:
        code += b"\x68" + extra_request
    code += b"\x80\x30" + bytes((xor_key,))
    code += b"\x90" * (0x400 - len(code))

    header = bytearray(nvml_dat.CODEMARK_HEADER_SIZE)
    header[: len(marker)] = marker
    header[0x20:0x24] = len(first_host).to_bytes(4, "little")
    header[0x24:0x28] = (443).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(second_host).to_bytes(4, "little")
    header[0x30:0x34] = (8443).to_bytes(4, "little")
    header[0x34:0x38] = (1).to_bytes(4, "little")
    canonical = (
        "|p1:primary.example|o1:443|t1:1"
        "|p2:secondary.example|o2:8443|t2:1"
        f"|p3:{third_host}|o3:9443|t3:0|dd:10|cl:30|"
    )
    trailing = canonical[::-1].encode("utf-16le")
    return code + bytes(header) + first_host + second_host + trailing


@pytest.mark.parametrize(
    ("architecture", "module_request", "peb_profile"),
    (
        ("x86", "x32", "x86_fs_peb"),
        ("x64", "x64", "x64_gs_peb"),
    ),
)
def test_codecode_recovers_candidate_config_with_distinct_profile(
    architecture: str,
    module_request: str,
    peb_profile: str,
) -> None:
    """codecode、module要求、XOR 0x2B、PEB参照の同時成立だけを採用する。"""

    result = codecode_config.extract_codecode_config(_stage(architecture=architecture))

    assert result["status"] == "validated_codecode_route_candidate"
    assert result["marker_profile"] == "codecode"
    assert result["module_request"] == module_request
    assert result["request_architecture"] == architecture
    assert result["download_transform"] == "xor_0x2b"
    assert result["endpoints"] == [
        "primary.example:443",
        "secondary.example:8443",
        "backup.example:9443",
    ]
    assert result["candidate_config_recovered"] is True
    assert result["static_config_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["evidence"]["peb_access_profile"] == peb_profile
    assert result["evidence"]["xor_2b_instruction_count"] == 1
    assert result["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "raw_config_included": False,
        "raw_payload_included": False,
    }


def test_codecode_probe_hides_endpoint_and_raw_config_values() -> None:
    """detector probeへhost、port、反転config、raw payloadを複写しない。"""

    result = codecode_config.probe_codecode_config(_stage())
    serialized = json.dumps(result, ensure_ascii=False)

    assert result["matched"] is True
    assert result["endpoint_count"] == 3
    assert result["supports_family_attribution"] is False
    assert result["static_config_recovered"] is False
    for secret in (
        "primary.example",
        "secondary.example",
        "backup.example",
        "443",
        "8443",
        "9443",
    ):
        assert secret not in serialized


@pytest.mark.parametrize(
    ("kwargs", "reason_code"),
    (
        ({"xor_key": 0x36}, "xor_2b_instruction_missing"),
        ({"include_peb": False}, "peb_access_not_unique"),
        ({"extra_request": b"x64\0"}, "module_request_not_unique"),
        ({"marker": nvml_dat.CODEMARK}, "marker_missing"),
    ),
)
def test_codecode_rejects_incomplete_or_mixed_profiles(
    kwargs: dict[str, object], reason_code: str
) -> None:
    """旧codemark条件、異なるXOR、PEB欠落、複数要求を混成採用しない。"""

    result = codecode_config.probe_codecode_config(_stage(**kwargs))

    assert result["matched"] is False
    assert result["reason_code"] == reason_code
    assert result["evidence"] == {}
    assert result["endpoint_count"] == 0


@pytest.mark.parametrize(
    "prefix",
    (
        b"MZ",
        b"PK\x03\x04",
        bytes.fromhex("d0cf11e0a1b11ae1"),
        b"\x7fELF",
    ),
)
def test_codecode_rejects_container_decoys(prefix: bytes) -> None:
    """containerへ埋め込まれた文字列・設定をraw shellcodeとして扱わない。"""

    result = codecode_config.probe_codecode_config(prefix + _stage())

    assert result["matched"] is False
    assert result["reason_code"] == "container_input_rejected"


def test_codecode_rejects_marker_and_config_without_code_lineage() -> None:
    """設定blobだけをmodule取得profileへ昇格しない。"""

    config_only = _stage()[0x400:]
    result = codecode_config.probe_codecode_config(b"\x90" * 0x400 + config_only)

    assert result["matched"] is False
    assert result["reason_code"] == "module_request_not_unique"


def test_codecode_rejects_conflicting_configuration_candidates() -> None:
    """同一stageに異なるC2設定があれば一意性を満たさない。"""

    first = _stage()
    second = _stage(third_host="different.example")
    result = codecode_config.probe_codecode_config(first + second)

    assert result["matched"] is False
    assert result["reason_code"] == "config_structure_invalid"


def test_codecode_marker_occurrence_limit_is_fail_closed() -> None:
    """探索上限より後ろのmarkerを黙って無視しない。"""

    result = codecode_config.probe_codecode_config(
        nvml_dat.CODECODE * (nvml_dat.MAX_CODEMARK_OCCURRENCES + 1)
    )

    assert result["matched"] is False
    assert result["reason_code"] == "marker_scan_limit"


def test_codecode_input_limit_precedes_marker_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """大容量入力はmarker探索前に拒否する。"""

    monkeypatch.setattr(codecode_config, "MAX_PAYLOAD_SIZE", 4)
    result = codecode_config.probe_codecode_config(b"codecode")

    assert result["matched"] is False
    assert result["reason_code"] == "input_size_limit"


def test_codemark_wrapper_remains_marker_specific() -> None:
    """共通parser化後も既存codemark wrapperの意味を変更しない。"""

    codemark = _stage(marker=nvml_dat.CODEMARK)
    assert nvml_dat.parse_codemark_config(codemark)["marker"] == "codemark"
    with pytest.raises(nvml_dat.NvmlDatError, match="codecode"):
        nvml_dat.parse_codecode_config(codemark)


def test_shared_extractor_publishes_codecode_as_route_only() -> None:
    result = extractor.extract(_stage(), "stage.bin")

    config = result["config"]
    assert config["variant"] == "winos_codecode_recovered_stage"
    assert config["candidate_config_recovered"] is True
    assert config["static_config_recovered"] is False
    assert config["terminal_family_confirmed"] is False
    assert config["endpoints"] == [
        "primary.example:443",
        "secondary.example:8443",
        "backup.example:9443",
    ]
