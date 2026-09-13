"""ValleyRAT設定抽出器の正常・異常・誤検出・上限を検証する。"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from types import SimpleNamespace

import pytest
from Cryptodome.Cipher import AES

from extractors.valleyrat import extractor, n520, nvml_dat


def _encrypt_n520(value: str, key: bytes, iv: bytes = bytes(range(16))) -> str:
    raw = value.encode("utf-8")
    width = AES.block_size - len(raw) % AES.block_size
    padded = raw + bytes([width]) * width
    encrypted = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv).encrypt(padded)
    return base64.b64encode(iv + encrypted).decode("ascii")


def _instruction(name: str, operand: object = None) -> SimpleNamespace:
    return SimpleNamespace(opcode=SimpleNamespace(name=name), operand=operand)


def _key_image(key: bytes) -> tuple[SimpleNamespace, bytes, list[SimpleNamespace]]:
    method = SimpleNamespace(Name="GetConfigKey", Rva=1)
    type_refs = [
        SimpleNamespace(TypeNamespace="System", TypeName="Int32"),
        SimpleNamespace(TypeNamespace="System", TypeName="Byte"),
    ]
    member_ref = SimpleNamespace(Name="InitializeArray")
    field_rva = SimpleNamespace(
        Field=SimpleNamespace(row_index=1),
        Rva=0x200,
    )
    tables = SimpleNamespace(
        TypeRef=SimpleNamespace(rows=type_refs),
        TypeDef=SimpleNamespace(rows=[]),
        Field=SimpleNamespace(rows=[SimpleNamespace(Name="key")]),
        MethodDef=SimpleNamespace(rows=[method]),
        MemberRef=SimpleNamespace(rows=[member_ref]),
        FieldRva=SimpleNamespace(rows=[field_rva]),
    )
    image = SimpleNamespace(
        net=SimpleNamespace(mdtables=tables),
        get_offset_from_rva=lambda _rva: 32,
    )
    data = b"\0" * 32 + struct.pack(f"<{len(key)}I", *key)
    instructions = [
        _instruction("ldc.i4.s", len(key)),
        _instruction("newarr", 0x01000001),
        _instruction("dup"),
        _instruction("ldtoken", 0x04000001),
        _instruction("call", 0x0A000001),
        _instruction("stloc.0"),
        _instruction("ldloc.0"),
        _instruction("ldlen"),
        _instruction("conv.i4"),
        _instruction("newarr", 0x01000002),
        _instruction("stloc.1"),
        _instruction("ldc.i4.0"),
        _instruction("stloc.2"),
        _instruction("ldloc.1"),
        _instruction("ldloc.2"),
        _instruction("ldloc.0"),
        _instruction("ldloc.2"),
        _instruction("ldelem.i4"),
        _instruction("conv.u1"),
        _instruction("stelem.i1"),
        _instruction("ldloc.2"),
        _instruction("ldc.i4.1"),
        _instruction("add"),
        _instruction("stloc.2"),
        _instruction("ldloc.2"),
        _instruction("ldloc.0"),
        _instruction("ldlen"),
        _instruction("conv.i4"),
        _instruction("blt.s"),
        _instruction("ret"),
    ]
    return image, data, instructions


def _minimal_x86_pe(encoded_tail: bytes) -> bytes:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    return bytes(data) + encoded_tail


def _codemark_stage(
    *,
    third_host: str = "115.190.205.255",
    transports: tuple[int, int, int] = (1, 1, 1),
    header_enabled: tuple[bool, bool] = (True, True),
) -> bytes:
    first_host = b"115.190.205.255\0"
    second_host = b"115.190.205.255\0"
    header = bytearray(nvml_dat.CODEMARK_HEADER_SIZE)
    header[:8] = nvml_dat.CODEMARK
    header[0x20:0x24] = len(first_host).to_bytes(4, "little")
    header[0x24:0x28] = (66).to_bytes(4, "little")
    header[0x28:0x2C] = int(header_enabled[0]).to_bytes(4, "little")
    header[0x2C:0x30] = len(second_host).to_bytes(4, "little")
    header[0x30:0x34] = (8888).to_bytes(4, "little")
    header[0x34:0x38] = int(header_enabled[1]).to_bytes(4, "little")
    canonical = (
        f"|p1:115.190.205.255|o1:66|t1:{transports[0]}"
        f"|p2:115.190.205.255|o2:8888|t2:{transports[1]}"
        f"|p3:{third_host}|o3:6688|t3:{transports[2]}|fz:默认|"
    )
    trailing = canonical[::-1].encode("utf-16le")
    code = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    code += b"\xe8\x00\x00\x00\x00" * 4
    code += b"\x90" * (0x400 - len(code))
    return code + bytes(header) + first_host + second_host + trailing


def test_n520_decrypts_aes_cbc_with_strict_padding() -> None:
    """レビュー済み鍵導出とIV prefix形式を再現する。"""

    key = b"N520-fixture-key"
    encoded = _encrypt_n520("https://config.example/stage.bin", key)

    assert n520._decrypt_value(encoded, key) == "https://config.example/stage.bin"

    damaged = bytearray(base64.b64decode(encoded))
    damaged[-1] ^= 0x7F
    with pytest.raises(n520.N520ConfigError, match="PKCS#7"):
        n520._decrypt_value(base64.b64encode(damaged).decode("ascii"), key)


def test_n520_network_values_canonicalize_ipv6_consistently() -> None:
    """N520 URL／endpointも共通IPv6圧縮・角括弧表現を使用する。"""

    urls, endpoints, opaque = n520._public_network_values(
        [
            "https://[2001:0DB8:0:0:0:0:0:1]:8443/stage.bin",
            "[2001:0DB8:0:0:0:0:0:2]:9443",
        ]
    )

    assert urls == ("https://[2001:db8::1]:8443/stage.bin",)
    assert endpoints == ("[2001:db8::2]:9443",)
    assert opaque == 0


def test_n520_key_requires_initialize_array_and_byte_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GetConfigKeyの初期化列とbacking field境界を検証する。"""

    expected = b"N520-key-material"
    image, data, instructions = _key_image(expected)
    monkeypatch.setattr(n520, "_method_instructions", lambda *_args: instructions)

    key, proof = n520._recover_key(image, data)
    assert key == expected
    assert proof["initializer"] == "RuntimeHelpers.InitializeArray"
    assert proof["raw_key_included"] is False

    invalid = data[:32] + struct.pack(f"<{len(expected)}I", 256, *expected[1:])
    with pytest.raises(n520.N520ConfigError, match="上位24 bit"):
        n520._recover_key(image, invalid)

    without_conversion = instructions[:6] + [_instruction("ret")]
    monkeypatch.setattr(n520, "_method_instructions", lambda *_args: without_conversion)
    with pytest.raises(n520.N520ConfigError, match="initializer列"):
        n520._recover_key(image, data)


def test_n520_recovery_publishes_only_sanitized_network_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """生鍵・暗号文・任意plaintextを公開要約から除外する。"""

    key = b"N520-private-fixture"
    public_plaintext = (
        "https://operator:password@config.example/stage.bin?token=hidden#part"
    )
    opaque_plaintext = "opaque-private-configuration-value"
    encrypted = [
        _encrypt_n520(public_plaintext, key),
        _encrypt_n520(opaque_plaintext, key, b"I" * 16),
    ]
    image = object()
    evidence = {
        "matched": True,
        "managed_metadata_validated": True,
        "sample_executed": False,
        "network_contacted": False,
    }
    monkeypatch.setattr(n520, "_open_managed_image", lambda _data: image)
    monkeypatch.setattr(
        n520, "_structural_evidence_from_image", lambda _image: evidence
    )
    monkeypatch.setattr(
        n520,
        "_method_bodies",
        lambda _image, _data: {},
    )
    monkeypatch.setattr(
        n520,
        "_recover_key",
        lambda _image, _data, **_kwargs: (
            key,
            {"method": "GetConfigKey", "raw_key_included": False},
        ),
    )
    monkeypatch.setattr(
        n520,
        "_base64_values",
        lambda _image, _data, **_kwargs: encrypted,
    )

    recovery = n520.recover_config(b"MZ-fixture")
    summary = n520.public_recovery_summary(recovery)
    serialized = json.dumps(summary, ensure_ascii=False, sort_keys=True)

    assert summary["urls"] == ["https://config.example/stage.bin"]
    assert summary["opaque_value_count"] == 1
    assert summary["raw_ciphertexts_included"] is False
    assert summary["raw_plaintexts_included"] is False
    assert key.decode("ascii") not in serialized
    assert public_plaintext not in serialized
    assert opaque_plaintext not in serialized
    assert all(item not in serialized for item in encrypted)


def test_n520_false_positive_and_input_limit_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """marker文字列だけと上限超過dataではmanaged復元を開始しない。"""

    weak = (
        b"MZ BSJB N520 GetConfigKey InitializeArray FromBase64String "
        b"SHA256 CreateDecryptor https://c2.example/config.enc"
    )
    assert n520.structural_evidence(weak)["matched"] is False

    monkeypatch.setattr(n520, "MAXIMUM_INPUT_SIZE", 8)
    limited = n520.structural_evidence(b"MZ" + b"A" * 8)
    assert limited["matched"] is False
    assert "上限" in limited["reason"]


def test_n520_adapter_requires_gate_and_labels_distribution_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """構造gate成立後だけ配布URLとして共有resultへ統合する。"""

    calls = 0

    def should_not_run(_data: bytes) -> n520.N520ConfigRecovery:
        nonlocal calls
        calls += 1
        raise AssertionError("構造不一致では復元器を呼ばない")

    monkeypatch.setattr(
        extractor,
        "n520_structural_evidence",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(extractor, "recover_n520_config", should_not_run)
    rejected = extractor.extract(
        b"MZ https://config.example/stage.bin", r"C:\secret\sample.exe"
    )
    assert calls == 0
    assert rejected["config"]["static_config_recovered"] is False
    assert rejected["findings"] == []

    recovery = n520.N520ConfigRecovery(
        key_size=16,
        key_sha256="a" * 64,
        encrypted_candidate_count=2,
        decrypted_value_count=2,
        urls=("https://config.example/stage.bin",),
        endpoints=("config.example:443",),
        opaque_value_count=0,
        initializer_proof={"raw_key_included": False},
        structural_evidence={"matched": True},
    )
    monkeypatch.setattr(
        extractor,
        "n520_structural_evidence",
        lambda _data: {"matched": True},
    )
    monkeypatch.setattr(extractor, "recover_n520_config", lambda _data: recovery)
    accepted = extractor.extract(b"MZ-fixture", r"C:\private\sample.exe")

    assert accepted["config"]["source_name"] == "sample.exe"
    assert accepted["config"]["decoded_config_recovered"] is True
    assert accepted["config"]["static_config_recovered"] is True
    assert accepted["config"]["candidate_config_recovered"] is False
    assert accepted["config"]["terminal_family_confirmed"] is True
    assert (
        accepted["config"]["attribution_scope"]
        == "validated_terminal_component_structure"
    )
    assert (
        accepted["config"]["final_c2_inherited_from_configuration_distribution"]
        is False
    )
    assert {item["role"] for item in accepted["findings"]} == {
        "configuration_distribution",
        "configuration_distribution_endpoint",
    }


def test_n520_detector_probe_requires_complete_recovery_and_hides_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N520 probeは完全復号成功だけをfamily証拠とし、設定値を公開しない。"""

    recovery = n520.N520ConfigRecovery(
        key_size=16,
        key_sha256="a" * 64,
        encrypted_candidate_count=2,
        decrypted_value_count=2,
        urls=("https://config.example/stage.bin",),
        endpoints=("198.51.100.24:443",),
        opaque_value_count=0,
        initializer_proof={"method": "GetConfigKey", "raw_key_included": False},
        structural_evidence={"matched": True, "managed_metadata_validated": True},
    )
    monkeypatch.setattr(n520, "recover_config", lambda _data: recovery)
    accepted = n520.probe_config(b"MZ-fixture")
    serialized = json.dumps(accepted, ensure_ascii=False, sort_keys=True)

    assert accepted["matched"] is True
    assert accepted["supports_family_attribution"] is True
    assert accepted["static_config_recovered"] is True
    assert accepted["config"]["decrypted_value_count"] == 2
    assert accepted["config"]["raw_network_values_included"] is False
    assert "config.example" not in serialized
    assert "198.51.100.24" not in serialized

    def fail_recovery(_data: bytes) -> n520.N520ConfigRecovery:
        raise n520.N520ConfigError("合成fixtureの復号失敗")

    monkeypatch.setattr(n520, "recover_config", fail_recovery)
    rejected = n520.probe_config(b"MZ-incomplete")
    assert rejected["matched"] is False
    assert rejected["supports_family_attribution"] is False
    assert rejected["evidence"] == {}
    assert rejected["config"] == {}

    opaque_only = n520.N520ConfigRecovery(
        key_size=16,
        key_sha256="b" * 64,
        encrypted_candidate_count=1,
        decrypted_value_count=1,
        urls=(),
        endpoints=(),
        opaque_value_count=1,
        initializer_proof={"method": "GetConfigKey", "raw_key_included": False},
        structural_evidence={"matched": True, "managed_metadata_validated": True},
    )
    monkeypatch.setattr(n520, "recover_config", lambda _data: opaque_only)
    opaque_rejected = n520.probe_config(b"MZ-opaque")
    assert opaque_rejected["matched"] is False
    assert opaque_rejected["supports_family_attribution"] is False
    assert opaque_rejected["evidence"] == {}
    assert opaque_rejected["config"] == {}


def test_n520_detector_probe_applies_size_limit_before_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N520 probeは上限超過入力でmanaged parserを呼ばない。"""

    monkeypatch.setattr(n520, "MAXIMUM_INPUT_SIZE", 4)
    monkeypatch.setattr(
        n520,
        "recover_config",
        lambda _data: pytest.fail("入力上限の後にN520復号器を呼んではならない"),
    )
    assert n520.probe_config(b"MZ123")["matched"] is False


def test_vvas_decoder_skips_malformed_candidate_and_rejects_ambiguity() -> None:
    """探索順ではなく、一意に検証された反転設定だけを採用する。"""

    valid = "|6666:1o|061.3.911.301:1p|"
    assert extractor.decode_vvas_reversed_config(["|bad:1o|host:1p|", valid]) == {
        "endpoint_1": "103.119.3.160:6666"
    }
    other = "|7777:1o|02.001.15.891:1p|"
    assert extractor.decode_vvas_reversed_config([valid, other]) == {}


def test_vvas_decoder_excludes_loopback_slot_without_losing_external_slots() -> None:
    """b336型の第3placeholderだけを除外し、外部slot 1/2を維持する。"""

    stored = (
        ":zf|1:lc|1:dd|1:3t|10801:3o|1.0.0.721:3p|1:2t|10801:2o|"
        "43.64.57.301:2p|1:1t|10801:1o|43.64.57.301:1p|"
    )
    decoded, evidence = extractor._decode_vvas_reversed_config([stored])
    assert decoded == {
        "endpoint_1": "103.75.46.34:10801",
        "endpoint_2": "103.75.46.34:10801",
    }
    assert evidence["excluded_placeholder_slot_count"] == 1

    probe = extractor.probe_vvas_config(
        b"odaktomk " + stored.encode("ascii"),
        input_format="data",
    )
    assert probe["matched"] is True
    assert (
        probe["evidence"]["vvas_reversed_config"]["excluded_placeholder_slot_count"]
        == 1
    )

    only_placeholder = "|10801:1o|1.0.0.721:1p|"
    assert extractor.decode_vvas_reversed_config([only_placeholder]) == {}


def test_vvas_decoder_tracks_tcp_and_udp_transport_slot_identity() -> None:
    """t=0をUDP selectorとして採用し、transport差も一意性へ含める。"""

    canonical = "|p1:198.51.100.24|o1:443|t1:1|p2:backup-a.example|o2:8443|t2:0|"
    decoded, evidence = extractor._decode_vvas_reversed_config([canonical[::-1]])

    assert decoded == {
        "endpoint_1": "198.51.100.24:443",
        "endpoint_2": "backup-a.example:8443",
    }
    assert evidence["configured_slot_count"] == 2
    assert evidence["disabled_slot_count"] == 0
    assert evidence["explicit_enable_flag_count"] == 0
    assert evidence["implicit_enable_flag_count"] == 0
    assert evidence["explicit_transport_selector_count"] == 2
    assert evidence["tcp_transport_slot_count"] == 1
    assert evidence["udp_transport_slot_count"] == 1
    assert evidence["endpoint_slots"] == [
        {"slot": 1, "endpoint": "198.51.100.24:443", "transport": "tcp"},
        {"slot": 2, "endpoint": "backup-a.example:8443", "transport": "udp"},
    ]

    extracted = extractor.extract(b"odaktomk " + canonical[::-1].encode("ascii"))
    assert extracted["config"]["decoded_vvas_slots"] == evidence["endpoint_slots"]

    different_transport = canonical.replace("t2:0", "t2:1")
    ambiguous, ambiguous_evidence = extractor._decode_vvas_reversed_config(
        [canonical[::-1], different_transport[::-1]]
    )
    assert ambiguous == {}
    assert ambiguous_evidence["status"] == "ambiguous_rejected"
    assert ambiguous_evidence["unique_configuration_count"] == 2


def test_vvas_decoder_rejects_partial_or_unknown_transport_selectors() -> None:
    """t fieldを1つでも使うbuildでは全p/o slotに観測済み0/1を要求する。"""

    partial = "|p1:198.51.100.24|o1:443|t1:1|p2:backup.example|o2:8443|"
    invalid = "|p1:198.51.100.24|o1:443|t1:2|"

    assert extractor.decode_vvas_reversed_config([partial[::-1]]) == {}
    assert extractor.decode_vvas_reversed_config([invalid[::-1]]) == {}


def test_vvas_legacy_slot_without_selector_is_reported_as_unknown() -> None:
    """t fieldが存在しない旧buildではtransportを推測せずunknownに保つ。"""

    canonical = "|p1:198.51.100.24|o1:443|"
    result = extractor.extract(b"odaktomk " + canonical[::-1].encode("ascii"))

    assert result["config"]["decoded_vvas_slots"] == [
        {"slot": 1, "endpoint": "198.51.100.24:443", "transport": "unknown"}
    ]


def test_vvas_raw_detector_probe_requires_unique_marker_and_hides_config() -> None:
    """raw probeはodaktomkの一意性を要求し、endpointをprobe結果へ含めない。"""

    config = b"|944:1o|42.001.15.891:1p|"
    accepted = extractor.probe_vvas_config(
        b"odaktomk " + config,
        input_format="data",
    )
    serialized = json.dumps(accepted, ensure_ascii=False, sort_keys=True)
    assert accepted["matched"] is True
    assert accepted["family"] is None
    assert accepted["supports_family_attribution"] is False
    assert accepted["terminal_family_confirmed"] is False
    assert accepted["static_config_recovered"] is False
    assert accepted["candidate_config_recovered"] is True
    assert accepted["config"]["endpoint_count"] == 1
    assert accepted["config"]["raw_network_values_included"] is False
    assert "198.51.100.24" not in serialized

    for rejected_data in (
        config,
        b"odaktomk odaktomk " + config,
        b"odaktomk |944:1o|42.001.15.891:1p| |844:1o|02.001.15.891:1p|",
    ):
        rejected = extractor.probe_vvas_config(rejected_data, input_format="data")
        assert rejected["matched"] is False
        assert rejected["evidence"] == {}
        assert rejected["config"] == {}


def test_vvas_pe_detector_probe_requires_real_ws2_32_import_cluster(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PE probeは文字列markerではなくimport tableのWinsock API群で補強する。"""

    symbols = [b"WSAStartup", b"socket", b"connect", b"send", b"recv"]

    def fake_pe(*, data: bytes, fast_load: bool) -> SimpleNamespace:
        assert data.startswith(b"MZ")
        assert fast_load is False
        return SimpleNamespace(
            DIRECTORY_ENTRY_IMPORT=[
                SimpleNamespace(
                    dll=b"WS2_32.dll",
                    imports=[SimpleNamespace(name=item) for item in symbols],
                )
            ]
        )

    monkeypatch.setattr(extractor.pefile, "PE", fake_pe)
    sample = b"MZ fixture |944:1o|42.001.15.891:1p|"
    accepted = extractor._vvas_pe_import_evidence(sample)
    assert accepted["matched"] is True
    assert accepted["required_groups"] == {
        "ws2_32_library": True,
        "winsock_initialization": True,
        "socket_creation": True,
        "connection": True,
        "send": True,
        "receive": True,
    }

    symbols.remove(b"recv")
    rejected = extractor._vvas_pe_import_evidence(sample)
    assert rejected["matched"] is False

    weak_extract = extractor.extract(b"prefix |944:1o|42.001.15.891:1p|")
    assert weak_extract["config"]["static_config_recovered"] is False
    assert weak_extract["findings"] == []


def test_vvas_detector_probe_rejects_invalid_format_and_import_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未知format、壊れたPE、import上限超過を証拠なしで拒否する。"""

    sample = b"MZ fixture odaktomk |944:1o|42.001.15.891:1p|"
    assert (
        extractor.probe_vvas_config(sample, input_format="archive")["matched"] is False
    )

    def invalid_pe(*, data: bytes, fast_load: bool) -> SimpleNamespace:
        del data, fast_load
        raise extractor.pefile.PEFormatError("invalid")

    monkeypatch.setattr(extractor.pefile, "PE", invalid_pe)
    assert extractor.probe_vvas_config(sample, input_format="pe")["matched"] is False

    many = [SimpleNamespace(name=b"send") for _ in range(4)]
    monkeypatch.setattr(
        extractor.pefile,
        "PE",
        lambda **_kwargs: SimpleNamespace(
            DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(dll=b"WS2_32.dll", imports=many)]
        ),
    )
    monkeypatch.setattr(extractor, "MAXIMUM_PE_IMPORTS", 3)
    limited = extractor.probe_vvas_config(sample, input_format="pe")
    assert limited["matched"] is False
    assert limited["evidence"] == {}


def test_vvas_pe_probe_binds_required_apis_to_ws2_32_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別DLLの同名importをWS2_32証拠へ横断集約しない。"""

    symbols = [b"WSAStartup", b"socket", b"connect", b"send", b"recv"]
    image = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(
                dll=b"WS2_32.dll",
                imports=[SimpleNamespace(name=None)],
            ),
            SimpleNamespace(
                dll=b"unrelated.dll",
                imports=[SimpleNamespace(name=item) for item in symbols],
            ),
        ]
    )
    monkeypatch.setattr(extractor.pefile, "PE", lambda **_kwargs: image)
    sample = b"MZ fixture |944:1o|42.001.15.891:1p|"

    rejected = extractor.probe_vvas_config(sample, input_format="pe")

    assert rejected["matched"] is False
    assert rejected["evidence"] == {}


def test_vvas_pe_probe_rejects_required_apis_split_across_duplicate_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同名WS2_32 descriptor間のAPI unionを終端構造へ昇格しない。"""

    image = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(
                dll=b"WS2_32.dll",
                imports=[
                    SimpleNamespace(name=b"WSAStartup"),
                    SimpleNamespace(name=b"socket"),
                    SimpleNamespace(name=b"connect"),
                ],
            ),
            SimpleNamespace(
                dll=b"WS2_32.dll",
                imports=[
                    SimpleNamespace(name=b"send"),
                    SimpleNamespace(name=b"recv"),
                ],
            ),
        ]
    )
    monkeypatch.setattr(extractor.pefile, "PE", lambda **_kwargs: image)
    sample = b"MZ fixture |944:1o|42.001.15.891:1p|"

    rejected = extractor.probe_vvas_config(sample, input_format="pe")

    assert rejected["matched"] is False
    assert rejected["supports_family_attribution"] is False
    assert rejected["evidence"] == {}


def test_vvas_detector_probe_applies_input_limit_before_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """vvaS probeは上限超過入力で文字列parserを呼ばない。"""

    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_PROBE_INPUT_SIZE", 4)
    monkeypatch.setattr(
        extractor,
        "_bounded_strings",
        lambda _data: pytest.fail("入力上限の後に文字列抽出を呼んではならない"),
    )
    result = extractor.probe_vvas_config(b"MZ123", input_format="pe")
    assert result["matched"] is False
    assert result["evidence"] == {}


def test_vvas_single_byte_xor_recovery_is_route_only_and_publish_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raw XOR復元は設定候補を残すが終端payload／familyを確定しない。"""

    plaintext = b"payload odaktomk |6666:1o|061.3.911.301:1p|"
    encrypted = bytes(value ^ 0x14 for value in plaintext)
    result = extractor.extract(encrypted, r"C:\private\vvaS.bin")

    assert result["config"]["endpoints"] == ["103.119.3.160:6666"]
    assert result["config"]["vvas_recovery"]["status"] == "decoded_unique"
    assert result["config"]["vvas_recovery"]["raw_key_included"] is False
    assert result["config"]["source_name"] == "vvaS.bin"
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["candidate_config_recovered"] is True
    assert result["config"]["terminal_family_confirmed"] is False
    assert "terminal_payload" not in result

    probe = extractor.probe_xor_vvas_config(encrypted)
    serialized = json.dumps(probe, sort_keys=True)
    assert probe["matched"] is True
    assert probe["family"] is None
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["static_config_recovered"] is False
    assert probe["candidate_config_recovered"] is True
    assert probe["config"]["endpoint_count"] == 1
    assert "103.119.3.160" not in serialized
    assert "0x14" not in serialized

    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_XOR_INPUT_SIZE", 4)
    rejected = extractor.extract(encrypted)
    assert rejected["config"]["static_config_recovered"] is False
    assert "terminal_payload" not in rejected


def test_vvas_inactive_plaintext_or_xor_embedded_in_pe_is_not_terminal() -> None:
    """sectionを検証できないMZ末尾文字列は設定候補にも採用しない。"""

    plaintext = b"odaktomk |944:1o|42.001.15.891:1p|"
    plaintext_outer = extractor.extract(_minimal_x86_pe(plaintext))
    assert plaintext_outer["config"]["static_config_recovered"] is False
    assert plaintext_outer["config"]["terminal_family_confirmed"] is False
    assert plaintext_outer["config"]["candidate_config_recovered"] is False
    assert plaintext_outer["config"]["endpoints"] == []
    assert plaintext_outer["config"]["vvas_recovery"]["status"] == (
        "mapped_config_scan_incomplete_rejected"
    )
    assert plaintext_outer["config"]["vvas_recovery"]["mapped_config_scan"][
        "status"
    ] == "invalid_pe_sections"

    encrypted = bytes(value ^ 0x14 for value in plaintext)
    xor_outer = extractor.extract(_minimal_x86_pe(encrypted))
    assert xor_outer["config"]["static_config_recovered"] is False
    assert xor_outer["config"]["candidate_config_recovered"] is False
    assert xor_outer["config"]["terminal_family_confirmed"] is False
    assert xor_outer["config"]["endpoints"] == []
    assert "terminal_payload" not in xor_outer


def test_xor_b1_downloader_needs_x86_pe_and_complete_api_cluster() -> None:
    """一般URLや部分markerをXOR 0xB1次段loaderへ誤昇格しない。"""

    decoded = (
        b"wininet.dll GetProcAddress GetModuleHandleA InternetOpenA "
        b"InternetOpenUrlA InternetReadFile AddVectoredExceptionHandler VirtualAlloc "
        b"http://user:password@202.189.12.244/.bin?token=hidden"
    )
    encrypted = bytes(value ^ 0xB1 for value in decoded)
    result = extractor.extract(_minimal_x86_pe(encrypted), "loader.exe")

    assert result["config"]["variant"] == (
        "x86_single_byte_xor_wininet_next_stage_loader"
    )
    assert result["config"]["urls"] == ["http://202.189.12.244/.bin"]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["static_stage_locator_recovered"] is True
    assert result["config"]["final_c2_inherited_from_next_stage_url"] is False
    assert result["config"]["next_stage_download"]["key_size"] == 1
    assert result["config"]["next_stage_download"]["raw_key_included"] is False
    assert "fixed_key" not in result["config"]["next_stage_download"]
    assert result["findings"][0]["role"] == "next_stage_download"
    assert result["findings"][0]["confidence"] == "confirmed_static_stage_locator"

    probe = extractor.probe_xor_b1_downloader(_minimal_x86_pe(encrypted))
    serialized = json.dumps(probe, sort_keys=True)
    assert probe["matched"] is True
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["static_config_recovered"] is False
    assert probe["static_stage_locator_recovered"] is True
    assert "202.189.12.244" not in serialized
    assert "fixed_key" not in serialized
    assert "0xB1" not in serialized
    assert "x86_xor_b1" not in serialized

    no_pe = extractor.extract(encrypted)
    assert no_pe["config"]["static_config_recovered"] is False
    incomplete = bytes(
        value ^ 0xB1
        for value in (
            b"wininet.dll GetProcAddress GetModuleHandleA InternetOpenA "
            b"InternetOpenUrlA InternetReadFile http://202.189.12.244/.bin"
        )
    )
    partial = extractor.extract(_minimal_x86_pe(incomplete))
    assert partial["config"]["static_config_recovered"] is False
    assert partial["findings"] == []


def test_xor_b1_downloader_skips_string_scan_without_wininet_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """必須markerのない一般x86 PEでは全文文字列列挙を開始しない。"""

    monkeypatch.setattr(
        extractor,
        "_bounded_strings",
        lambda _data: pytest.fail("WinINet marker不在で文字列走査してはいけません"),
    )

    assert extractor._extract_xor_b1_downloader(
        _minimal_x86_pe(b"unrelated encrypted body"),
        "sample.exe",
    ) is None


@pytest.mark.parametrize("width", [32, 40, 64])
def test_public_urls_redact_short_opaque_path_tokens(width: int) -> None:
    """32/40/64文字のopaque path tokenを公開URLへ残さない。"""

    token = "A1b2" * (width // 4)
    urls = extractor._public_urls([f"https://stage.example/{token}"])

    assert urls == ["https://stage.example/[REDACTED]"]
    assert token not in json.dumps(urls)


def test_codemark_stage_recovers_correlated_reversed_third_slot() -> None:
    """header 2 slotと一致する末尾UTF-16LE反転設定から第3 slotを追加する。"""

    stage = _codemark_stage()
    config = nvml_dat.parse_codemark_config(stage)
    expected = [
        "115.190.205.255:66",
        "115.190.205.255:8888",
        "115.190.205.255:6688",
    ]
    assert config["endpoints"] == expected
    assert config["trailing_config"]["status"] == "decoded_correlated_three_slots"
    assert config["trailing_config"]["field_count"] == 10
    assert config["trailing_config"]["raw_config_included"] is False

    result = extractor.extract(stage, "recovered-shellcode.bin")
    assert result["config"]["variant"] == "winos_codemark_recovered_stage"
    assert result["config"]["endpoints"] == expected
    assert result["config"]["family_attribution_basis"] == (
        "validated_raw_x64_shellcode_and_codemark_structure"
    )
    assert all(item["role"] == "static_config_c2" for item in result["findings"])
    probe = extractor.probe_codemark_terminal_config(stage)
    assert probe["matched"] is True
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False


def test_codemark_trailing_t_fields_are_transport_selectors() -> None:
    """t=0もUDP endpointとして保持し、固定header enabledとは分離する。"""

    config = nvml_dat.parse_codemark_config(
        _codemark_stage(transports=(1, 0, 0))
    )

    assert config["endpoints"] == [
        "115.190.205.255:66",
        "115.190.205.255:8888",
        "115.190.205.255:6688",
    ]
    assert [slot["transport_selector"] for slot in config["slots"]] == [1, 0, 0]
    assert [slot["transport"] for slot in config["slots"]] == ["tcp", "udp", "udp"]
    assert [slot["header_enabled"] for slot in config["slots"]] == [True, True, None]
    assert all(slot["active"] is True for slot in config["slots"])
    assert all(slot["enabled"] is True for slot in config["slots"])
    assert config["trailing_config"]["transport_selector_semantics"] == {
        "0": "udp",
        "1": "tcp",
    }


def test_codemark_transport_difference_is_part_of_config_identity() -> None:
    """同じhost／portでもtransportが異なる末尾候補は相反として拒否する。"""

    first = _codemark_stage(transports=(1, 0, 0))
    second = _codemark_stage(transports=(1, 0, 1))
    marker_offset = second.index(nvml_dat.CODEMARK)
    first_length = int.from_bytes(
        second[marker_offset + 0x20 : marker_offset + 0x24], "little"
    )
    second_length = int.from_bytes(
        second[marker_offset + 0x2C : marker_offset + 0x30], "little"
    )
    tail_offset = (
        marker_offset
        + nvml_dat.CODEMARK_HEADER_SIZE
        + first_length
        + second_length
    )

    with pytest.raises(nvml_dat.NvmlDatError):
        nvml_dat.parse_codemark_config(first + b"\0\0" + second[tail_offset:])


def test_codemark_trailing_config_cannot_reactivate_disabled_header_slot() -> None:
    """固定headerで無効なslotを末尾transport selectorだけで有効化しない。"""

    config = nvml_dat.parse_codemark_config(
        _codemark_stage(
            transports=(1, 0, 0),
            header_enabled=(True, False),
        )
    )

    assert config["endpoints"] == ["115.190.205.255:66"]
    assert config["trailing_config"]["status"] == "not_recovered_or_not_correlated"
    assert config["slots"][1]["header_enabled"] is False
    assert config["slots"][1]["endpoint"] is None


def test_codemark_probe_rejects_config_in_arbitrary_or_container_bytes() -> None:
    """codemark境界だけを任意blob/MZ/containerの高信頼証拠にしない。"""

    config_only = _codemark_stage()[0x400:]
    arbitrary = b"\0" * 0x400 + config_only
    samples = (
        arbitrary,
        b"MZ" + _codemark_stage(),
        b"PK\x03\x04" + _codemark_stage(),
        bytes.fromhex("d0cf11e0a1b11ae1") + _codemark_stage(),
    )

    for sample in samples:
        probe = extractor.probe_codemark_terminal_config(sample)
        assert probe["matched"] is False
        assert probe["supports_family_attribution"] is False
        assert probe["evidence"] == {}


def test_codemark_trailing_slot_requires_header_correlation_and_unique_value() -> None:
    """先頭2 slot不一致と複数の異なる第3 slotを昇格しない。"""

    mismatched = _codemark_stage().replace(
        "|p1:115.190.205.255"[::-1].encode("utf-16le"),
        "|p1:198.51.100.20"[::-1].encode("utf-16le"),
    )
    base = nvml_dat.parse_codemark_config(mismatched)
    assert base["endpoints"] == [
        "115.190.205.255:66",
        "115.190.205.255:8888",
    ]
    assert base["trailing_config"]["status"] == "not_recovered_or_not_correlated"

    first = _codemark_stage()
    second_trailing = _codemark_stage(third_host="198.51.100.20")
    second_marker = second_trailing.find(nvml_dat.CODEMARK)
    second_tail_offset = second_marker + nvml_dat.CODEMARK_HEADER_SIZE + 32
    ambiguous = first + b"\0\0" + second_trailing[second_tail_offset:]
    with pytest.raises(nvml_dat.NvmlDatError):
        nvml_dat.parse_codemark_config(ambiguous)


def test_codemark_occurrence_limit_is_fail_closed() -> None:
    """探索上限より後ろの異なるmarkerを黙って無視しない。"""

    with pytest.raises(nvml_dat.NvmlDatError, match="出現数"):
        nvml_dat.parse_codemark_config(
            nvml_dat.CODEMARK * (nvml_dat.MAX_CODEMARK_OCCURRENCES + 1)
        )


def _two_slot_codemark(*, second_host: str, second_enabled: bool) -> bytes:
    first = b"198.51.100.24\0"
    second = second_host.encode("ascii") + b"\0"
    header = bytearray(nvml_dat.CODEMARK_HEADER_SIZE)
    header[: len(nvml_dat.CODEMARK)] = nvml_dat.CODEMARK
    header[0x20:0x24] = len(first).to_bytes(4, "little")
    header[0x24:0x28] = (443).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(second).to_bytes(4, "little")
    header[0x30:0x34] = (8443).to_bytes(4, "little")
    header[0x34:0x38] = int(second_enabled).to_bytes(4, "little")
    return bytes(header) + first + second


def test_codemark_uniqueness_includes_disabled_backup_slots() -> None:
    """active endpointが同じでもbackup slotが異なる複数設定は曖昧拒否する。"""

    first = _two_slot_codemark(second_host="backup-a.example", second_enabled=False)
    second = _two_slot_codemark(second_host="backup-b.example", second_enabled=False)
    with pytest.raises(nvml_dat.NvmlDatError, match="一意"):
        nvml_dat.parse_codemark_config(first + b"\0\0" + second)


def test_optional_trailing_candidate_limit_is_fail_closed() -> None:
    """末尾候補上限で相反slotを見落とし得る場合はheader fallbackを確定しない。"""

    base = _two_slot_codemark(second_host="backup.example", second_enabled=True)
    noisy = (("A" * 24 + "\0").encode("utf-16le")) * (
        nvml_dat.MAX_TRAILING_WIDE_CANDIDATES + 1
    )
    with pytest.raises(
        nvml_dat.NvmlDatOptionalConfigLimit,
        match="候補数",
    ):
        nvml_dat.parse_codemark_config(base + noisy)


def test_optional_trailing_candidate_length_limit_is_fail_closed() -> None:
    """過長な単一候補を捨ててheader 2-slotへfallbackしない。"""

    base = _two_slot_codemark(second_host="backup.example", second_enabled=True)
    oversized = ("A" * (nvml_dat.MAX_TRAILING_CONFIG_CHARACTERS + 1)).encode("utf-16le")

    with pytest.raises(
        nvml_dat.NvmlDatOptionalConfigLimit,
        match="文字数",
    ):
        nvml_dat.parse_codemark_config(base + oversized)


def test_optional_trailing_candidate_total_limit_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候補ごとの長さ内でも候補総文字数の上限超過はfail-closedにする。"""

    base = _two_slot_codemark(second_host="backup.example", second_enabled=True)
    candidates = (
        ("A" * nvml_dat.MIN_TRAILING_CONFIG_CHARACTERS + "\0")
        + ("B" * nvml_dat.MIN_TRAILING_CONFIG_CHARACTERS + "\0")
    ).encode("utf-16le")
    monkeypatch.setattr(
        nvml_dat,
        "MAX_TRAILING_TOTAL_CHARACTERS",
        nvml_dat.MIN_TRAILING_CONFIG_CHARACTERS,
    )

    with pytest.raises(nvml_dat.NvmlDatOptionalConfigLimit, match="総文字数"):
        nvml_dat.parse_codemark_config(base + candidates)


def test_vvas_string_scan_limit_rejects_partial_unique_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上限後の相反設定を未走査のまま先頭設定だけで確定しない。"""

    first = b"|6666:1o|061.3.911.301:1p|"
    conflicting = b"|7777:1o|7.001.15.891:1p|"
    sample = b"odaktomk\0" + first + b"\0" + conflicting
    monkeypatch.setattr(extractor, "MAXIMUM_STRING_COUNT", 2)

    values, scan = extractor._bounded_strings(sample)
    assert values == ["odaktomk", first.decode("ascii")]
    assert scan["completed"] is False
    assert scan["truncated"] is True
    assert scan["truncation_reasons"] == ["maximum_string_count"]

    probe = extractor.probe_vvas_config(sample, input_format="data")
    assert probe["matched"] is False
    assert probe["supports_family_attribution"] is False
    assert probe["static_config_recovered"] is False
    assert probe["analysis_limits"]["string_scan"]["truncated"] is True

    extracted = extractor.extract(sample)
    assert extracted["config"]["static_config_recovered"] is False
    assert extracted["config"]["endpoints"] == []
    assert extracted["config"]["string_scan"]["truncated"] is True
    assert extracted["config"]["vvas_recovery"]["status"] == (
        "string_scan_truncated_rejected"
    )


def test_permuted_dat_rejects_above_memory_safe_limit_before_table_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """大容量permutationは巨大なPython整数表を作る前にfail-closedとする。"""

    monkeypatch.setattr(nvml_dat, "MAX_PERMUTED_PAYLOAD_SIZE", 8)
    with pytest.raises(nvml_dat.NvmlDatError, match="permutation対象"):
        nvml_dat._scatter_dwords(b"A" * 12, 12)


def test_codemark_input_size_limit_precedes_marker_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """直接stage parserにも共有extractorと独立した入力上限を適用する。"""

    monkeypatch.setattr(nvml_dat, "MAX_PAYLOAD_SIZE", 4)
    with pytest.raises(nvml_dat.NvmlDatError, match="上限"):
        nvml_dat.parse_codemark_config(b"codemark")


def test_common_extractor_input_limit_precedes_variant_parsers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """共有上限を超える入力では各variant parserを呼ばない。"""

    monkeypatch.setattr(extractor, "MAXIMUM_INPUT_SIZE", 4)
    monkeypatch.setattr(
        extractor,
        "n520_structural_evidence",
        lambda _data: pytest.fail("上限超過後にN520 parserを呼んではならない"),
    )
    result = extractor.extract(b"MZ123")
    assert result["config"]["recovery_status"] == "not_attempted_input_size_limit"
    assert result["config"]["static_config_recovered"] is False
    assert result["findings"] == []
