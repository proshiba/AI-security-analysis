"""PureLogs YqTY/Pn5 resource静的復元器の境界テスト。"""

from __future__ import annotations

import base64
import importlib.util
import json
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from extractors.purelogs import extractor as purelogs_extractor
from extractors.purelogs import yqty_resource


def _seven_bit(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _protobuf_varint(field: int, value: int) -> bytes:
    return _seven_bit(field << 3) + _seven_bit(value)


def _protobuf_bytes(field: int, value: bytes) -> bytes:
    return _seven_bit((field << 3) | 2) + _seven_bit(len(value)) + value


def _config(*, extra_key: bytes | None = None) -> str:
    inner = b"".join(
        (
            _protobuf_bytes(1, b"https://fixture.example.test"),
            _protobuf_varint(2, 8443),
            _protobuf_bytes(3, b""),
            _protobuf_bytes(5, b"fixture-build"),
            _protobuf_bytes(6, b"Default"),
            _protobuf_bytes(7, b"K" * 32),
            _protobuf_bytes(8, extra_key) if extra_key is not None else b"",
        )
    )
    return base64.b64encode(_protobuf_bytes(7, inner)).decode("ascii")


def _table(
    records: tuple[str, ...],
    *,
    prefix: bytes = b"\x27\x2e\xca\xa9",
) -> bytes:
    output = bytearray(prefix)
    for value in records:
        encoded = value.encode("utf-8")
        output.extend(_seven_bit(len(encoded)))
        output.extend(encoded)
    return bytes(output)


def _resource(
    *,
    records: tuple[str, ...] | None = None,
    prefix: bytes = bytes(range(19)),
    table_prefix: bytes = b"\x27\x2e\xca\xa9",
) -> tuple[bytes, bytes, tuple[str, ...]]:
    values = records or (
        "/plugin",
        "/userinfo",
        "/filesearch/req",
        "/finish",
        _config(),
    )
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    packed = (
        compressor.compress(_table(values, prefix=table_prefix)) + compressor.flush()
    )
    clear = prefix + packed

    key = bytes(range(32))
    iv = bytes(range(16, 32))
    identifier = b"fixturePn5"
    header = (
        _seven_bit(len(identifier)) + identifier + bytes((3, 2, 24, len(key))) + key
    )
    encrypted_header = bytes(
        value ^ iv[index % len(iv)] for index, value in enumerate(header)
    )
    padding = 16 - (len(clear) % 16)
    padded = clear + bytes((padding,)) * padding
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    blob = (
        len(header).to_bytes(2, "little")
        + encrypted_header
        + bytes((len(iv),))
        + iv
        + ciphertext
    )
    return blob, clear, values


def _shape(
    token: int,
    owner: int,
    *,
    name: str = "x",
    signature: bytes = b"",
    opcodes: tuple[str, ...] = (),
    integers: tuple[int, ...] = (),
    operands: tuple[int, ...] = (),
) -> yqty_resource._MethodShape:
    return yqty_resource._MethodShape(
        token=token,
        owner_token=owner,
        name=name,
        signature=signature,
        opcodes=opcodes,
        integer_constants=integers,
        method_operands=operands,
    )


def test_decodes_unique_validated_boundary_without_publishing_key() -> None:
    """一意な境界・文字列・設定を復元し、鍵materialは公開しない。"""

    blob, _clear, records = _resource()

    result = yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=1)

    assert result.records == records
    assert result.compressed_offset == 19
    assert result.string_table_offset == 4
    evidence = result.public_evidence()
    assert yqty_resource.public_recovery_evidence(result) == evidence
    assert evidence["profile"] == "pn5_validated_boundary_search_v1"
    assert evidence["boundary_candidate_count"] == 1
    assert evidence["pn5_cil_profile_verified"] is True
    published = json.dumps(evidence, sort_keys=True)
    assert bytes(range(32)).hex() not in published
    assert _config() not in published


def test_boundary_search_inflates_each_compressed_offset_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """各compressed offsetを1回だけ展開し、table探索で再展開しない。"""

    blob, clear, _records = _resource()
    original = yqty_resource._inflate_raw_deflate
    input_lengths: list[int] = []

    def _counted(data: bytes) -> bytes:
        input_lengths.append(len(data))
        return original(data)

    monkeypatch.setattr(yqty_resource, "_inflate_raw_deflate", _counted)

    yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=1)

    expected_attempts = min(yqty_resource.MAX_BOUNDARY_OFFSET, len(clear) - 1) + 1
    assert len(input_lengths) == expected_attempts
    assert len(input_lengths) == len(set(input_lengths))


@pytest.mark.parametrize(
    ("constant", "message"),
    (
        ("MAX_BOUNDARY_TOTAL_COMPRESSED_BYTES", "総入力work上限"),
        ("MAX_BOUNDARY_TOTAL_INFLATED_BYTES", "総展開work上限"),
        ("MAX_BOUNDARY_TOTAL_PARSE_BYTES", "総parse work上限"),
        ("MAX_BOUNDARY_PARSE_ATTEMPTS", "総parse work上限"),
    ),
)
def test_boundary_search_work_budgets_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    message: str,
) -> None:
    """入力・展開・parseの総work budget超過を部分結果で受理しない。"""

    blob, _clear, _records = _resource()
    monkeypatch.setattr(yqty_resource, constant, 0)

    with pytest.raises(yqty_resource.PureLogsYqtyError, match=message):
        yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=1)


def test_boundary_search_candidate_budget_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """semantic候補経路の総数が上限を超えた場合は曖昧入力として拒否する。"""

    records = (
        "/plugin",
        "/userinfo",
        "/filesearch/req",
        "/finish",
        _config(),
    )
    inflated = _table(records)
    monkeypatch.setattr(
        yqty_resource,
        "_inflate_raw_deflate",
        lambda _data: inflated,
    )
    monkeypatch.setattr(yqty_resource, "MAX_BOUNDARY_CANDIDATES", 1)

    with pytest.raises(
        yqty_resource.PureLogsYqtyError,
        match="候補数が安全上限",
    ):
        yqty_resource._decode_boundary(b"AB")


def test_decodes_variable_inner_prefix_and_reports_bounded_offsets() -> None:
    """build固有の展開後prefixを越えて最大の完全tableだけを採用する。"""

    blob, _clear, records = _resource(table_prefix=bytes(range(12)))

    result = yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=1)

    assert result.records == records
    assert result.compressed_offset == 19
    assert result.string_table_offset == 12
    assert result.boundary_candidate_count == 1
    assert result.equivalent_boundary_count >= 1


def test_yqty_result_flows_through_detector_and_extractor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """YqTY固有result型をdetectorとconfig/C2 extractorが同一PE層で扱う。"""

    blob, _clear, _records = _resource()
    recovered = yqty_resource.decode_yqty_resource_blob(
        blob,
        pn5_profile_count=1,
    )
    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )
    extracted = purelogs_extractor.extract(
        b"MZ synthetic YqTY terminal", "terminal.exe"
    )
    assert extracted["config"]["confidence"] == "confirmed"
    assert extracted["config"]["configured_endpoints"] == ["fixture.example.test:8443"]
    assert (
        extracted["config"]["managed_resource_recovery"]["profile"]
        == "pn5_validated_boundary_search_v1"
    )

    detector_path = (
        Path(__file__).parents[2]
        / "analysis-framework"
        / "malware"
        / "purelogs"
        / "detect.py"
    )
    specification = importlib.util.spec_from_file_location(
        "purelogs_yqty_detector_test",
        detector_path,
    )
    detector = importlib.util.module_from_spec(specification)
    assert specification is not None and specification.loader is not None
    specification.loader.exec_module(detector)
    monkeypatch.setattr(
        detector,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )
    detected = detector.detect(b"MZ synthetic YqTY terminal")
    assert detected["matched"] is True
    assert detected["managed_resource_recovery"]["profile"] == (
        "pn5_validated_boundary_search_v1"
    )


def test_offset_21_and_30_resync_outputs_fail_complete_table_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raw Deflate suffixが展開できても完全tableでないoffset 21/30を拒否する。"""

    blob, clear, records = _resource()
    full_table = _table(records)
    original = yqty_resource._inflate_raw_deflate
    observed: set[int] = set()

    def _suffix_model(data: bytes) -> bytes:
        offset = len(clear) - len(data)
        observed.add(offset)
        if offset == 19:
            return full_table
        if offset == 21:
            # 実検体のresync候補と同じくwrapper途中から始まり、4 byteを
            # 捨てても先頭recordの長さ境界を失う。
            return full_table[2:]
        if offset == 30:
            return b"\x37\x62\x79\xcc" + full_table[11:]
        return original(data)

    monkeypatch.setattr(yqty_resource, "_inflate_raw_deflate", _suffix_model)

    result = yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=1)

    assert result.compressed_offset == 19
    assert {19, 21, 30}.issubset(observed)
    with pytest.raises(yqty_resource.PureLogsYqtyError):
        yqty_resource._parse_string_table(full_table[2:])
    with pytest.raises(yqty_resource.PureLogsYqtyError):
        yqty_resource._parse_string_table(b"\x37\x62\x79\xcc" + full_table[11:])


def test_rejects_multiple_32_byte_config_key_candidates() -> None:
    """protobufに32 byte鍵候補が複数ある場合は設定へ昇格させない。"""

    blob, _clear, _records = _resource(
        records=(
            "/plugin",
            "/userinfo",
            "/filesearch/req",
            "/finish",
            _config(extra_key=b"Z" * 32),
        )
    )

    with pytest.raises(
        yqty_resource.PureLogsYqtyError,
        match="検証済み圧縮境界",
    ):
        yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=1)


def test_reviewed_pn5_type_shape_is_unique_and_fail_closed() -> None:
    """Pn5型はmethod名/token/hashではなくCILとsignatureの形で一意化する。"""

    owner = 0x02000010
    constructor = _shape(
        0x06000020,
        owner,
        name=".ctor",
        opcodes=("ldc.i4", "newobj", "newobj", "ret"),
        integers=(32769,),
    )
    read_one = _shape(
        0x06000021,
        owner,
        signature=yqty_resource._PN5_READ_SIGNATURE,
        opcodes=("ldlen", "ret"),
    )
    read_two = _shape(
        0x06000022,
        owner,
        signature=yqty_resource._PN5_READ_SIGNATURE,
        opcodes=("switch", "ret"),
    )
    bool_core = _shape(
        0x06000023,
        owner,
        signature=yqty_resource._PN5_BOOL_SIGNATURE,
        opcodes=("switch", "switch", "switch", "ldloca.s") + ("nop",) * 396,
    )
    wrapper = _shape(
        0x06000030,
        0x02000011,
        opcodes=("switch", "switch", "newarr", "ldlen", "newobj", "ret"),
        integers=(81920,),
        operands=(constructor.token,),
    )
    methods = (constructor, read_one, read_two, bool_core, wrapper)

    assert yqty_resource._pn5_profile_count(methods) == 1
    assert (
        yqty_resource._pn5_profile_count(
            methods[:-1]
            + (
                _shape(
                    wrapper.token,
                    wrapper.owner_token,
                    opcodes=wrapper.opcodes,
                    integers=(4096,),
                    operands=wrapper.method_operands,
                ),
            )
        )
        == 0
    )


def test_rejects_unverified_pn5_profile_and_truncated_ciphertext() -> None:
    """CIL profile未確認と不完全AES暗号文をともにfail-closedで拒否する。"""

    blob, _clear, _records = _resource()
    with pytest.raises(yqty_resource.PureLogsYqtyError, match="Pn5 CIL profile"):
        yqty_resource.decode_yqty_resource_blob(blob, pn5_profile_count=0)
    with pytest.raises(yqty_resource.PureLogsYqtyError, match="暗号文長"):
        yqty_resource.decode_yqty_resource_blob(blob[:-1], pn5_profile_count=1)
