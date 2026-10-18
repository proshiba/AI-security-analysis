"""PureRATの実detector・handler・one-shot接続を回帰検証する。"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON_ROOT = REPOSITORY_ROOT / "analysis-framework" / "common"
CLASSIFIERS_ROOT = REPOSITORY_ROOT / "analysis-framework" / "classifiers"
for import_root in (REPOSITORY_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import analyze_sample as one_shot
from handler_catalog import (
    discover_handlers,
    preflight_handler_for_assessment,
)

REGISTRY = REPOSITORY_ROOT / "analysis-framework" / "registry" / "malware_types.json"
FAMILY_HANDLER_ID = "purehvnc:analysis.framework.malware.purehvnc.extract.config.py:extract_config"
SHARED_HANDLER_ID = "purehvnc:extractors.purehvnc.extractor.py:extract"
HOST = "purerat.example.test"
PORTS = [56001, 56002, 56003]


def _varint(value: int) -> bytes:
    """非負整数をprotobuf varintへ変換する。"""

    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _bytes_field(number: int, value: bytes) -> bytes:
    """protobufのlength-delimited fieldを作る。"""

    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _pfx_base64() -> bytes:
    """family detector用の自己署名証明書をmemory内で作る。"""

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PureRAT Agent")])
    start = datetime(2026, 1, 1, tzinfo=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        b"fixture",
        key,
        certificate,
        None,
        serialization.NoEncryption(),
    )
    return base64.b64encode(pfx)


def _compressed_length(value: int) -> bytes:
    """CLR metadataのcompressed unsigned integerを作る。"""

    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([(value >> 8) | 0x80, value & 0xFF])
    return bytes(
        [
            (value >> 24) | 0xC0,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF,
        ]
    )


def _managed_pe(strings: list[str]) -> bytes:
    """実行コードを持たないCLR headerと#US heapだけのPEを作る。"""

    user_strings = bytearray(b"\0")
    for value in strings:
        raw = value.encode("utf-16le") + b"\0"
        user_strings += _compressed_length(len(raw)) + raw
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, 0, 0)
    streams = [
        (b"#~\0", tables),
        (b"#Strings\0", b"\0"),
        (b"#US\0", bytes(user_strings)),
    ]
    version = b"v4.0.30319\0\0\0"
    header = bytearray(
        struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(streams))
    )
    stream_header_size = sum(8 + ((len(name) + 3) & ~3) for name, _content in streams)
    offset = len(header) + stream_header_size
    stream_data = bytearray()
    for name, content in streams:
        header += struct.pack("<II", offset + len(stream_data), len(content)) + name
        header += b"\0" * ((-len(name)) % 4)
        stream_data += content
    metadata = bytes(header + stream_data)
    data = bytearray(0x2000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x14C,
        1,
        0,
        0,
        0,
        0xE0,
        0x2102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 14 * 8, 0x1000, 0x48)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1800, 0x1000, 0x1E00, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)
    struct.pack_into("<IHHII", data, 0x200, 0x48, 2, 5, 0x1080, len(metadata))
    struct.pack_into("<I", data, 0x210, 1)
    data[0x280 : 0x280 + len(metadata)] = metadata
    return bytes(data)


def _purerat_fixture() -> bytes:
    """full-schema設定とPKCS#12を持つ不活性managed PEを作る。"""

    message = (
        _bytes_field(1, HOST.encode())
        + b"".join(_varint(2 << 3) + _varint(port) for port in PORTS)
        + _bytes_field(3, _pfx_base64())
        + _bytes_field(4, b"pipeline-fixture")
        + _varint(5 << 3)
        + _varint(1)
        + _varint(6 << 3)
        + _varint(0)
        + _bytes_field(7, b"fixture-task")
        + _bytes_field(8, b"fixture-environment")
        + _bytes_field(9, b"fixture-mutex")
    )
    encoded = base64.b64encode(gzip.compress(message, mtime=0)).decode()
    return _managed_pe([encoded, "4.4.1"])


def _handler_specs():
    specs = [item for item in discover_handlers() if item.id in {FAMILY_HANDLER_ID, SHARED_HANDLER_ID}]
    assert {item.id for item in specs} == {
        FAMILY_HANDLER_ID,
        SHARED_HANDLER_ID,
    }
    return specs


def test_family_unspecified_one_shot_applies_both_purerat_handlers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """実detectorで選んだ同一PEへ両handlerを適用しC2を投影する。"""

    data = _purerat_fixture()
    digest = hashlib.sha256(data).hexdigest()
    classification = one_shot.classify_sample.classify_bytes(
        data,
        Path("purerat-static-fixture.exe"),
        REGISTRY,
    )
    evaluation = next(item for item in classification["detector_evaluations"] if item["malware_type"] == "purehvnc")
    assert classification["malware_type"] == "purehvnc"
    assert evaluation["detector_matched"] is True
    assert evaluation["supports_family_attribution"] is True

    specs = _handler_specs()
    for spec in specs:
        preflight = preflight_handler_for_assessment(
            spec,
            actual_format="pe",
            input_size=len(data),
        )
        assert preflight["eligible"] is True, preflight["blockers"]
        assert preflight["blockers"] == []
        assert preflight["sample_execution_allowed"] is False
        assert preflight["network_allowed"] is False
        assert preflight["filesystem_write_allowed"] is False

    monkeypatch.setattr(
        one_shot,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {
                "analysis_coverage": {"status": "complete"},
                "executed_sample": False,
                "network_contacted": False,
            },
            "complete",
        ),
    )
    unit = one_shot.InputUnit(
        source_name="purerat-static-fixture.exe",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )
    output = tmp_path / "out"

    one_shot.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=specs,
        registered={"purehvnc"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = output / "cases" / digest
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    patterns = json.loads((case_dir / "communication-patterns.json").read_text(encoding="utf-8"))
    c2 = json.loads((case_dir / "c2-analysis.json").read_text(encoding="utf-8"))

    assert report["classification"]["selected_family"] == "purehvnc"
    assert report["classification"]["automation_family"] == "purehvnc"
    executions = {item["handler_id"]: item for item in report["handler_executions"]}
    assert set(executions) == {FAMILY_HANDLER_ID, SHARED_HANDLER_ID}
    assert all(item["status"] == "succeeded" for item in executions.values())
    assert all(item["selected_layer_sha256"] == digest for item in executions.values())
    assert report["candidate_handler_assessment"]["status"] == "no_candidates"
    assert patterns["family"] == "purehvnc"
    assert patterns["config"]["static_config_recovered"] is True
    assert {item["value"] for item in patterns["communication"]["candidate_patterns"]} >= {
        f"{HOST}:{port}" for port in PORTS
    }
    phases = {item["phase"]: item for item in c2["phase_evidence"]}
    assert phases["family_config_extraction"]["status"] == "completed"
    assert phases["c2_endpoint_extraction"]["status"] == "completed"
    assert patterns["safety"]["sample_executed"] is False
    assert patterns["safety"]["network_contacted"] is False
