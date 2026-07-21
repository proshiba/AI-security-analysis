"""第20バッチで追加した解析器と公開情報の回帰テスト。"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib

import pytest
import yara


ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK = ROOT / "analysis-framework"
BATCH = ROOT / "analysis-results" / "research" / "malwarebazaar" / "batches" / "batch-0020"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


YUANBAO = _load(
    "batch20_yuanbao",
    FRAMEWORK / "malware" / "valleyrat" / "campaigns" / "yuanbao_sideload" / "analyze_bundle.py",
)
OFFLOADER = _load(
    "batch20_offloader",
    FRAMEWORK / "malware" / "dotnet_resource_loader" / "offloader_zip.py",
)
NANOCORE = _load(
    "batch20_nanocore",
    FRAMEWORK / "malware" / "nanocore" / "extract_config.py",
)
PHORPIEX = _load(
    "batch20_phorpiex",
    FRAMEWORK / "malware" / "phorpiex_spam" / "extract_config_v2.py",
)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def test_yuanbao_png_concealed_data_is_measured_but_not_returned() -> None:
    hidden = b"concealed-ciphertext"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = b"\x00\x00\x00\x00"
    png = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
    png += _png_chunk(b"IDAT", zlib.compress(pixels) + hidden) + _png_chunk(b"IEND", b"")

    result = YUANBAO.parse_png_idat(png)

    assert result["width"] == 1
    assert result["height"] == 1
    assert result["concealed_size"] == len(hidden)
    assert result["concealed_data_returned"] is False


def test_offloader_zip_inspection_is_hash_only_and_rejects_traversal() -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("payload.exe", b"MZ" + b"\0" * 16)
    members = OFFLOADER.inspect_zip("resource.zip", stream.getvalue())
    assert members[0]["pe_candidate"] is True
    assert members[0]["content_returned"] is False

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../escape.exe", b"MZ")
    with pytest.raises(ValueError, match="path traversal"):
        OFFLOADER.inspect_zip("resource.zip", stream.getvalue())


def test_nanocore_typed_values_and_phorpiex_decoder() -> None:
    payload = b"\x00\x00\x00\x00"
    payload += bytes([NANOCORE.ValueType.STRING, 7]) + b"Version"
    payload += bytes([NANOCORE.ValueType.VERSION, 7]) + b"1.2.2.0"
    values = NANOCORE._typed_values(payload)
    assert values == [
        (NANOCORE.ValueType.STRING, "Version"),
        (NANOCORE.ValueType.VERSION, "1.2.2.0"),
    ]
    assert PHORPIEX.decode_not_xor(PHORPIEX.ENCRYPTED_CONTROLLER).decode("ascii") == PHORPIEX.CONTROLLER_URL


def test_batch20_publication_has_ten_unique_samples_and_safe_version_key() -> None:
    manifest = json.loads((BATCH / "manifest.json").read_text(encoding="utf-8"))
    classification = json.loads((BATCH / "classification.json").read_text(encoding="utf-8"))
    manifest_hashes = {item["sha256"] for item in manifest["samples"]}
    classified_hashes = {item["sha256"] for item in classification["samples"]}
    assert manifest["sample_count"] == 10
    assert len(manifest_hashes) == 10
    assert classified_hashes == manifest_hashes
    nanocore = next(item for item in classification["samples"] if item["family"] == "nanocore")
    assert nanocore["version"] == "v1.2.2.0"
    assert nanocore["reported_version"] == "1.2.2.0"


def test_batch20_yara_rules_compile() -> None:
    rules = [
        FRAMEWORK / "malware" / "nanocore" / "rules" / "nanocore.yar",
        FRAMEWORK / "malware" / "valleyrat" / "campaigns" / "yuanbao_sideload" / "rules" / "yuanbao_sideload.yar",
        FRAMEWORK / "malware" / "dotnet_resource_loader" / "rules" / "offloader_zip.yar",
    ]
    for rule in rules:
        yara.compile(filepath=str(rule))
