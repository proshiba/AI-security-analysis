"""正規化PEと宣言型変換の親子SHA-256を合成bytesだけで検証する。"""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys

from unpackers import profiled_transform as transforms
from unpackers import static_unpacker

# repo rootの通常pytestでも、固定された共通静的pipelineを明示的に参照する。
_FRAMEWORK = Path(__file__).resolve().parents[2] / "analysis-framework"
if str(_FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK))


def _pe_shape() -> bytes:
    """実行可能コードを持たない一sectionのPE外形だけを作る。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 28, 0x400000)
    struct.pack_into("<II", data, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, 0x98 + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, 0x98 + 92, 16)
    data[0x178:0x180] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 0x180, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, 0x178 + 36, 0x60000020)
    return bytes(data)


def _fixture(monkeypatch):
    prefix = _pe_shape()
    clear = b"MAGIC-ordinary-terminal-fixture"
    encoded = bytes(value ^ 0x5A for value in clear)
    raw = prefix + bytes(64) + encoded
    compact = prefix + encoded
    profile = transforms.validate_profile({
        "id": "fixture-compact-lineage",
        "artifact_kind": "fixture-profile-output",
        "input_formats": ["pe"],
        "operations": [{"operation": "slice", "offset": len(prefix)},
                       {"operation": "xor_byte", "key": 0x5A}],
        "validator": {"type": "magic", "magic_hex": b"MAGIC".hex()},
    })
    monkeypatch.setattr(transforms, "load_profiles", lambda _path: (profile,))
    monkeypatch.setattr(static_unpacker, "recover_inflated_pe", lambda data: (
        ({"status": "recovered", "synthetic": True}, compact) if data == raw
        else ({"status": "not_recovered", "synthetic": True}, None)
    ))
    return raw, compact, clear


def test_profile_transform_input_is_raw_layer_not_hidden_compact(monkeypatch) -> None:
    """正規化childの値をraw親のprofile結果として公開しない。"""

    raw, compact, clear = _fixture(monkeypatch)
    report, artifacts = static_unpacker.unpack_bytes(raw, "fixture.exe")
    attempt = report["profiled_transforms"]["attempts"][0]
    assert attempt["input_sha256"] == report["sha256"] == hashlib.sha256(raw).hexdigest()
    assert attempt["status"] == "validation_failed"
    assert ("pe-inflated-gap-removed", compact) in artifacts
    assert ("fixture-profile-output", clear) not in artifacts


def test_recursive_profile_output_retains_compaction_parent(monkeypatch) -> None:
    """raw→compact→profileの二段階を独立したSHA-256で保持する。"""

    from common.static_layer_pipeline import InputUnit, StaticLayerPolicy, recover_static_layers

    raw, compact, clear = _fixture(monkeypatch)
    observations = []

    def unpacker(data, name, **kwargs):
        report, artifacts = static_unpacker.unpack_bytes(data, name, **kwargs)
        observations.append((hashlib.sha256(data).hexdigest(), report))
        return report, artifacts

    unit = InputUnit("fixture.exe", raw, "raw", hashlib.sha256(raw).hexdigest(), len(raw))
    layers, _report = recover_static_layers(unit, unpacker=unpacker,
        policy=StaticLayerPolicy(max_layers=8, max_depth=3, max_layer_size=4096,
                                 max_total_size=16384, max_compression_ratio=25.0))
    by_hash = {layer.sha256: layer for layer in layers}
    compact_hash = hashlib.sha256(compact).hexdigest()
    clear_hash = hashlib.sha256(clear).hexdigest()
    assert by_hash[compact_hash].parent_sha256 == unit.outer_sha256
    assert by_hash[compact_hash].transform == "pe-inflated-gap-removed"
    assert by_hash[clear_hash].parent_sha256 == compact_hash
    assert by_hash[clear_hash].transform == "fixture-profile-output"
    for parent_hash, report in observations:
        for attempt in report.get("profiled_transforms", {}).get("attempts", []):
            if "input_sha256" in attempt:
                assert attempt["input_sha256"] == parent_hash
    assert all(report["executed"] is False and report["network_contacted"] is False
               for _digest, report in observations)
