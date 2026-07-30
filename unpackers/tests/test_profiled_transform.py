"""宣言型byte変換エンジンの回帰テスト。"""

from __future__ import annotations

import json
import struct

import pytest

from unpackers.profiled_transform import (
    TransformProfileError,
    apply_operations,
    load_profiles,
    recover_profiled_transforms,
    recover_transform_profile,
)


def _donut_fixture() -> bytes:
    instance = bytearray(0x300)
    struct.pack_into("<I", instance, 0x23C, 3)
    instance[0x240:0x24C] = b"ole32;wininet"
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


def _encode(clear: bytes, rotation: int, xor_key: int) -> bytes:
    xored = bytes(value ^ xor_key for value in clear)
    shift = rotation % len(clear)
    return xored[shift:] + xored[:shift] if shift else xored


def test_default_profile_recovers_validated_donut() -> None:
    clear = _donut_fixture()
    encoded = _encode(clear, 0x3EF14, 0xC6)
    report, artifacts = recover_profiled_transforms(
        encoded,
        input_format="data",
        source_name="riched32.dat",
    )
    assert report["status"] == "validated_artifacts_recovered"
    assert artifacts == [("rotated-xor-donut-shellcode", clear)]


def test_profile_supports_reusable_operation_and_validator_chain() -> None:
    clear = b"MAGIC-payload"
    encoded = bytes(value ^ 0x22 for value in clear[::-1])
    profile = {
        "id": "fixture_reverse_xor",
        "artifact_kind": "fixture-payload",
        "input_formats": ["data"],
        "operations": [
            {"operation": "xor_byte", "key": 0x22},
            {"operation": "reverse"},
        ],
        "validator": {"type": "magic", "magic_hex": b"MAGIC".hex()},
    }
    report, artifacts = recover_transform_profile(encoded, profile)
    assert report["status"] == "validated_artifact_recovered"
    assert artifacts == [("fixture-payload", clear)]


def test_profile_validation_is_fail_closed(tmp_path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profiles": [
                    {
                        "id": "unsafe",
                        "artifact_kind": "unsafe-output",
                        "input_formats": ["data"],
                        "operations": [{"operation": "python_eval"}],
                        "validator": {"type": "magic", "magic_hex": "4d5a"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(TransformProfileError, match="未対応operation"):
        load_profiles(path)


def test_operations_enforce_bounds_and_nonempty_output() -> None:
    with pytest.raises(TransformProfileError, match="上限"):
        apply_operations(b"abcd", [{"operation": "reverse"}], max_input_size=3)
    with pytest.raises(TransformProfileError, match="空"):
        apply_operations(
            b"abcd",
            [{"operation": "slice", "offset": 4, "length": None}],
        )
