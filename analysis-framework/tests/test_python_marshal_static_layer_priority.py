"""marshal定数候補の静的layer queue優先度を検証する。"""

from __future__ import annotations

import hashlib

from common.static_layer_pipeline import (
    InputUnit,
    StaticLayerPolicy,
    _artifact_analysis_priority,
    recover_static_layers,
)


def _unit(data: bytes = b"root") -> InputUnit:
    return InputUnit(
        source_name="sample.bin",
        data=data,
        input_kind="raw",
        outer_sha256=hashlib.sha256(data).hexdigest(),
        outer_size=len(data),
    )


def _marshal_report(data: bytes, candidate: bytes) -> dict[str, object]:
    artifact_kind = "python-marshal-sequence-base64-decoded-000"
    return {
        "status": "fixture",
        "python_marshal": {
            "schema_version": 1,
            "status": "artifacts_recovered",
            "profile": "cpython_3_8_to_3_10_marshal_v4_code_layout_candidate",
            "input": {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "coverage": {
                "bytes_consumed": len(data),
                "input_size": len(data),
                "full_consumption": True,
            },
            "candidate_set_complete": True,
            "blockers": [],
            "candidate_count": 1,
            "candidate_total_size": len(candidate),
            "candidates": [
                {
                    "index": 0,
                    "artifact_kind": artifact_kind,
                    "sha256": hashlib.sha256(candidate).hexdigest(),
                    "size": len(candidate),
                }
            ],
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "marshal_loads_used": False,
                "python_bytecode_executed": False,
                "raw_constant_published": False,
            },
        },
    }


def test_marshal_label_alone_cannot_raise_queue_priority() -> None:
    blob = b"opaque decoded fixture"

    assert (
        _artifact_analysis_priority(
            "python-marshal-sequence-base64-decoded-000",
            blob,
        )
        != -2
    )
    assert (
        _artifact_analysis_priority(
            "python-marshal-sequence-base64-decoded-000-extra",
            blob,
            verified_marshal_candidate=True,
        )
        != -2
    )
    assert (
        _artifact_analysis_priority(
            "python-marshal-sequence-base64-decoded-000",
            blob,
            verified_marshal_candidate=True,
        )
        == -2
    )


def test_unbound_marshal_label_does_not_outrank_container_content() -> None:
    calls: list[bytes] = []
    candidate = b"opaque decoded payload candidate"
    container = b"PK\x05\x06" + b"\0" * 18

    def unpacker(data: bytes, name: str, **_kwargs):
        del name
        calls.append(data)
        if data == b"root":
            return {"status": "fixture"}, [
                ("nested-container.zip", container),
                ("python-marshal-sequence-base64-decoded-000", candidate),
            ]
        return {"status": "terminal"}, []

    layers, _report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=2,
            max_layer_size=128,
            max_total_size=256,
            max_compression_ratio=100.0,
            max_archive_members=8,
        ),
    )

    assert [layer.data for layer in layers] == [b"root", container]
    assert calls == [b"root", container]


def test_duplicate_report_identity_disables_priority_instead_of_guessing() -> None:
    candidate = b"duplicate decoded payload candidate"
    artifact_kind = "python-marshal-sequence-base64-decoded-000"
    container = b"PK\x05\x06" + b"\0" * 18

    def unpacker(data: bytes, name: str, **_kwargs):
        del name
        if data == b"root":
            return _marshal_report(data, candidate), [
                (artifact_kind, candidate),
                (artifact_kind, candidate),
                ("nested-container.zip", container),
            ]
        return {"status": "terminal"}, []

    layers, _report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=2,
            max_layer_size=128,
            max_total_size=256,
            max_compression_ratio=100.0,
            max_archive_members=8,
        ),
    )

    assert [layer.data for layer in layers] == [b"root", container]


def test_marshal_candidate_is_processed_before_remaining_pyinstaller_modules() -> None:
    calls: list[bytes] = []
    candidate = b"opaque decoded payload candidate"

    def unpacker(data: bytes, name: str, **_kwargs):
        del name
        calls.append(data)
        if data == b"root":
            digest = hashlib.sha256(candidate).hexdigest()
            return {
                "status": "fixture",
                "python_marshal": {
                    "schema_version": 1,
                    "status": "artifacts_recovered",
                    "profile": ("cpython_3_8_to_3_10_marshal_v4_code_layout_candidate"),
                    "input": {
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                    "coverage": {
                        "bytes_consumed": len(data),
                        "input_size": len(data),
                        "full_consumption": True,
                    },
                    "candidate_set_complete": True,
                    "blockers": [],
                    "candidate_count": 1,
                    "candidate_total_size": len(candidate),
                    "candidates": [
                        {
                            "index": 0,
                            "artifact_kind": ("python-marshal-sequence-base64-decoded-000"),
                            "sha256": digest,
                            "size": len(candidate),
                        }
                    ],
                    "safety": {
                        "sample_executed": False,
                        "network_contacted": False,
                        "marshal_loads_used": False,
                        "python_bytecode_executed": False,
                        "raw_constant_published": False,
                    },
                },
            }, [
                ("python-marshal-base64-decoded-999", candidate),
                ("pyinstaller-python_module-000-runtime", b"runtime-a"),
                ("pyinstaller-python_module-001-runtime", b"runtime-b"),
                ("python-marshal-sequence-base64-decoded-000", candidate),
            ]
        return {"status": "terminal"}, []

    layers, _report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=2,
            max_layer_size=128,
            max_total_size=256,
            max_compression_ratio=100.0,
            max_archive_members=8,
        ),
    )

    assert [layer.data for layer in layers] == [b"root", candidate]
    assert calls == [b"root", candidate]
    assert layers[1].transform == "python-marshal-sequence-base64-decoded-000"
