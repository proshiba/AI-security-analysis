"""再利用可能な静的レイヤーパイプラインの回帰テスト。"""

from __future__ import annotations

import hashlib

import pytest

from common.static_layer_pipeline import (
    InputUnit,
    StaticLayerPolicy,
    recover_static_layers,
)


def _unit(data: bytes = b"root") -> InputUnit:
    digest = hashlib.sha256(data).hexdigest()
    return InputUnit(
        source_name="sample.bin",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )


def test_custom_unpacker_and_policy_are_reusable() -> None:
    calls: list[dict[str, object]] = []

    def unpacker(data: bytes, name: str, **kwargs):
        calls.append({"data": data, "name": name, **kwargs})
        if data == b"root":
            return {"status": "fixture"}, [("decoded-child", b"child")]
        return {"status": "terminal"}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=3,
            max_depth=2,
            max_layer_size=32,
            max_total_size=64,
            max_compression_ratio=25.0,
            max_archive_members=7,
        ),
    )
    assert [item.data for item in layers] == [b"root", b"child"]
    assert layers[1].transform == "decoded-child"
    assert calls[0]["max_archive_members"] == 7
    assert calls[0]["max_archive_compression_ratio"] == 25.0
    assert report["limits"]["max_layers"] == 3
    assert report["executed_sample"] is False


def test_malformed_and_oversized_artifacts_are_rejected() -> None:
    def unpacker(_data: bytes, _name: str, **_kwargs):
        return {"status": "fixture"}, [
            ("oversized", b"x" * 5),
            ("not-bytes", "text"),
            "malformed",
        ]

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=4,
            max_depth=1,
            max_layer_size=4,
            max_total_size=8,
        ),
    )
    assert len(layers) == 1
    reasons = {item["reason"] for item in report["limit_events"]}
    assert reasons == {
        "layer_size_limit",
        "non_bytes_artifact_rejected",
        "malformed_artifact_rejected",
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_layers": 0},
        {"max_depth": 0},
        {"max_layer_size": 0},
        {"max_total_size": 0},
        {"max_compression_ratio": 0},
        {"max_archive_members": 0},
    ],
)
def test_policy_rejects_nonpositive_limits(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        StaticLayerPolicy(**kwargs)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_name": ""},
        {"source_name": "bad\nname"},
        {"data": bytearray(b"root")},
        {"input_kind": ""},
        {"outer_sha256": "A" * 64},
        {"outer_sha256": "0" * 63},
        {"outer_size": True},
        {"outer_size": -1},
        {"outer_size": 5},
    ],
)
def test_input_unit_rejects_invalid_raw_metadata(changes: dict[str, object]) -> None:
    """raw入力の型、名前、hash、size不整合を構築時に拒否する。"""
    values: dict[str, object] = {
        "source_name": "sample.bin",
        "data": b"root",
        "input_kind": "raw",
        "outer_sha256": hashlib.sha256(b"root").hexdigest(),
        "outer_size": 4,
    }
    values.update(changes)
    with pytest.raises((TypeError, ValueError)):
        InputUnit(**values)  # type: ignore[arg-type]


def test_authenticated_member_keeps_outer_archive_metadata() -> None:
    """認証済み内包メンバーではouter hashと内包dataの不一致を許可する。"""
    unit = InputUnit(
        source_name="payload.bin",
        data=b"inner",
        input_kind="authenticated_single_member_zip",
        outer_sha256=hashlib.sha256(b"outer archive").hexdigest(),
        outer_size=len(b"outer archive"),
        member_name="folder/payload.bin",
    )
    assert unit.data == b"inner"


def test_sanitizer_failure_never_leaks_unsanitized_error() -> None:
    """サニタイザー自身が失敗しても未加工の例外文字列を成果物へ残さない。"""

    def unpacker(_data: bytes, _name: str, **_kwargs):
        raise ValueError("unique-sensitive-unpacker-error")

    def sanitizer(_value: object) -> object:
        raise RuntimeError("unique-sensitive-sanitizer-error")

    _, report = recover_static_layers(_unit(), unpacker=unpacker, sanitizer=sanitizer)
    error = report["steps"][0]["error"]
    assert error == {"sanitization_failed": True, "error_type": "RuntimeError"}
    serialized = repr(report)
    assert "unique-sensitive-unpacker-error" not in serialized
    assert "unique-sensitive-sanitizer-error" not in serialized


def test_sanitizer_failure_on_report_keeps_step_structurally_valid() -> None:
    """正常unpackerのreport秘匿に失敗してもstepを成功として閉じる。"""

    def unpacker(_data: bytes, _name: str, **_kwargs):
        return {"secret": "unique-report-secret"}, []

    def sanitizer(_value: object) -> object:
        raise LookupError("sanitizer failed")

    _, report = recover_static_layers(_unit(), unpacker=unpacker, sanitizer=sanitizer)
    step = report["steps"][0]
    assert step["status"] == "succeeded"
    assert step["report"] == {"sanitization_failed": True, "error_type": "LookupError"}
    assert "unique-report-secret" not in repr(report)


def test_empty_duplicate_and_untrusted_artifact_labels_are_bounded() -> None:
    """空artifactを拒否し、重複を計数し、種別を安全な短い名前へ正規化する。"""
    raw_label = "bad\r\n../../" + ("x" * 200)

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [
                ("empty", b""),
                (raw_label, b"child"),
                ("duplicate", b"child"),
            ]
        return {}, []

    layers, report = recover_static_layers(_unit(), unpacker=unpacker)
    assert len(layers) == 2
    assert len(layers[1].transform) == 80
    assert layers[1].transform.startswith("bad_")
    assert set(layers[1].transform) <= set("abcdefghijklmnopqrstuvwxyz._-")
    assert "\r" not in layers[1].name and "\n" not in layers[1].name
    assert report["counts"]["deduplicated_artifacts"] == 1
    assert {item["reason"] for item in report["limit_events"]} == {"empty_artifact_rejected"}


@pytest.mark.parametrize(
    "result",
    [
        ([], []),
        ({}, {}),
        "invalid",
        None,
    ],
)
def test_unpacker_contract_violations_become_failed_steps(result: object) -> None:
    """壊れたunpacker戻り値をパイプライン外へ例外として漏らさない。"""

    def unpacker(_data: bytes, _name: str, **_kwargs):
        return result

    layers, report = recover_static_layers(_unit(), unpacker=unpacker)  # type: ignore[arg-type]
    assert len(layers) == 1
    assert report["steps"][0]["status"] == "failed"
