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
        ),
    )
    assert [item.data for item in layers] == [b"root", b"child"]
    assert layers[1].transform == "decoded-child"
    assert calls[0]["max_archive_members"] == 2
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
    ],
)
def test_policy_rejects_nonpositive_limits(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        StaticLayerPolicy(**kwargs)
