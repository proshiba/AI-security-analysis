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


def test_inno_password_is_forwarded_only_when_explicit() -> None:
    """外装passwordは維持し、Inno専用値は明示時だけ別keywordで渡す。"""

    calls: list[dict[str, object]] = []

    def unpacker(_data: bytes, _name: str, **kwargs):
        calls.append(kwargs)
        return {"status": "terminal"}, []

    recover_static_layers(
        _unit(),
        unpacker=unpacker,
        archive_password="outer-password",
    )
    recover_static_layers(
        _unit(),
        unpacker=unpacker,
        archive_password="outer-password",
        inno_password="inner-password",
    )

    assert calls[0]["archive_password"] == "outer-password"
    assert "inno_password" not in calls[0]
    assert calls[1]["archive_password"] == "outer-password"
    assert calls[1]["inno_password"] == "inner-password"


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


def test_unpacker_failure_never_exposes_exception_text_to_sanitizer() -> None:
    """unpacker例外本文はsanitizerへ渡さず固定codeと型だけを公開する。"""

    def unpacker(_data: bytes, _name: str, **_kwargs):
        raise ValueError("unique-sensitive-unpacker-error")

    def sanitizer(_value: object) -> object:
        raise RuntimeError("unique-sensitive-sanitizer-error")

    _, report = recover_static_layers(_unit(), unpacker=unpacker, sanitizer=sanitizer)
    step = report["steps"][0]
    assert step["error"] == "unpacker_failed"
    assert step["error_type"] == "ValueError"
    serialized = repr(report)
    assert "unique-sensitive-unpacker-error" not in serialized
    assert "unique-sensitive-sanitizer-error" not in serialized


def test_bare_secret_unpacker_exception_is_fixed_and_type_is_validated() -> None:
    """既定sanitizerでも秘密値本文と不正な例外型名を公開しない。"""

    unsafe_error = type("secret-bearing-error", (Exception,), {})

    def unpacker(_data: bytes, _name: str, **_kwargs):
        raise unsafe_error("bare-secret-that-must-not-be-published")

    _, report = recover_static_layers(_unit(), unpacker=unpacker)
    step = report["steps"][0]
    assert step["status"] == "failed"
    assert step["error"] == "unpacker_failed"
    assert step["error_type"] == "Exception"
    assert "bare-secret-that-must-not-be-published" not in repr(report)
    assert "secret-bearing-error" not in repr(report)


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


def test_cab_last_reaches_nested_pe_before_many_terminal_pe_siblings() -> None:
    """>maxのPEが先に並んでも末尾CAB内PEへ層上限前に到達する。"""

    sibling_pes = [
        (f"pe-sibling-{index}", b"MZterminal-sibling-" + bytes([index]))
        for index in range(1, 8)
    ]
    cab = b"MSCFcab-fixture"
    nested_pe = b"MZnested-cab-payload"
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == b"root":
            recovered = [
                {
                    "kind": kind,
                    "size": len(blob),
                    "sha256": hashlib.sha256(blob).hexdigest(),
                }
                for kind, blob in [*sibling_pes, ("late-cab", cab)]
            ]
            return {"status": "fixture", "recovered": recovered}, [
                *sibling_pes,
                ("late-cab", cab),
            ]
        if data == cab:
            return {"status": "fixture"}, [("cab-member-pe", nested_pe)]
        return {"status": "terminal"}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=3,
            max_depth=4,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    assert [item.data for item in layers] == [b"root", cab, nested_pe]
    assert [item.transform for item in layers] == [
        "submission",
        "late-cab",
        "cab-member-pe",
    ]
    assert calls == [b"root", cab, nested_pe]
    assert report["limit_events"] == [
        {
            "parent_sha256": hashlib.sha256(b"root").hexdigest(),
            "kind": kind,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "size": len(blob),
            "reason": "layer_count_limit",
        }
        for kind, blob in sibling_pes
    ]
    assert len(report["steps"][0]["report"]["recovered"]) == len(sibling_pes) + 1
    assert report["steps"][0]["accepted_children"] == [layers[1].public()]


def test_pending_duplicate_uses_later_better_priority_provenance() -> None:
    """保留digestを高priorityで再発見した場合はtransformと親を更新する。"""

    shared_blob = b"shared opaque payload fixture"
    cab = b"MSCFduplicate-provenance-cab"
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == b"root":
            return {}, [
                ("opaque-resource", shared_blob),
                ("late-cab", cab),
            ]
        if data == cab:
            return {}, [("decoded-payload", shared_blob)]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=4,
            max_depth=4,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    assert [item.data for item in layers] == [b"root", cab, shared_blob]
    assert layers[2].parent_sha256 == hashlib.sha256(cab).hexdigest()
    assert layers[2].transform == "decoded-payload"
    assert layers[2].depth == 2
    assert calls == [b"root", cab, shared_blob]
    assert report["counts"]["deduplicated_artifacts"] == 1
    assert report["steps"][0]["accepted_children"] == [layers[1].public()]
    assert report["steps"][1]["accepted_children"] == [layers[2].public()]


def test_script_and_config_precede_media_without_reordering_equal_tiers() -> None:
    """script/configをmediaより優先し、同tier内は発見順を維持する。"""

    png = b"\x89PNG\r\n\x1a\nresource"
    first_config = b'{"host":"one.example"}'
    second_config = b'{"host":"two.example"}'
    script = b"Write-Output 'fixture'"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [
                ("dotnet-resource-png", png),
                ("decoded-config-one", first_config),
                ("decoded-config-two", second_config),
                ("zip-script-run.ps1", script),
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=4,
            max_depth=2,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    assert [item.data for item in layers] == [
        b"root",
        script,
        first_config,
        second_config,
    ]
    assert report["limit_events"] == [
        {
            "parent_sha256": hashlib.sha256(b"root").hexdigest(),
            "kind": "dotnet-resource-png",
            "sha256": hashlib.sha256(png).hexdigest(),
            "size": len(png),
            "reason": "layer_count_limit",
        }
    ]


def test_same_tier_siblings_preserve_discovery_order_when_all_fit() -> None:
    """同一tierが上限内なら従来どおり発見順を完全に維持する。"""

    siblings = [
        (f"cab-pe-{index:03d}", b"MZ" + index.to_bytes(2, "little") + b"-fixture")
        for index in range(12)
    ]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, siblings
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=len(siblings) + 1,
            max_depth=2,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    assert [item.data for item in layers[1:]] == [blob for _kind, blob in siblings]
    assert report["limit_events"] == []
    assert report["selection_policy"]["stratified_sibling_groups"] == 0
    assert report["selection_policy"]["stratified_sibling_candidates"] == 0


def test_oversubscribed_same_tier_siblings_cover_head_middle_and_tail() -> None:
    """大量の同tier siblingを層化し、先頭偏重せず末尾payloadも保持する。"""

    sibling_count = 232
    siblings = [
        (f"cab-pe-{index:03d}", b"MZ" + index.to_bytes(2, "little") + b"-fixture")
        for index in range(sibling_count)
    ]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, siblings
        return {}, []

    policy = StaticLayerPolicy(
        max_layers=64,
        max_depth=2,
        max_layer_size=1024,
        max_total_size=1024 * 1024,
    )
    layers, report = recover_static_layers(_unit(), unpacker=unpacker, policy=policy)
    repeated_layers, repeated_report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=policy,
    )

    selected_indexes = [int.from_bytes(item.data[2:4], "little") for item in layers[1:]]
    assert len(selected_indexes) == policy.max_layers - 1
    assert selected_indexes[:3] == [0, sibling_count - 1, (sibling_count - 1) // 2]
    assert {0, (sibling_count - 1) // 2, sibling_count - 1} <= set(selected_indexes)
    assert [item.sha256 for item in repeated_layers] == [item.sha256 for item in layers]

    omitted_indexes = [
        int(event["kind"].rsplit("-", 1)[1]) for event in report["limit_events"]
    ]
    assert omitted_indexes == sorted(set(range(sibling_count)) - set(selected_indexes))
    assert len(omitted_indexes) == sibling_count - (policy.max_layers - 1)
    assert {event["reason"] for event in report["limit_events"]} == {
        "layer_count_limit"
    }
    selection_policy = report["selection_policy"]
    assert selection_policy == repeated_report["selection_policy"]
    assert selection_policy == {
        "name": "format_depth_pending_capacity_stratified_siblings_v3",
        "primary_order": "validated_lineage_then_format_priority_then_deeper_layer",
        "capacity_evaluation": "all_pending_layers_after_each_expansion",
        "under_capacity_same_tier_order": "discovery_order",
        "oversubscribed_same_parent_tier_order": (
            "endpoints_then_largest_interval_midpoint"
        ),
        "stratified_sibling_groups": 1,
        "stratified_sibling_candidates": sibling_count,
    }
    assert "cab-pe" not in repr(selection_policy)


def test_deeper_container_children_rebalance_an_existing_fitting_group() -> None:
    """後発の深い同tier子が枠を消費しても既存groupを先頭偏重にしない。"""

    container = b"MSCF-capacity-competition"
    root_siblings = [
        (f"root-pe-{index}", b"MZ" + index.to_bytes(2, "little") + b"-root")
        for index in range(6)
    ]
    deeper_siblings = [
        (f"deep-pe-{index}", b"MZ" + index.to_bytes(2, "little") + b"-deep")
        for index in range(2)
    ]
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == b"root":
            return {}, [*root_siblings, ("late-container", container)]
        if data == container:
            return {}, deeper_siblings
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=8,
            max_depth=3,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    selected_root_indexes = [
        int.from_bytes(item.data[2:4], "little")
        for item in layers
        if item.transform.startswith("root-pe-")
    ]
    assert selected_root_indexes == [0, 5, 2, 3]
    assert {0, 2, 5} <= set(selected_root_indexes)
    assert calls == [
        b"root",
        container,
        deeper_siblings[0][1],
        deeper_siblings[1][1],
        root_siblings[0][1],
        root_siblings[5][1],
        root_siblings[2][1],
        root_siblings[3][1],
    ]
    assert [
        event["kind"] for event in report["limit_events"]
    ] == ["root-pe-1", "root-pe-4"]
    assert {event["reason"] for event in report["limit_events"]} == {
        "layer_count_limit"
    }
    assert report["selection_policy"]["stratified_sibling_groups"] == 1
    assert report["selection_policy"]["stratified_sibling_candidates"] == 6
    root_step = next(
        step for step in report["steps"] if step["input_layer"]["depth"] == 0
    )
    container_step = next(
        step
        for step in report["steps"]
        if step["input_layer"]["sha256"] == hashlib.sha256(container).hexdigest()
    )
    assert [child["transform"] for child in root_step["accepted_children"]] == [
        "late-container",
        "root-pe-0",
        "root-pe-5",
        "root-pe-2",
        "root-pe-3",
    ]
    assert [child["transform"] for child in container_step["accepted_children"]] == [
        "deep-pe-0",
        "deep-pe-1",
    ]
    assert all(
        child["parent_sha256"] == hashlib.sha256(container).hexdigest()
        for child in container_step["accepted_children"]
    )


def test_repeated_rebalance_uses_immutable_sibling_discovery_order() -> None:
    """複数の後発深層で再層化しても既適用の順列を再適用しない。"""

    containers = [b"MSCF-first-container", b"MSCF-second-container"]
    deep_payloads = [b"MZ-first-deep-payload", b"MZ-second-deep-payload"]
    siblings = [
        (f"root-pe-{index}", b"MZ" + index.to_bytes(2, "little") + b"-root")
        for index in range(6)
    ]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [
                ("first-container", containers[0]),
                ("second-container", containers[1]),
                *siblings,
            ]
        if data == containers[0]:
            return {}, [("first-deep.exe", deep_payloads[0])]
        if data == containers[1]:
            return {}, [("second-deep.exe", deep_payloads[1])]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=8,
            max_depth=3,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    selected_root_indexes = [
        int.from_bytes(item.data[2:4], "little")
        for item in layers
        if item.transform.startswith("root-pe-")
    ]
    assert selected_root_indexes == [0, 5, 2]
    assert {item.data for item in layers} >= set(containers) | set(deep_payloads)
    assert [event["kind"] for event in report["limit_events"]] == [
        "root-pe-1",
        "root-pe-3",
        "root-pe-4",
    ]


def test_stratification_keeps_dedup_provenance_and_total_size_accounting() -> None:
    """層化前に発見順でdedupと容量予約を確定し、既存契約を維持する。"""

    first = b"MZ-first-unique"
    duplicate = bytes(first)
    second = b"MZ-second-unique"
    over_total = b"MZ-over-total"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [
                ("cab-pe-first", first),
                ("cab-pe-duplicate", duplicate),
                ("cab-pe-second", second),
                ("cab-pe-over-total", over_total),
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=2,
            max_layer_size=1024,
            max_total_size=len(first) + len(second) + 5,
        ),
    )

    assert [item.data for item in layers] == [b"root", first]
    assert layers[1].transform == "cab-pe-first"
    assert report["counts"]["deduplicated_artifacts"] == 1
    assert report["counts"]["recovered_bytes"] == len(first)
    assert [event["reason"] for event in report["limit_events"]] == [
        "recovered_total_limit",
        "layer_count_limit",
    ]
    assert report["limit_events"][0]["sha256"] == hashlib.sha256(over_total).hexdigest()
    assert report["limit_events"][1]["sha256"] == hashlib.sha256(second).hexdigest()


def test_layer_capacity_pruning_releases_reservation_for_deep_payload() -> None:
    """採用不能siblingの予約を戻し、後発する深い高優先度payloadを回収する。"""

    container = b"MSCF-deep-reservation-container"
    deep_payload = b"MZ-deep-high-priority-payload" + (b"D" * 32)
    siblings = [
        (f"opaque-sibling-{index}", bytes([index]) * 48)
        for index in range(1, 7)
    ]
    max_total_size = len(container) + sum(len(blob) for _kind, blob in siblings)
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == b"root":
            return {}, [("deep-container", container), *siblings]
        if data == container:
            return {}, [("deep-payload.exe", deep_payload)]
        return {}, []

    policy = StaticLayerPolicy(
        max_layers=4,
        max_depth=3,
        max_layer_size=1024,
        max_total_size=max_total_size,
    )
    layers, report = recover_static_layers(_unit(), unpacker=unpacker, policy=policy)
    repeated_layers, repeated_report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=policy,
    )

    assert deep_payload in [item.data for item in layers]
    deep_layer = next(item for item in layers if item.data == deep_payload)
    assert deep_layer.parent_sha256 == hashlib.sha256(container).hexdigest()
    assert deep_layer.depth == 2
    assert report["counts"]["recovered_bytes"] <= max_total_size
    assert [item.sha256 for item in repeated_layers] == [
        item.sha256 for item in layers
    ]
    assert repeated_report["limit_events"] == report["limit_events"]
    assert {event["reason"] for event in report["limit_events"]} == {
        "layer_count_limit"
    }
    omitted_kinds = [event["kind"] for event in report["limit_events"]]
    assert omitted_kinds == [
        kind
        for kind, _blob in siblings
        if kind not in {item.transform for item in layers}
    ]
    assert calls[:3] == [b"root", container, deep_payload]


def test_total_capacity_rebalances_low_priority_pending_for_lineage_child() -> None:
    """低優先度の大きいpendingを退避し、後発の検証済みlineage子を採用する。"""

    container = b"MSCF-byte-capacity-container"
    low_priority_pending = b"L" * 80
    lineage_child = b"validated-lineage-child" + (b"H" * 32)
    max_total_size = len(container) + len(low_priority_pending)
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == b"root":
            return {}, [
                ("deep-container", container),
                ("opaque-low-priority", low_priority_pending),
            ]
        if data == container:
            return _complete_bcrypt_report(lineage_child), [
                ("bcrypt-resource-shellcode", lineage_child)
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=4,
            max_depth=3,
            max_layer_size=1024,
            max_total_size=max_total_size,
        ),
    )

    assert [item.data for item in layers] == [b"root", container, lineage_child]
    assert low_priority_pending not in [item.data for item in layers]
    assert report["counts"]["recovered_bytes"] == len(container) + len(lineage_child)
    assert report["counts"]["recovered_bytes"] <= max_total_size
    assert report["limit_events"] == [
        {
            "parent_sha256": hashlib.sha256(b"root").hexdigest(),
            "kind": "opaque-low-priority",
            "sha256": hashlib.sha256(low_priority_pending).hexdigest(),
            "size": len(low_priority_pending),
            "reason": "recovered_total_limit",
        }
    ]
    assert calls == [b"root", container, lineage_child]


def test_total_capacity_same_rank_selection_is_deterministic() -> None:
    """同priority・同depthのbyte競合は発見順で決定的に選択する。"""

    first = b"A" * 32
    second = b"B" * 32

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [
                ("opaque-first", first),
                ("opaque-second", second),
            ]
        return {}, []

    policy = StaticLayerPolicy(
        max_layers=4,
        max_depth=2,
        max_layer_size=64,
        max_total_size=40,
    )
    layers, report = recover_static_layers(_unit(), unpacker=unpacker, policy=policy)
    repeated_layers, repeated_report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=policy,
    )

    assert [item.data for item in layers] == [b"root", first]
    assert [item.sha256 for item in repeated_layers] == [item.sha256 for item in layers]
    assert repeated_report["limit_events"] == report["limit_events"]
    assert report["limit_events"][0]["sha256"] == hashlib.sha256(second).hexdigest()
    assert report["limit_events"][0]["reason"] == "recovered_total_limit"


def test_child_larger_than_total_capacity_is_rejected_once() -> None:
    """総byte上限を単体で超える同一childを複数親から無限に再試行しない。"""

    containers = [b"MSCF-first", b"MSCF-second"]
    oversized = b"X" * 41
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == b"root":
            return {}, [
                ("first-container", containers[0]),
                ("second-container", containers[1]),
            ]
        if data in containers:
            return {}, [("opaque-oversized", oversized)]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=4,
            max_depth=3,
            max_layer_size=64,
            max_total_size=40,
        ),
    )

    assert [item.data for item in layers] == [b"root", *containers]
    assert oversized not in [item.data for item in layers]
    assert calls == [b"root", *containers]
    assert report["counts"]["recovered_bytes"] == sum(map(len, containers))
    assert report["counts"]["recovered_bytes"] <= 40
    assert report["counts"]["deduplicated_artifacts"] == 1
    assert [event["reason"] for event in report["limit_events"]] == [
        "recovered_total_limit"
    ]
    assert report["limit_events"][0]["sha256"] == hashlib.sha256(oversized).hexdigest()


def test_pruned_digest_can_return_with_better_priority_provenance() -> None:
    """予約解放済みdigestも後発する高priority provenanceで再評価する。"""

    container = b"MSCF-pruned-dedup-container"
    first_pending = b"first low priority pending"
    reprioritized = b"reprioritized shared payload"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [
                ("deep-container", container),
                ("opaque-first", first_pending),
                ("opaque-shared", reprioritized),
            ]
        if data == container:
            return {}, [("decoded-payload", reprioritized)]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=3,
            max_depth=3,
            max_layer_size=1024,
            max_total_size=4096,
        ),
    )

    assert [item.data for item in layers] == [b"root", container, reprioritized]
    assert layers[2].parent_sha256 == hashlib.sha256(container).hexdigest()
    assert layers[2].transform == "decoded-payload"
    assert layers[2].depth == 2
    assert report["counts"]["deduplicated_artifacts"] == 1
    assert report["limit_events"] == [
        {
            "parent_sha256": hashlib.sha256(b"root").hexdigest(),
            "kind": "opaque-first",
            "sha256": hashlib.sha256(first_pending).hexdigest(),
            "size": len(first_pending),
            "reason": "layer_count_limit",
        }
    ]


def _complete_inno_report(
    script: bytes,
    payload: bytes,
    *,
    payload_sha256: str | None = None,
) -> dict[str, object]:
    """trustedな単一launch target Inno report fixtureを返す。"""

    return {
        "inno": {
            "candidate": True,
            "status": "artifacts_recovered",
            "inventory_complete": True,
            "extraction_complete": True,
            "tool": {"identity_unchanged": True},
            "inventory": {
                "inventory_complete": True,
                "member_count": 2,
                "invalid_member_count": 0,
                "duplicate_member_count": 0,
            },
            "selection": {
                "selected_member_count": 2,
                "complete_archive_extraction": True,
                "omitted_member_count": 0,
                "limit_reasons": [],
                "launch_target_match_count": 1,
            },
            "install_script": {
                "status": "recovered_and_parsed",
                "size": len(script),
                "sha256": hashlib.sha256(script).hexdigest(),
                "payload_encrypted": False,
                "decompiler_provenance_verified": True,
                "launch_target_count": 1,
                "launch_targets": ["{app}/host.exe"],
                "dynamic_launch_target_count": 0,
                "invalid_launch_target_count": 0,
            },
            "recovered_members": [
                {
                    "name": "{app}/host.exe",
                    "size": len(payload),
                    "sha256": payload_sha256
                    or hashlib.sha256(payload).hexdigest(),
                    "format": "unknown",
                    "launch_target": True,
                }
            ],
        }
    }


def _complete_bcrypt_report(payload: bytes) -> dict[str, object]:
    """完全列挙された単一BCrypt recovery report fixtureを返す。"""

    return {
        "bcrypt_resource": {
            "candidate": True,
            "status": "artifacts_recovered",
            "candidate_set_complete": True,
            "recovery_attempts_complete": True,
            "recovered_artifact_set_complete": True,
            "recovered_artifact_count": 1,
            "recovered_artifact_total_size": len(payload),
        }
    }


def _limited_policy() -> StaticLayerPolicy:
    return StaticLayerPolicy(
        max_layers=2,
        max_depth=2,
        max_layer_size=4096,
        max_total_size=1024 * 1024,
    )


def test_complete_inno_launch_target_precedes_container_at_small_layer_limit() -> None:
    """実byteへ一意に結合したInno launch targetだけを最優先にする。"""

    script = b"trusted install script"
    payload = b"opaque launched payload"
    container = b"MSCF competing container"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return _complete_inno_report(script, payload), [
                ("competing-container", container),
                ("inno-install-script.iss", script),
                ("inno-member-001-unknown.exe", payload),
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", payload]
    root_step = report["steps"][0]
    selection = root_step["lineage_child_selection"]
    assert selection["status"] == "complete_selected"
    assert selection["counts"]["selected_child_count"] == 1
    assert selection["selected_relation_counts"] == {"script_launch": 1}
    assert [child["transform"] for child in root_step["accepted_children"]] == [
        "inno-member-001-unknown.exe"
    ]
    assert {event["kind"] for event in report["limit_events"]} == {
        "competing-container",
        "inno-install-script.iss",
    }


@pytest.mark.parametrize(
    ("section", "field", "boolean_value"),
    [
        ("inventory", "member_count", True),
        ("inventory", "invalid_member_count", False),
        ("inventory", "duplicate_member_count", False),
        ("selection", "selected_member_count", True),
        ("selection", "omitted_member_count", False),
        ("selection", "launch_target_match_count", True),
        ("install_script", "launch_target_count", True),
        ("install_script", "dynamic_launch_target_count", False),
        ("install_script", "invalid_launch_target_count", False),
    ],
)
def test_inno_boolean_count_is_never_treated_as_integer(
    section: str,
    field: str,
    boolean_value: bool,
) -> None:
    """boolが数値と等価でもInno countとして受理しない。"""

    script = b"trusted install script"
    payload = b"opaque launched payload"
    container = b"MSCF competing container"
    report = _complete_inno_report(script, payload)
    inno = report["inno"]
    assert isinstance(inno, dict)
    section_report = inno[section]
    assert isinstance(section_report, dict)
    section_report[field] = boolean_value

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return report, [
                ("competing-container", container),
                ("inno-install-script.iss", script),
                ("inno-member-001-unknown.exe", payload),
            ]
        return {}, []

    layers, public = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", container]
    assert public["steps"][0]["lineage_child_selection"]["status"] == "partial"


def test_extra_distinct_inno_install_script_makes_lineage_partial() -> None:
    """異なる余剰install scriptがあれば実artifact集合を不完全とする。"""

    script = b"trusted install script"
    extra_script = b"unexpected second install script"
    payload = b"opaque launched payload"
    container = b"MSCF competing container"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return _complete_inno_report(script, payload), [
                ("competing-container", container),
                ("inno-install-script.iss", script),
                ("inno-install-script.iss", extra_script),
                ("inno-member-001-unknown.exe", payload),
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", container]
    assert report["steps"][0]["lineage_child_selection"]["status"] == "partial"


@pytest.mark.parametrize(
    "failure",
    [
        "reported_digest_mismatch",
        "reported_size_mismatch",
        "global_digest_size_duplicate",
    ],
)
def test_inno_install_script_identity_failure_keeps_existing_order(
    failure: str,
) -> None:
    """install script実体を一意に照合できなければ従来順へ戻す。"""

    script = b"trusted install script"
    payload = b"opaque launched payload"
    container = b"MSCF competing container"
    report = _complete_inno_report(script, payload)
    inno = report["inno"]
    assert isinstance(inno, dict)
    install_script = inno["install_script"]
    assert isinstance(install_script, dict)
    artifacts = [
        ("competing-container", container),
        ("inno-install-script.iss", script),
        ("inno-member-001-unknown.exe", payload),
    ]
    if failure == "reported_digest_mismatch":
        install_script["sha256"] = "f" * 64
    elif failure == "reported_size_mismatch":
        install_script["size"] = len(script) + 1
    else:
        artifacts.append(("unrelated-script-copy", script))

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return report, artifacts
        return {}, []

    layers, public = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", container]
    root_step = public["steps"][0]
    assert root_step["lineage_child_selection"]["status"] == "partial"
    assert [child["transform"] for child in root_step["accepted_children"]] == [
        "competing-container"
    ]


def test_complete_bcrypt_target_precedes_container_at_small_layer_limit() -> None:
    """全completeness flagがtrueのBCrypt復元物だけを最優先にする。"""

    payload = b"opaque decoded resource"
    container = b"MSCF competing container"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return _complete_bcrypt_report(payload), [
                ("competing-container", container),
                ("bcrypt-resource-shellcode", payload),
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", payload]
    selection = report["steps"][0]["lineage_child_selection"]
    assert selection["status"] == "complete_selected"
    assert selection["selected_relation_counts"] == {"resource_decode": 1}


def test_deep_bcrypt_target_uses_rehashed_containment_chain() -> None:
    """depth>0でも実byte ancestor chainを検証してdecoded targetを選択する。"""

    first_container = b"MSCF first container"
    competing_container = b"MSCF nested competing container"
    payload = b"opaque nested decoded resource"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return {}, [("first-container", first_container)]
        if data == first_container:
            return _complete_bcrypt_report(payload), [
                ("competing-container", competing_container),
                ("bcrypt-resource-shellcode", payload),
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=3,
            max_depth=3,
            max_layer_size=4096,
            max_total_size=1024 * 1024,
        ),
    )

    assert [item.data for item in layers] == [b"root", first_container, payload]
    nested_step = next(
        step
        for step in report["steps"]
        if step["input_layer"]["sha256"]
        == hashlib.sha256(first_container).hexdigest()
    )
    assert nested_step["lineage_child_selection"]["status"] == "complete_selected"
    assert [child["transform"] for child in nested_step["accepted_children"]] == [
        "bcrypt-resource-shellcode"
    ]


@pytest.mark.parametrize("failure", ["digest_mismatch", "duplicate", "incomplete"])
def test_incomplete_or_ambiguous_lineage_never_changes_existing_order(
    failure: str,
) -> None:
    """不一致・重複・不完全reportでは従来format優先順へfail closedする。"""

    script = b"trusted install script"
    payload = b"opaque launched payload"
    container = b"MSCF competing container"
    report = _complete_inno_report(
        script,
        payload,
        payload_sha256="f" * 64 if failure == "digest_mismatch" else None,
    )
    if failure == "incomplete":
        report["inno"]["extraction_complete"] = False  # type: ignore[index]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data != b"root":
            return {}, []
        artifacts = [
            ("competing-container", container),
            ("inno-install-script.iss", script),
            ("inno-member-001-unknown.exe", payload),
        ]
        if failure == "duplicate":
            artifacts.append(("inno-member-002-unknown.exe", payload))
        return report, artifacts

    layers, public = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", container]
    selection = public["steps"][0]["lineage_child_selection"]
    assert selection["status"] == "partial"
    assert public["steps"][0]["report"]["inno"]["extraction_complete"] is (
        failure != "incomplete"
    )


def test_incomplete_bcrypt_report_never_prioritizes_decoded_artifact() -> None:
    """BCrypt completenessが一つでもfalseならdecoded artifactを昇格しない。"""

    payload = b"opaque decoded resource"
    container = b"MSCF competing container"
    report = _complete_bcrypt_report(payload)
    report["bcrypt_resource"]["recovery_attempts_complete"] = False  # type: ignore[index]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return report, [
                ("competing-container", container),
                ("bcrypt-resource-shellcode", payload),
            ]
        return {}, []

    layers, public = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", container]
    assert public["steps"][0]["lineage_child_selection"]["status"] == "partial"


def test_lineage_public_projection_has_no_private_identity_fields() -> None:
    """stepへ公開するselector projectionにdigest/path/name/addressを含めない。"""

    script = b"private script bytes"
    payload = b"private payload bytes"

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return _complete_inno_report(script, payload), [
                ("inno-install-script.iss", script),
                ("inno-member-001-private.exe", payload),
            ]
        return {}, []

    _layers, report = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )
    selection = report["steps"][0]["lineage_child_selection"]

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    private_keys = {
        "sha256",
        "path",
        "name",
        "address",
        "selected_sha256",
        "selected_artifacts",
        "validated_edges",
    }
    assert keys(selection).isdisjoint(private_keys)
    assert selection["family_attribution_allowed"] is False
    assert selection["c2_attribution_allowed"] is False


def test_incomplete_overflow_commitment_is_never_used_for_priority() -> None:
    """coreが一部edgeを選べてもoverflow commitment不完全なら昇格しない。"""

    script = b"trusted install script"
    payload = b"opaque launched payload"
    container = b"MSCF competing container"
    filler = [(f"opaque-{index}", index.to_bytes(2, "little")) for index in range(509)]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == b"root":
            return _complete_inno_report(script, payload), [
                ("competing-container", container),
                ("inno-install-script.iss", script),
                ("inno-member-001-unknown.exe", payload),
                *filler,
            ]
        return {}, []

    layers, report = recover_static_layers(
        _unit(), unpacker=unpacker, policy=_limited_policy()
    )

    assert [item.data for item in layers] == [b"root", container]
    selection = report["steps"][0]["lineage_child_selection"]
    assert selection["status"] == "partial"
    assert selection["omitted_commitment"]["complete"] is False
