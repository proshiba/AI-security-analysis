"""PureLogsコホート厳格評価器の回帰テスト。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "common" / "evaluate_purelogs_cohort.py"
SPEC = importlib.util.spec_from_file_location("evaluate_purelogs_cohort", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def _varint(value: int) -> bytes:
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _bytes_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _payload(endpoint: bytes) -> bytes:
    message = b"".join(
        (
            _bytes_field(1, b"https://" + endpoint),
            _bytes_field(2, bytes(range(32))),
            _bytes_field(3, b"fixture-build"),
            _bytes_field(4, b"fixture-mutex"),
        )
    )
    return b"PureLogs\x00/plugin\x00" + base64.b64encode(message)


def _layer(data: bytes, *, depth: int = 0) -> object:
    digest = hashlib.sha256(data).hexdigest()
    return MODULE.StaticLayer(
        name="fixture.bin",
        data=data,
        sha256=digest,
        parent_sha256=None if depth == 0 else "0" * 64,
        depth=depth,
        transform="submission" if depth == 0 else "fixture-transform",
    )


def test_strict_success_requires_detector_family_and_protobuf_config() -> None:
    result = MODULE.evaluate_layers([_layer(_payload(b"logs.example.test:8443"))])

    assert result["family_confirmed"] is True
    assert result["validated_config_recovered"] is True
    assert result["qualified_c2_recovered"] is True
    assert result["strict_success"] is True
    assert result["strict_evidence_layers"][0]["configured_endpoint_count"] == 1
    serialized = json.dumps(result)
    assert "logs.example.test" not in serialized
    assert result["strict_evidence_layers"][0]["raw_endpoint_published"] is False


def test_family_only_http_profile_is_not_strict_config_success() -> None:
    data = b"https://logs.example.test:8443/plugin\n/userinfo\n/filesearch/req\n/finish\n"

    result = MODULE.evaluate_layers([_layer(data)])

    assert result["family_confirmed"] is True
    assert result["validated_config_recovered"] is False
    assert result["qualified_c2_recovered"] is False
    assert result["strict_success"] is False
    assert "family_bound_protobuf_config_not_recovered" in result["blockers"]


def test_provider_label_or_loose_url_cannot_confirm_family() -> None:
    result = MODULE.evaluate_layers([_layer(b"PureLogsStealer https://candidate.example.test/path")])

    assert result["family_confirmed"] is False
    assert result["strict_success"] is False


def test_cross_layer_configuration_conflict_fails_closed() -> None:
    result = MODULE.evaluate_layers(
        [
            _layer(_payload(b"one.example.test:443")),
            _layer(_payload(b"two.example.test:443"), depth=1),
        ]
    )

    assert result["family_confirmed"] is True
    assert result["configuration_conflict"] is True
    assert result["validated_config_recovered"] is False
    assert result["strict_success"] is False
    assert "conflicting_configuration_candidates_across_layers" in result["blockers"]


def test_cross_layer_key_conflict_with_same_endpoint_fails_closed() -> None:
    """同じendpointでもAES鍵fingerprintが異なるlayerは競合として拒否する。"""

    def payload(key: bytes) -> bytes:
        message = b"".join(
            (
                _bytes_field(1, b"https://same.example.test:443"),
                _bytes_field(2, key),
                _bytes_field(3, b"fixture-build"),
                _bytes_field(4, b"fixture-mutex"),
            )
        )
        return b"PureLogs\x00/plugin\x00" + base64.b64encode(message)

    result = MODULE.evaluate_layers(
        [
            _layer(payload(b"A" * 32)),
            _layer(payload(b"B" * 32), depth=1),
        ]
    )

    assert result["configuration_conflict"] is True
    assert result["validated_config_recovered"] is False
    assert result["qualified_c2_recovered"] is False
    assert result["strict_success"] is False
    assert result["strict_evidence_layers"] == []
    assert "conflicting_configuration_candidates_across_layers" in result["blockers"]


def test_family_and_config_on_different_layers_do_not_form_strict_success() -> None:
    config_layer = _layer(_payload(b"logs.example.test:8443"))
    family_layer = _layer(
        b"https://profile.example.test:8443/plugin\n/userinfo\n/filesearch/req\n/finish\n",
        depth=1,
    )

    def detector(data: bytes, _path: Path | None) -> dict[str, object]:
        digest = hashlib.sha256(data).hexdigest()
        return {
            "matched": data == family_layer.data,
            "confidence": "high_static" if data == family_layer.data else "none",
            "sha256": digest,
        }

    result = MODULE.evaluate_layers(
        [config_layer, family_layer],
        detector=detector,
        extractor=MODULE.extract_purelogs,
    )

    assert result["family_confirmed"] is True
    assert result["validated_config_recovered"] is True
    assert result["qualified_c2_recovered"] is True
    assert result["strict_success"] is False
    assert result["strict_evidence_layers"] == []
    assert "config_and_family_evidence_not_on_same_layer" in result["blockers"]


def test_identical_layer_sha_reuses_detector_and_extractor_result() -> None:
    """共有layerはrootごとに高コストな静的解析を繰り返さない。"""

    layer = _layer(_payload(b"logs.example.test:8443"))
    calls = {"detector": 0, "extractor": 0}

    def detector(data: bytes, path: Path | None) -> dict[str, object]:
        calls["detector"] += 1
        return MODULE.PURELOGS_DETECT(data, path)

    def extractor(data: bytes, name: str) -> dict:
        calls["extractor"] += 1
        return MODULE.extract_purelogs(data, name)

    cache: dict = {}
    first = MODULE.evaluate_layers(
        [layer],
        detector=detector,
        extractor=extractor,
        layer_cache=cache,
    )
    second = MODULE.evaluate_layers(
        [layer],
        detector=detector,
        extractor=extractor,
        layer_cache=cache,
    )

    assert first["strict_success"] is True
    assert second["strict_success"] is True
    assert calls == {"detector": 1, "extractor": 1}
    assert list(cache) == [layer.sha256]


def test_baseline_zero_dimension_proves_strict_zero() -> None:
    cohort = {
        "family": {"confirmed_case_count": 0},
        "config_c2_terminal": {
            "validated_config_recovered_case_count": 0,
            "qualified_network_endpoint_recovered_case_count": 0,
        },
    }

    result = MODULE.baseline_metrics(cohort)

    assert result["strict_joint_success_case_count"] == 0
    assert result["strict_joint_derivation"] == ("zero_dimension_proves_empty_intersection")


def test_static_reason_counts_exposes_only_fixed_format_reasons() -> None:
    pipeline = {
        "steps": [
            {
                "report": {
                    "reason": "resource_binding_ambiguous",
                    "nested": [{"error": "unpacker_failed"}],
                    "endpoint": "sensitive.example.test:443",
                    "unsafe_reason": "do not publish this value",
                }
            },
            {"reason": "resource_binding_ambiguous"},
        ]
    }

    result = MODULE.static_reason_counts(pipeline)

    assert result == {
        "resource_binding_ambiguous": 2,
        "unpacker_failed": 1,
    }
    assert "sensitive.example.test" not in json.dumps(result)


def test_load_cohort_rejects_provider_label_as_family_confirmation(tmp_path: Path) -> None:
    digest = "a" * 64
    manifest = {
        "cohorts": {
            "PureLogsStealer": {
                "root_case_count": 1,
                "root_sha256": [digest],
                "provider_label_role": "family_confirmation",
            }
        }
    }
    path = tmp_path / "cohort.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    try:
        MODULE.load_cohort(path, "PureLogsStealer")
    except MODULE.CohortEvaluationError as exc:
        assert "provider label" in str(exc)
    else:  # pragma: no cover - 回帰時の明示的失敗経路。
        raise AssertionError("provider labelのfamily流用を拒否しませんでした")


def test_evaluate_case_reports_managed_omlx_terminal_recovery(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    data = b"fixture-root"
    digest = hashlib.sha256(data).hexdigest()
    sample_path = tmp_path / "fixture.bin"
    sample_path.write_bytes(data)
    root = _layer(data)
    terminal_data = _payload(b"logs.example.test:8443")
    terminal = MODULE.StaticLayer(
        name="terminal.bin",
        data=terminal_data,
        sha256=hashlib.sha256(terminal_data).hexdigest(),
        parent_sha256=root.sha256,
        depth=1,
        transform=MODULE.MANAGED_OMLX_TERMINAL_TRANSFORM,
    )

    def recover(*_args: object, **_kwargs: object) -> tuple[list[object], dict]:
        return [root, terminal], {
            "counts": {"limit_events": 0},
            "steps": [],
        }

    monkeypatch.setattr(MODULE, "recover_static_layers", recover)

    result = MODULE.evaluate_case(
        sample_path,
        digest,
        policy=MODULE.StaticLayerPolicy(max_layers=2, max_depth=1),
    )

    assert result["managed_omlx_terminal_recovered"] is True
    assert result["managed_omlx_terminal_layer_sha256"] == [terminal.sha256]
    assert result["static_layer_sha256"] == sorted([root.sha256, terminal.sha256])


def test_end_to_end_cohort_evaluation_binds_current_implementation(
    tmp_path: Path,
) -> None:
    """実pipelineを通した1件評価でもsource束縛と50% gateを保持する。"""

    data = _payload(b"logs.example.test:8443")
    digest = hashlib.sha256(data).hexdigest()
    sample_dir = tmp_path / "samples" / digest
    sample_dir.mkdir(parents=True)
    (sample_dir / "fixture.bin").write_bytes(data)
    manifest = {
        "cohorts": {
            "PureLogsStealer": {
                "root_case_count": 1,
                "root_sha256": [digest],
                "provider_label_role": "route_cohort_only_not_family_confirmation",
                "family": {"confirmed_case_count": 0},
                "config_c2_terminal": {
                    "validated_config_recovered_case_count": 0,
                    "qualified_network_endpoint_recovered_case_count": 0,
                },
            }
        }
    }
    manifest_path = tmp_path / "cohort.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = MODULE.evaluate_cohort(
        cohort_manifest=manifest_path,
        samples_root=tmp_path / "samples",
        cohort_name="PureLogsStealer",
        policy=MODULE.StaticLayerPolicy(max_layers=2, max_depth=1),
    )

    assert result["current"]["strict_joint_success_case_count"] == 1
    assert result["current"]["strict_joint_success_root_sha256"] == [digest]
    assert result["current"]["family_confirmed_root_sha256"] == [digest]
    assert result["current"]["validated_config_recovered_root_sha256"] == [digest]
    assert result["current"]["qualified_c2_recovered_root_sha256"] == [digest]
    assert result["current"]["target_met"] is True
    assert result["current"]["implementation_stable_during_evaluation"] is True
    assert result["current"]["managed_omlx_terminal_recovered_case_count"] == 0
    assert result["current"]["managed_omlx_terminal_recovered_root_sha256"] == []
    assert result["current"]["shared_static_layer_sha256"] == []
    assert "analysis-framework/common/evaluate_purelogs_cohort.py" in (result["implementation_sha256"])
    assert "unpackers/managed_tripledes_gzip.py" in result["implementation_sha256"]
    assert "analysis-framework/malware/purelogs/c2_detector.py" in (result["implementation_sha256"])
    assert "logs.example.test" not in json.dumps(result)


def test_source_identity_covers_transitive_purelogs_and_omlx_dependencies() -> None:
    """評価結果へ影響する間接依存を重複なしの安定順で束縛する。"""

    identity = MODULE._source_identity()

    assert list(identity) == sorted(identity)
    assert len(identity) == len(set(identity))
    assert {
        "analysis-framework/common/immutable_snapshot.py",
        "analysis-framework/common/lineage_child_selector.py",
        "analysis-framework/common/safe_artifact_io.py",
        "analysis-framework/common/safe_private_output.py",
        "extractors/__init__.py",
        "extractors/common.py",
        "extractors/managed_pe.py",
        "extractors/purehvnc/__init__.py",
        "extractors/purehvnc/extractor.py",
        "extractors/purelogs/managed_resource.py",
        "extractors/purelogs/yqty_resource.py",
        "unpackers/managed_eaz_resource.py",
        "unpackers/managed_omlx_semantics.py",
        "unpackers/managed_omlx_tripledes.py",
        "unpackers/profiles/byte_transforms.json",
    } <= set(identity)


@pytest.mark.parametrize(
    "relative_path",
    (
        "analysis-framework/common/lineage_child_selector.py",
        "extractors/__init__.py",
        "extractors/common.py",
        "extractors/purehvnc/__init__.py",
        "extractors/purehvnc/extractor.py",
        "unpackers/managed_omlx_tripledes.py",
        "unpackers/profiles/byte_transforms.json",
    ),
)
def test_source_identity_detects_transitive_implementation_change(
    relative_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """間接依存の内容変化でもimplementation identityを変更する。"""

    before = MODULE._source_identity()
    target = MODULE.REPOSITORY_ROOT / relative_path
    target_key = target.relative_to(MODULE.REPOSITORY_ROOT).as_posix()
    original_read = MODULE._read_regular_file

    def changed_read(path: Path, *, maximum_size: int) -> bytes:
        data = original_read(path, maximum_size=maximum_size)
        return data + b"\n# identity-change-fixture\n" if path == target else data

    monkeypatch.setattr(MODULE, "_read_regular_file", changed_read)

    after = MODULE._source_identity()

    assert before[target_key] != after[target_key]
    assert {key for key in before if before[key] != after[key]} == {target_key}


def test_manifest_case_count_has_absolute_upper_bound(tmp_path: Path) -> None:
    hashes = [f"{index:064x}" for index in range(MODULE.MAX_COHORT_CASES + 1)]
    manifest = {
        "cohorts": {
            "PureLogsStealer": {
                "root_case_count": len(hashes),
                "root_sha256": hashes,
                "provider_label_role": "route_cohort_only_not_family_confirmation",
            }
        }
    }
    path = tmp_path / "too-many-cases.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(MODULE.CohortEvaluationError, match="有界"):
        MODULE.load_cohort(path, "PureLogsStealer")


def test_default_cohort_deadline_covers_25_default_case_budgets() -> None:
    assert MODULE.DEFAULT_COHORT_DEADLINE_SECONDS >= (25 * MODULE.DEFAULT_CASE_DEADLINE_SECONDS)


@pytest.mark.parametrize(
    ("field", "maximum"),
    (
        ("max_layers", MODULE.MAX_POLICY_LAYERS),
        ("max_depth", MODULE.MAX_POLICY_DEPTH),
        ("max_layer_size", MODULE.MAX_POLICY_LAYER_SIZE),
        ("max_total_size", MODULE.MAX_POLICY_TOTAL_SIZE),
        ("max_compression_ratio", MODULE.MAX_POLICY_COMPRESSION_RATIO),
        ("max_archive_members", MODULE.MAX_POLICY_ARCHIVE_MEMBERS),
    ),
)
def test_programmatic_policy_rejects_values_above_absolute_limits(
    field: str,
    maximum: float,
) -> None:
    values = {field: maximum + 1}
    if field == "max_layer_size":
        values["max_total_size"] = MODULE.MAX_POLICY_TOTAL_SIZE
    policy = MODULE.StaticLayerPolicy(**values)

    with pytest.raises(MODULE.CohortEvaluationError, match=field):
        MODULE._validate_policy(policy)


@pytest.mark.parametrize(
    ("option", "value"),
    (
        ("--max-layers", MODULE.MAX_POLICY_LAYERS + 1),
        ("--max-depth", MODULE.MAX_POLICY_DEPTH + 1),
        ("--max-layer-size", MODULE.MAX_POLICY_LAYER_SIZE + 1),
        ("--max-total-size", MODULE.MAX_POLICY_TOTAL_SIZE + 1),
        ("--case-deadline-seconds", MODULE.MAX_CASE_DEADLINE_SECONDS + 1),
        ("--cohort-deadline-seconds", MODULE.MAX_COHORT_DEADLINE_SECONDS + 1),
    ),
)
def test_cli_rejects_values_above_absolute_limits(
    option: str,
    value: float,
) -> None:
    parser = MODULE.build_parser()
    argv = [
        "--cohort-manifest",
        "cohort.json",
        "--samples-root",
        "samples",
        "--output",
        "result.json",
        option,
        str(value),
    ]

    with pytest.raises(SystemExit):
        parser.parse_args(argv)


def test_case_deadline_is_checked_after_static_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"deadline-fixture"
    digest = hashlib.sha256(data).hexdigest()
    sample_path = tmp_path / "fixture.bin"
    sample_path.write_bytes(data)
    now = [0.0]

    def recover(*_args: object, **_kwargs: object) -> tuple[list[object], dict]:
        now[0] = 2.0
        return [_layer(data)], {"counts": {"limit_events": 0}, "steps": []}

    monkeypatch.setattr(MODULE, "recover_static_layers", recover)

    with pytest.raises(MODULE.EvaluationDeadlineExceeded) as raised:
        MODULE.evaluate_case(
            sample_path,
            digest,
            policy=MODULE.StaticLayerPolicy(max_layers=2, max_depth=1),
            deadline=1.0,
            clock=lambda: now[0],
        )

    assert raised.value.scope == "case"


def test_cohort_deadline_stops_starting_new_cases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hashes = [f"{index + 1:064x}" for index in range(3)]
    manifest = {
        "cohorts": {
            "PureLogsStealer": {
                "root_case_count": len(hashes),
                "root_sha256": hashes,
                "provider_label_role": "route_cohort_only_not_family_confirmation",
                "family": {"confirmed_case_count": 0},
                "config_c2_terminal": {
                    "validated_config_recovered_case_count": 0,
                    "qualified_network_endpoint_recovered_case_count": 0,
                },
            }
        }
    }
    manifest_path = tmp_path / "cohort.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    now = [0.0]
    calls: list[str] = []

    def evaluate(*_args: object, **kwargs: object) -> dict:
        calls.append(str(kwargs["deadline_scope"]))
        now[0] = 2.0
        raise MODULE.EvaluationDeadlineExceeded(str(kwargs["deadline_scope"]))

    monkeypatch.setattr(MODULE, "_source_identity", lambda: {"fixture.py": "0" * 64})
    monkeypatch.setattr(MODULE, "_sample_path", lambda *_args: tmp_path / "unused")
    monkeypatch.setattr(MODULE, "evaluate_case", evaluate)

    result = MODULE.evaluate_cohort(
        cohort_manifest=manifest_path,
        samples_root=tmp_path,
        cohort_name="PureLogsStealer",
        policy=MODULE.StaticLayerPolicy(max_layers=2, max_depth=1),
        case_deadline_seconds=10.0,
        cohort_deadline_seconds=1.0,
        clock=lambda: now[0],
    )

    assert calls == ["cohort"]
    assert result["current"]["cohort_deadline_exceeded_case_count"] == 3
    assert result["current"]["case_deadline_exceeded_count"] == 0
    assert result["current"]["evaluation_completed_without_deadline"] is False
    assert result["current"]["target_met"] is False


def test_case_deadline_isolated_from_later_cases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hashes = [f"{index + 1:064x}" for index in range(2)]
    manifest = {
        "cohorts": {
            "PureLogsStealer": {
                "root_case_count": len(hashes),
                "root_sha256": hashes,
                "provider_label_role": "route_cohort_only_not_family_confirmation",
                "family": {"confirmed_case_count": 0},
                "config_c2_terminal": {
                    "validated_config_recovered_case_count": 0,
                    "qualified_network_endpoint_recovered_case_count": 0,
                },
            }
        }
    }
    manifest_path = tmp_path / "cohort.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    now = [0.0]
    calls: list[str] = []

    def evaluate(_path: Path, digest: str, **kwargs: object) -> dict:
        scope = str(kwargs["deadline_scope"])
        calls.append(scope)
        if len(calls) == 1:
            now[0] = 2.0
            raise MODULE.EvaluationDeadlineExceeded(scope)
        return {
            "root_sha256": digest,
            "family_confirmed": False,
            "validated_config_recovered": False,
            "qualified_c2_recovered": False,
            "strict_success": False,
            "blockers": [],
            "evaluation_error_count": 0,
            "evaluation_errors": [],
            "sample_executed": False,
            "network_contacted": False,
        }

    monkeypatch.setattr(MODULE, "_source_identity", lambda: {"fixture.py": "0" * 64})
    monkeypatch.setattr(MODULE, "_sample_path", lambda *_args: tmp_path / "unused")
    monkeypatch.setattr(MODULE, "evaluate_case", evaluate)

    result = MODULE.evaluate_cohort(
        cohort_manifest=manifest_path,
        samples_root=tmp_path,
        cohort_name="PureLogsStealer",
        policy=MODULE.StaticLayerPolicy(max_layers=2, max_depth=1),
        case_deadline_seconds=1.0,
        cohort_deadline_seconds=100.0,
        clock=lambda: now[0],
    )

    assert calls == ["case", "case"]
    assert result["current"]["case_deadline_exceeded_count"] == 1
    assert result["current"]["cohort_deadline_exceeded_case_count"] == 0
    assert len(result["cases"]) == 2


@pytest.mark.parametrize(
    ("case_deadline_seconds", "cohort_deadline_seconds", "expected_blocker"),
    (
        (1.0, 100.0, "case_deadline_exceeded"),
        (10.0, 1.0, "cohort_deadline_exceeded"),
    ),
)
def test_generic_case_failure_after_deadline_is_also_marked_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_deadline_seconds: float,
    cohort_deadline_seconds: float,
    expected_blocker: str,
) -> None:
    """下位処理の別例外でも期限超過を成功扱いへ戻さない。"""

    digest = "1" * 64
    manifest = {
        "cohorts": {
            "PureLogsStealer": {
                "root_case_count": 1,
                "root_sha256": [digest],
                "provider_label_role": "route_cohort_only_not_family_confirmation",
                "family": {"confirmed_case_count": 0},
                "config_c2_terminal": {
                    "validated_config_recovered_case_count": 0,
                    "qualified_network_endpoint_recovered_case_count": 0,
                },
            }
        }
    }
    manifest_path = tmp_path / "cohort.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    now = [0.0]

    def evaluate(*_args: object, **_kwargs: object) -> dict:
        now[0] = 2.0
        raise ValueError("公開結果へ含めないfixture例外")

    monkeypatch.setattr(MODULE, "_source_identity", lambda: {"fixture.py": "0" * 64})
    monkeypatch.setattr(MODULE, "_sample_path", lambda *_args: tmp_path / "unused")
    monkeypatch.setattr(MODULE, "evaluate_case", evaluate)

    result = MODULE.evaluate_cohort(
        cohort_manifest=manifest_path,
        samples_root=tmp_path,
        cohort_name="PureLogsStealer",
        policy=MODULE.StaticLayerPolicy(max_layers=2, max_depth=1),
        case_deadline_seconds=case_deadline_seconds,
        cohort_deadline_seconds=cohort_deadline_seconds,
        clock=lambda: now[0],
    )

    assert result["cases"][0]["blockers"] == [
        "case_evaluation_failed",
        expected_blocker,
    ]
    assert result["current"]["evaluation_completed_without_deadline"] is False
    assert result["current"]["target_met"] is False
