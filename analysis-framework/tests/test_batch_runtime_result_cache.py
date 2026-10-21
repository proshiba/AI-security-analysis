"""batch内の検出器・handler結果cacheが証拠境界を変えないことを確認する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample as one_shot  # noqa: E402
import handler_catalog as catalog  # noqa: E402


def _spec() -> catalog.HandlerSpec:
    return catalog.HandlerSpec(
        id="cache-fixture:extractors.cache_fixture:extract",
        family="cache-fixture",
        relative_path="extractors/cache_fixture.py",
        callable_name="extract",
        invocation="bytes_name",
        source="shared_extractor",
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason="test fixture",
        input_formats=("data",),
        input_contract_source="module_declaration",
        minimum_evidence_score=1,
    )


def _zero_output_execution(spec: catalog.HandlerSpec) -> dict:
    return {
        "handler": spec.public(),
        "result": {"status": "not_applicable", "reason": "fixture"},
        "result_quota": {
            "maximum_entries": 4096,
            "maximum_string_characters": 2 * 1024 * 1024,
            "maximum_binary_bytes": 256 * 1024 * 1024,
            "entries_seen": 2,
            "string_characters_seen": 16,
            "binary_bytes_seen": 0,
            "truncated": False,
            "reasons": [],
        },
        "observed_binary_outputs": [],
        "verified_binary_outputs": [],
        "verified_binary_output_audit": {
            "schema_version": 1,
            "binary_values_seen": 0,
            "binary_bytes_seen": 0,
            "observed_output_count": 0,
            "retained_output_count": 0,
            "retained_for_follow_on_analysis": False,
            "observation_scope": "parent_verified_zero_output",
            "truncated": False,
            "reasons": [],
        },
        "executed_sample": False,
        "network_contacted": False,
    }


def _install_handler_preflight_stubs(
    monkeypatch: pytest.MonkeyPatch,
    spec: catalog.HandlerSpec,
) -> catalog._AssessmentInvariantPreflight:
    invariant = catalog._AssessmentInvariantPreflight(
        spec=spec,
        blockers=(),
        source_sha256="a" * 64,
        dependency_audit={},
        commitment_sha256="b" * 64,
    )
    monkeypatch.setattr(catalog, "_preflight_dependency_source_manifest", lambda _value: [])
    monkeypatch.setattr(catalog, "_preflight_dependency_module_manifest", lambda _value: [])
    monkeypatch.setattr(catalog, "_preflight_dependency_data_manifest", lambda _value: [])
    return invariant


def test_classification_cache_reuses_exact_input_and_returns_independent_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じlayer SHA・source名・optionだけがhitし、callerの変更を共有しない。"""

    registry = tmp_path / "registry.json"
    registry.write_text("{}", encoding="utf-8")
    calls: list[tuple[bytes, str, str | None]] = []

    def classify(data: bytes, source: Path, _registry: Path, family: str | None) -> dict:
        calls.append((data, source.as_posix(), family))
        return {
            "sample": source.as_posix(),
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "observations": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "detector_errors": {},
            },
            "detector_evaluations": [{"error": None}],
        }

    monkeypatch.setattr(one_shot.classify_sample, "classify_bytes", classify)
    cache = one_shot._BatchClassificationCache("1" * 64)
    first = cache.classify(b"same-layer", Path("child.bin"), registry, None)
    first["observations"]["poisoned"] = True
    second = cache.classify(b"same-layer", Path("child.bin"), registry, None)

    assert len(calls) == 1
    assert second["observations"].get("poisoned") is None
    assert cache.hit_count == cache.miss_count == cache.store_count == 1

    cache.classify(b"same-layer", Path("renamed.bin"), registry, None)
    cache.classify(b"same-layer", Path("child.bin"), registry, "valleyrat")
    assert len(calls) == 3

    other_source_seal = one_shot._BatchClassificationCache("2" * 64)
    other_source_seal.classify(b"same-layer", Path("child.bin"), registry, None)
    assert len(calls) == 4


def test_classification_cache_halves_repeated_64_layer_detector_orchestration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別caseで同じ64層が再登場しても全detector orchestrationを再実行しない。"""

    registry = tmp_path / "registry.json"
    registry.write_text("{}", encoding="utf-8")
    call_count = 0

    def classify(data: bytes, source: Path, _registry: Path, _family: str | None) -> dict:
        nonlocal call_count
        call_count += 1
        return {
            "sample": source.as_posix(),
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "observations": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "detector_errors": {},
            },
            "detector_evaluations": [{"error": None}],
        }

    monkeypatch.setattr(one_shot.classify_sample, "classify_bytes", classify)
    cache = one_shot._BatchClassificationCache("5" * 64)
    layers = [(f"layer-{index:02d}.bin", f"layer-{index:02d}".encode()) for index in range(64)]
    for _case in range(2):
        for name, data in layers:
            cache.classify(data, Path(name), registry, None)

    assert call_count == 64
    assert cache.store_count == 64
    assert cache.hit_count == 64


def test_classification_cache_does_not_reuse_detector_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """detectorの一時的な例外結果は後続caseへ固定しない。"""

    registry = tmp_path / "registry.json"
    registry.write_text("{}", encoding="utf-8")
    calls = 0

    def classify(_data: bytes, source: Path, _registry: Path, _family: str | None) -> dict:
        nonlocal calls
        calls += 1
        return {
            "sample": source.as_posix(),
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "observations": {
                "sha256": hashlib.sha256(b"same-layer").hexdigest(),
                "detector_errors": {"fixture": "RuntimeError: temporary"},
            },
            "detector_evaluations": [{"error": "RuntimeError: temporary"}],
        }

    monkeypatch.setattr(one_shot.classify_sample, "classify_bytes", classify)
    cache = one_shot._BatchClassificationCache("7" * 64)
    for _ in range(2):
        cache.classify(b"same-layer", Path("child.bin"), registry, None)

    assert calls == 2
    assert cache.hit_count == cache.store_count == 0
    assert cache.miss_count == 2


def test_handler_cache_avoids_duplicate_worker_and_is_immutable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一source commitment・layer・optionの二重評価はworkerを1回にする。"""

    spec = _spec()
    invariant = _install_handler_preflight_stubs(monkeypatch, spec)
    calls = 0

    def execute(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return _zero_output_execution(spec)

    monkeypatch.setattr(catalog, "_execute_handler_bounded", execute)
    cache = catalog._AssessmentExecutionCache("3" * 64)
    first = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"same-layer",
        "child.bin",
        actual_format="data",
        _invariant_preflight=invariant,
        _execution_cache=cache,
    )
    first["execution"]["result"]["poisoned"] = True
    second = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"same-layer",
        "child.bin",
        actual_format="data",
        _invariant_preflight=invariant,
        _execution_cache=cache,
    )

    assert calls == 1
    assert second["execution"]["result"].get("poisoned") is None
    assert cache.hit_count == cache.miss_count == cache.store_count == 1

    catalog.execute_handler_bounded_for_assessment(
        spec,
        b"same-layer",
        "other.bin",
        actual_format="data",
        _invariant_preflight=invariant,
        _execution_cache=cache,
    )
    assert calls == 2

    changed_source = catalog._AssessmentInvariantPreflight(
        spec=spec,
        blockers=(),
        source_sha256="c" * 64,
        dependency_audit={},
        commitment_sha256="d" * 64,
    )
    catalog.execute_handler_bounded_for_assessment(
        spec,
        b"same-layer",
        "child.bin",
        actual_format="data",
        _invariant_preflight=changed_source,
        _execution_cache=cache,
    )
    assert calls == 3

    other_batch = catalog._AssessmentExecutionCache("6" * 64)
    catalog.execute_handler_bounded_for_assessment(
        spec,
        b"same-layer",
        "child.bin",
        actual_format="data",
        _invariant_preflight=invariant,
        _execution_cache=other_batch,
    )
    assert calls == 4


def test_handler_cache_never_reuses_retained_output_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """follow-on artifactを伴う結果はcase間で再利用せず、毎回親が再検証する。"""

    spec = _spec()
    invariant = _install_handler_preflight_stubs(monkeypatch, spec)
    calls = 0
    digest = hashlib.sha256(b"MZfixture").hexdigest()

    def execute(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        result = _zero_output_execution(spec)
        result["observed_binary_outputs"] = [{"sha256": digest}]
        result["verified_binary_outputs"] = [{"sha256": digest}]
        result["verified_binary_output_audit"].update(
            observed_output_count=1,
            retained_output_count=1,
            retained_for_follow_on_analysis=True,
            observation_scope="parent_rehashed_case_artifact",
        )
        return result

    monkeypatch.setattr(catalog, "_execute_handler_bounded", execute)
    cache = catalog._AssessmentExecutionCache("4" * 64)
    for _ in range(2):
        catalog.execute_handler_bounded_for_assessment(
            spec,
            b"same-layer",
            "child.bin",
            actual_format="data",
            _invariant_preflight=invariant,
            _execution_cache=cache,
        )

    assert calls == 2
    assert cache.store_count == cache.hit_count == 0
    assert cache.miss_count == 2


def test_handler_cache_never_reuses_incomplete_runtime_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """時間・容量に依存するpartial結果は後続caseへ固定しない。"""

    spec = _spec()
    invariant = _install_handler_preflight_stubs(monkeypatch, spec)
    calls = 0

    def execute(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        result = _zero_output_execution(spec)
        result["result"] = {
            "status": "configuration_candidate_scan_incomplete",
            "candidate_set_complete": False,
        }
        return result

    monkeypatch.setattr(catalog, "_execute_handler_bounded", execute)
    cache = catalog._AssessmentExecutionCache("8" * 64)
    for _ in range(2):
        catalog.execute_handler_bounded_for_assessment(
            spec,
            b"same-layer",
            "child.bin",
            actual_format="data",
            _invariant_preflight=invariant,
            _execution_cache=cache,
        )

    assert calls == 2
    assert cache.store_count == cache.hit_count == 0
    assert cache.miss_count == 2
