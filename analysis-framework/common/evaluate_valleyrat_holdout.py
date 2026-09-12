#!/usr/bin/env python3
"""封印済みone-shot成果物だけでValleyRATのオフラインholdout評価を行う。

検体本体を開かず、外部通信やsubprocessを使わない。single-set分割はfamily名、
C2値、解析成否から独立させ、近縁構造を同じ側へ固定する。公式reference modeは
identityを事前登録し、構造類似を既知／新規へ分ける。公開出力にcase識別子、
通信先、source name、private pathを含めない。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import orchestration_outcome  # noqa: E402
import summarize_one_shot_corpus as corpus  # noqa: E402

SCHEMA_VERSION = 2
TARGET_FAMILY = "valleyrat"
SPLIT_VERSION = "valleyrat-static-structure-holdout-v2"
PRE_REGISTRATION_SCHEMA_VERSION = 1
PRE_REGISTRATION_VERSION = "valleyrat-ai-free-holdout-preregistration-v1"
IDENTITY_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_HOLDOUT_COUNT = 100
DEFAULT_MINIMUM_SUCCESS_PERCENTAGE = 50.0
OFFICIAL_REQUIRED_JOINT_SUCCESSES = 50

ALLOWED_FAMILY_SOURCES = frozenset({"detector_selected", "detector_candidate"})
DISALLOWED_IDENTITY_SOURCE = "known_hash"
DISALLOWED_EXTERNAL_SOURCE = "external_metadata"
EXPECTED_FAMILY_STRENGTH = {"detector_selected": 3, "detector_candidate": 2}
MINIMUM_HANDLER_TIER = {"detector_selected": 1, "detector_candidate": 2}
C2_ROLES = frozenset(
    role
    for role in orchestration_outcome.CONTROL_NETWORK_ROLES
    if role not in {"exfil", "exfiltration", "exfiltration_endpoint"}
)
STATIC_CONFIG_RECOVERY_TYPES = frozenset(orchestration_outcome.CONFIG_FLAGS)
STATIC_LINEAGE_SOURCES = frozenset(
    {"candidate_verification", "selected_family_analysis"}
)

NEAR_JACCARD_NUMERATOR = 4
NEAR_JACCARD_DENOMINATOR = 5
MINIMUM_NEAR_SHARED_FINGERPRINTS = 2
MAX_EVALUATION_CASES = 4_096
MAX_LOGIC_FINGERPRINTS_PER_CASE = corpus.MAX_FUNCTION_RECORDS
MAX_TOTAL_LOGIC_FINGERPRINTS = 2_000_000
MAX_NEAR_CANDIDATE_PAIRS = 2_000_000


class HoldoutEvaluationError(ValueError):
    """秘密値を含まない固定codeを持つholdout評価エラー。"""

    def __init__(self, code: str, message_ja: str) -> None:
        super().__init__(message_ja)
        self.code = code


@dataclass(frozen=True)
class _CaseEvidence:
    """分割と評価に必要な非公開case record。"""

    digest: str
    exact_axes: tuple[tuple[str, str], ...]
    logic_fingerprints: frozenset[str]
    profile_axes: frozenset[str]
    family_confirmed: bool
    family_failure_reason: str | None
    c2_config_confirmed: bool
    c2_failure_reason: str | None


@dataclass(frozen=True)
class _ClusterPlan:
    """case indexだけを持つ非公開の構造cluster計画。"""

    components: tuple[tuple[int, ...], ...]
    exact_groups: tuple[tuple[int, ...], ...]
    near_pairs: tuple[tuple[int, int], ...]
    exact_relationship_count: int
    exact_axis_case_counts: tuple[tuple[str, int], ...]
    logic_fingerprint_case_count: int
    profile_axis_case_count: int


class _DisjointSet:
    """exact／near関係を決定的な連結成分へまとめる。"""

    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


def _safe_corpus_summary(run_paths: Sequence[Path]) -> dict[str, Any]:
    """既存のseal検証器を通し、入力由来の値をerrorへ反射しない。"""

    try:
        return corpus.summarize_runs(run_paths)
    except corpus.CorpusSummaryError as exc:
        raise HoldoutEvaluationError(
            f"sealed_corpus_{exc.code}",
            "封印済みone-shot成果物の検証に失敗しました。",
        ) from exc


def _logic_fingerprints(static_logic: Mapping[str, Any]) -> frozenset[str]:
    """比較可能な関数logic fingerprintを上限付きで取得する。"""

    functions = static_logic.get("functions")
    if not isinstance(functions, list):
        return frozenset()
    if len(functions) > corpus.MAX_FUNCTION_RECORDS:
        raise HoldoutEvaluationError(
            "static_logic_function_limit_exceeded",
            "static logicの関数件数がholdout評価上限を超えています。",
        )
    fingerprints: set[str] = set()
    for function in functions:
        if not isinstance(function, Mapping):
            continue
        supplied = function.get("fingerprints")
        if not isinstance(supplied, Mapping):
            continue
        token_count = supplied.get("semantic_token_count")
        if not isinstance(token_count, int) or isinstance(token_count, bool) or token_count < 4:
            continue
        semantic = str(supplied.get("semantic_sequence_sha256") or "").casefold()
        normalized = str(supplied.get("normalized_logic_sha256") or "").casefold()
        if corpus.SHA256_RE.fullmatch(semantic):
            fingerprints.add(f"semantic:{semantic}")
        elif corpus.SHA256_RE.fullmatch(normalized):
            fingerprints.add(f"normalized:{normalized}")
        if len(fingerprints) > MAX_LOGIC_FINGERPRINTS_PER_CASE:
            raise HoldoutEvaluationError(
                "logic_fingerprint_limit_exceeded",
                "一caseのlogic fingerprint件数がholdout評価上限を超えています。",
            )
    return frozenset(fingerprints)


def _family_failure_reason(resolution: Mapping[str, Any]) -> str | None:
    """family名や外部hintではなくdetectorとhandlerの相関だけを受理する。"""

    if resolution.get("status") != "resolved":
        return "family_not_resolved"
    if resolution.get("family") != TARGET_FAMILY:
        return "family_resolved_as_other"
    source = resolution.get("source")
    if source == DISALLOWED_IDENTITY_SOURCE:
        return "family_sample_identity_only_disallowed"
    if source == DISALLOWED_EXTERNAL_SOURCE:
        return "family_external_hint_disallowed"
    if source not in ALLOWED_FAMILY_SOURCES:
        return "family_structural_detector_evidence_missing"
    if resolution.get("reason") != "unique_strongest_corroborated_candidate":
        return "family_resolution_contract_incomplete"
    expected_strength = EXPECTED_FAMILY_STRENGTH[source]
    minimum_tier = MINIMUM_HANDLER_TIER[source]
    handler_tier = resolution.get("handler_tier")
    if (
        resolution.get("source_strength") != expected_strength
        or not isinstance(handler_tier, int)
        or isinstance(handler_tier, bool)
        or handler_tier < minimum_tier
    ):
        return "family_resolution_contract_incomplete"
    candidates = resolution.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > corpus.MAX_CANDIDATE_FAMILIES:
        return "family_resolution_contract_incomplete"
    # すべての候補で件数契約は検証するが、非winnerの外部metadataや既知hashは
    # 独立detectorが選んだwinnerの根拠ではないため、存在だけで失格にしない。
    for candidate in candidates:
        candidate_summary = (
            candidate.get("evidence_summary")
            if isinstance(candidate, Mapping)
            else None
        )
        if not isinstance(candidate_summary, Mapping):
            return "family_resolution_contract_incomplete"
        counts = [
            candidate_summary.get(key)
            for key in ("known_hash", "detector", "external_metadata")
        ]
        if any(type(count) is not int or count < 0 for count in counts):
            return "family_resolution_contract_incomplete"
    winners = [
        candidate
        for candidate in candidates
        if isinstance(candidate, Mapping)
        and candidate.get("family") == TARGET_FAMILY
        and candidate.get("source") == source
        and candidate.get("source_strength") == expected_strength
        and candidate.get("handler_tier") == handler_tier
        and candidate.get("qualified") is True
    ]
    if len(winners) != 1:
        return "family_resolution_contract_incomplete"
    winner = winners[0]
    evidence_summary = winner.get("evidence_summary")
    detector_count = evidence_summary.get("detector") if isinstance(evidence_summary, Mapping) else None
    if (
        not isinstance(detector_count, int)
        or isinstance(detector_count, bool)
        or detector_count < 1
        or type(evidence_summary.get("known_hash")) is not int
        or evidence_summary.get("known_hash") != 0
        # 外部metadataはdetectorの根拠へ加点されない。単なる併記は許容し、
        # source自体がexternal_metadataの場合だけ上段で拒否する。
        or type(evidence_summary.get("external_metadata")) is not int
    ):
        return "family_resolution_contract_incomplete"
    if source == "detector_selected" and winner.get("attribution_eligible") is not True:
        return "family_resolution_contract_incomplete"
    if source == "detector_candidate" and winner.get("handler_corroborated") is not True:
        return "family_resolution_contract_incomplete"
    return None


def _static_lineage_identity(value: object) -> tuple[str, str, str] | None:
    """公開provenanceをValleyRATの静的handler lineageへ縮約する。"""

    if not isinstance(value, Mapping) or value.get("family") != TARGET_FAMILY:
        return None
    handler_id = value.get("handler_id")
    source = value.get("source")
    evidence_path = value.get("evidence_path")
    if (
        not isinstance(handler_id, str)
        or not handler_id
        or len(handler_id) > 256
        or source not in STATIC_LINEAGE_SOURCES
        or not isinstance(evidence_path, str)
        or not evidence_path
        or len(evidence_path) > 1_024
    ):
        return None
    return TARGET_FAMILY, handler_id, source


def _static_config_lineages(value: object) -> set[tuple[str, str, str]] | None:
    """確定config evidenceを検証し、値を公開せずlineage集合だけを返す。"""

    if (
        not isinstance(value, list)
        or not value
        or len(value) > orchestration_outcome.MAX_CONTAINER_ITEMS
    ):
        return None
    lineages: set[tuple[str, str, str]] = set()
    for evidence in value:
        if (
            not isinstance(evidence, Mapping)
            or evidence.get("recovery_type") not in STATIC_CONFIG_RECOVERY_TYPES
        ):
            return None
        correlated_keys = evidence.get("correlated_keys")
        if (
            not isinstance(correlated_keys, list)
            or not correlated_keys
            or len(correlated_keys) > orchestration_outcome.MAX_CONTAINER_ITEMS
            or any(not isinstance(item, str) or not item for item in correlated_keys)
        ):
            return None
        identity = _static_lineage_identity(evidence.get("provenance"))
        if identity is None:
            return None
        lineages.add(identity)
    return lineages or None


def _c2_failure_reason(orchestration: Mapping[str, Any]) -> str | None:
    """静的configと相関したcontrol endpoint recordだけをC2設定確定とする。"""

    outputs = orchestration.get("outputs")
    if not isinstance(outputs, Mapping) or outputs.get("config_recovered") is not True:
        return "confirmed_config_missing"
    quality_gates = orchestration.get("quality_gates")
    config_gate = quality_gates.get("config") if isinstance(quality_gates, Mapping) else None
    if (
        not isinstance(config_gate, Mapping)
        or config_gate.get("satisfied") is not True
        or config_gate.get("status") != "satisfied"
    ):
        return "confirmed_config_gate_not_satisfied"
    config_lineages = _static_config_lineages(outputs.get("config_evidence"))
    if config_lineages is None:
        return "confirmed_config_evidence_missing"
    endpoints = outputs.get("qualified_network_endpoints")
    if not isinstance(endpoints, list) or not endpoints or len(endpoints) > orchestration_outcome.MAX_CONTAINER_ITEMS:
        return "c2_config_correlation_missing"
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            continue
        basis = endpoint.get("evidence_basis")
        raw_provenance = endpoint.get("provenance")
        endpoint_lineages = (
            {
                identity
                for item in raw_provenance
                if (identity := _static_lineage_identity(item)) is not None
            }
            if isinstance(raw_provenance, list)
            and raw_provenance
            and len(raw_provenance) <= orchestration_outcome.MAX_CONTAINER_ITEMS
            else set()
        )
        if (
            endpoint.get("role") in C2_ROLES
            and endpoint.get("contacted") is False
            and isinstance(basis, list)
            and "static_config_correlation" in basis
            and config_lineages.intersection(endpoint_lineages)
        ):
            return None
    return "c2_config_correlation_missing"


def _profile_axes(public_case: Mapping[str, Any]) -> frozenset[str]:
    """既存集計器がallowlist化したValleyRAT構造profileだけを返す。"""

    gap = public_case.get("automation_gap")
    if not isinstance(gap, Mapping):
        return frozenset()
    detector = gap.get("detector")
    if not isinstance(detector, Mapping):
        return frozenset()
    output: set[str] = set()
    for field, prefix in (
        ("loader_profile_layer_counts", "loader"),
        ("route_profile_layer_counts", "route"),
    ):
        values = detector.get(field)
        if not isinstance(values, Mapping):
            continue
        output.update(
            f"{prefix}:{item}"
            for item, count in values.items()
            if isinstance(item, str) and isinstance(count, int) and not isinstance(count, bool) and count > 0
        )
    return frozenset(output)


def _read_case_evidence(
    root: Path,
    public_case: Mapping[str, Any],
    budget: corpus._ReadBudget,
) -> _CaseEvidence:
    """public集計と同じartifact commitmentへ束縛した非公開判定材料を読む。"""

    digest = public_case.get("sha256")
    if not isinstance(digest, str) or corpus.SHA256_RE.fullmatch(digest) is None:
        raise HoldoutEvaluationError(
            "public_case_identity_invalid",
            "検証済みcaseの内部identity契約が不正です。",
        )
    try:
        case_dir = corpus._regular_directory(
            root / "cases" / digest,
            code="case_directory_invalid",
        )
        report_path = corpus.analysis_contract.resolve_case_artifact(case_dir, "report.json")
        report, report_raw = corpus._read_json_snapshot(
            report_path,
            budget,
            error_prefix="holdout_report",
        )
        corpus._validate_report(report, digest)
        documents: dict[str, dict[str, Any]] = {}
        artifact_hashes: dict[str, str] = {}
        for relative in corpus.REQUIRED_CASE_ARTIFACTS:
            documents[relative], artifact_hashes[relative] = corpus._case_artifact(
                case_dir,
                report,
                relative,
                budget,
            )
        generic: dict[str, Any] | None = None
        if "generic-triage.json" in report["artifact_sha256"]:
            generic, artifact_hashes["generic-triage.json"] = corpus._case_artifact(
                case_dir,
                report,
                "generic-triage.json",
                budget,
            )
        for relative in corpus.OPTIONAL_GAP_ARTIFACTS:
            if relative in report["artifact_sha256"]:
                _document, artifact_hashes[relative] = corpus._case_artifact(
                    case_dir,
                    report,
                    relative,
                    budget,
                )
        orchestration = documents["orchestration.json"]
        static_logic = documents["static-logic.json"]
        corpus._validate_orchestration(orchestration, digest)
        corpus._validate_candidate_assessment(documents["candidate-handler-assessment.json"])
        corpus._validate_route(documents["route-config-candidates.json"], digest)
    except corpus.CorpusSummaryError as exc:
        raise HoldoutEvaluationError(
            f"sealed_case_{exc.code}",
            "holdout判定材料のseal検証に失敗しました。",
        ) from exc

    if static_logic.get("schema_version") != 1 or static_logic.get("sha256") != digest:
        raise HoldoutEvaluationError(
            "static_logic_identity_invalid",
            "static logicのcase identityが一致しません。",
        )
    if generic is not None:
        generic_digest = generic.get("sha256")
        if generic_digest is not None and generic_digest != digest:
            raise HoldoutEvaluationError(
                "generic_triage_identity_invalid",
                "generic triageのcase identityが一致しません。",
            )
    commitment = corpus._canonical_sha256(
        {
            "report_sha256": corpus._sha256_bytes(report_raw),
            "selected_artifacts": artifact_hashes,
        }
    )
    if commitment != public_case.get("artifact_commitment_sha256"):
        raise HoldoutEvaluationError(
            "case_artifact_commitment_changed",
            "集計後にholdout判定対象の成果物が変更されました。",
        )

    resolution = orchestration["family_resolution"]
    family_reason = _family_failure_reason(resolution)
    c2_reason = _c2_failure_reason(orchestration)
    return _CaseEvidence(
        digest=digest,
        exact_axes=tuple(sorted(corpus._structure_axes(generic, static_logic).items())),
        logic_fingerprints=_logic_fingerprints(static_logic),
        profile_axes=_profile_axes(public_case),
        family_confirmed=family_reason is None,
        family_failure_reason=family_reason,
        c2_config_confirmed=c2_reason is None,
        c2_failure_reason=c2_reason,
    )


def _index_case_roots(
    roots: Sequence[Path],
    budget: corpus._ReadBudget,
) -> dict[str, list[Path]]:
    """各runの検証済みsummaryからroot caseの所在だけを索引化する。"""

    locations: dict[str, list[Path]] = defaultdict(list)
    for root in roots:
        try:
            summary, _raw = corpus._read_json_snapshot(
                root / "summary.json",
                budget,
                error_prefix="holdout_run_summary",
            )
            normalized = corpus._validate_run_summary(summary)
        except corpus.CorpusSummaryError as exc:
            raise HoldoutEvaluationError(
                f"sealed_run_{exc.code}",
                "holdout入力summaryの検証に失敗しました。",
            ) from exc
        for digest in normalized["cases"]:
            locations[digest].append(root)
    return locations


def _collect_case_evidence(
    run_paths: Sequence[Path],
) -> tuple[list[_CaseEvidence], dict[str, Any]]:
    """seal済みroot caseを収集し、再読込み前後の不変性も確認する。"""

    initial = _safe_corpus_summary(run_paths)
    valid_cases = initial.get("cases")
    if not isinstance(valid_cases, list):
        raise HoldoutEvaluationError(
            "corpus_case_shape_invalid",
            "検証済みコーパスのcase一覧が不正です。",
        )
    if len(valid_cases) > MAX_EVALUATION_CASES:
        raise HoldoutEvaluationError(
            "evaluation_case_limit_exceeded",
            "holdout評価のcase件数が上限を超えています。",
        )
    try:
        roots = [corpus._regular_directory(Path(path), code="run_directory_invalid") for path in run_paths]
    except corpus.CorpusSummaryError as exc:
        raise HoldoutEvaluationError(
            f"sealed_run_{exc.code}",
            "holdout入力directoryの検証に失敗しました。",
        ) from exc
    budget = corpus._ReadBudget()
    locations = _index_case_roots(roots, budget)
    evidence: list[_CaseEvidence] = []
    total_logic_fingerprints = 0
    for public_case in sorted(valid_cases, key=lambda item: str(item.get("sha256", ""))):
        digest = public_case.get("sha256") if isinstance(public_case, Mapping) else None
        candidates = locations.get(digest, []) if isinstance(digest, str) else []
        if not candidates:
            raise HoldoutEvaluationError(
                "case_location_missing",
                "検証済みcaseをrun rootへ束縛できません。",
            )
        observations = [_read_case_evidence(root, public_case, budget) for root in candidates]
        if any(item != observations[0] for item in observations[1:]):
            raise HoldoutEvaluationError(
                "duplicate_case_private_evidence_conflict",
                "重複caseのholdout判定材料が一致しません。",
            )
        total_logic_fingerprints += len(observations[0].logic_fingerprints)
        if total_logic_fingerprints > MAX_TOTAL_LOGIC_FINGERPRINTS:
            raise HoldoutEvaluationError(
                "aggregate_logic_fingerprint_limit_exceeded",
                "logic fingerprintの総件数がholdout評価上限を超えています。",
            )
        evidence.append(observations[0])

    final = _safe_corpus_summary(run_paths)
    if (
        initial.get("input_commitment") != final.get("input_commitment")
        or initial.get("counts") != final.get("counts")
        or initial.get("cases") != final.get("cases")
        or initial.get("invalid_cases") != final.get("invalid_cases")
    ):
        raise HoldoutEvaluationError(
            "sealed_corpus_changed_during_evaluation",
            "評価中に封印済みコーパスが変更されました。",
        )
    return evidence, final


def _near_enough(left: _CaseEvidence, right: _CaseEvidence) -> bool:
    """logic類似と別の検証済みprofile軸を同時に満たす場合だけ近縁とする。"""

    if not left.profile_axes.intersection(right.profile_axes):
        return False
    shared = len(left.logic_fingerprints.intersection(right.logic_fingerprints))
    if shared < MINIMUM_NEAR_SHARED_FINGERPRINTS:
        return False
    union_size = len(left.logic_fingerprints.union(right.logic_fingerprints))
    return union_size > 0 and shared * NEAR_JACCARD_DENOMINATOR >= union_size * NEAR_JACCARD_NUMERATOR


def _cluster_cases(cases: Sequence[_CaseEvidence]) -> _ClusterPlan:
    """exact／near関係の連結成分を作り、分割漏洩単位を固定する。"""

    disjoint = _DisjointSet(len(cases))
    exact: dict[tuple[str, str], list[int]] = defaultdict(list)
    axis_available: Counter[str] = Counter()
    for index, case in enumerate(cases):
        for axis, commitment in case.exact_axes:
            exact[(axis, commitment)].append(index)
            axis_available[axis] += 1

    exact_groups: list[tuple[int, ...]] = []
    exact_relationship_count = 0
    for _axis, members in sorted(exact.items()):
        unique_members = tuple(sorted(set(members)))
        if len(unique_members) < 2:
            continue
        exact_groups.append(unique_members)
        exact_relationship_count += len(unique_members) * (len(unique_members) - 1) // 2
        for member in unique_members[1:]:
            disjoint.union(unique_members[0], member)

    profile_members: dict[str, list[int]] = defaultdict(list)
    for index, case in enumerate(cases):
        for profile in case.profile_axes:
            profile_members[profile].append(index)
    candidate_pairs: set[tuple[int, int]] = set()
    for profile in sorted(profile_members):
        members = sorted(set(profile_members[profile]))
        for left, right in combinations(members, 2):
            candidate_pairs.add((left, right))
            if len(candidate_pairs) > MAX_NEAR_CANDIDATE_PAIRS:
                raise HoldoutEvaluationError(
                    "near_pair_limit_exceeded",
                    "near cluster候補数がholdout評価上限を超えています。",
                )
    near_pairs = []
    for left, right in sorted(candidate_pairs):
        if _near_enough(cases[left], cases[right]):
            near_pairs.append((left, right))
            disjoint.union(left, right)

    components: dict[int, list[int]] = defaultdict(list)
    for index in range(len(cases)):
        components[disjoint.find(index)].append(index)
    normalized_components = tuple(
        sorted(
            (tuple(sorted(members)) for members in components.values()),
            key=lambda members: tuple(cases[index].digest for index in members),
        )
    )
    return _ClusterPlan(
        components=normalized_components,
        exact_groups=tuple(exact_groups),
        near_pairs=tuple(near_pairs),
        exact_relationship_count=exact_relationship_count,
        exact_axis_case_counts=tuple(sorted(axis_available.items())),
        logic_fingerprint_case_count=sum(bool(case.logic_fingerprints) for case in cases),
        profile_axis_case_count=sum(bool(case.profile_axes) for case in cases),
    )


def _component_rank(component: Sequence[int], cases: Sequence[_CaseEvidence]) -> bytes:
    """case identityを分割順序だけへ使い、結果やlabelを参照しない。"""

    material = "\0".join((SPLIT_VERSION, *(cases[index].digest for index in sorted(component)))).encode("ascii")
    return hashlib.sha256(material).digest()


def _reconstruct_subset(
    total: int,
    parents: Mapping[int, tuple[int, int]],
) -> set[int]:
    selected: set[int] = set()
    cursor = total
    while cursor:
        previous, component_index = parents[cursor]
        selected.add(component_index)
        cursor = previous
    return selected


def _partition_cases(
    cases: Sequence[_CaseEvidence],
    clusters: _ClusterPlan,
    holdout_count: int,
) -> tuple[set[int], dict[str, int]]:
    """連結成分を壊さず、要求件数へ最も近い決定論的subsetを選ぶ。"""

    case_count = len(cases)
    if not isinstance(holdout_count, int) or isinstance(holdout_count, bool):
        raise HoldoutEvaluationError(
            "holdout_count_invalid",
            "holdout件数は整数で指定してください。",
        )
    if not 1 <= holdout_count < case_count:
        raise HoldoutEvaluationError(
            "holdout_count_out_of_range",
            "holdout件数は検証済みcase総数より小さい正の整数で指定してください。",
        )
    if len(clusters.components) < 2:
        raise HoldoutEvaluationError(
            "structural_split_impossible",
            "全caseが単一の構造clusterに属するためtrain／holdoutを分離できません。",
        )

    ranked = sorted(
        clusters.components,
        key=lambda component: (_component_rank(component, cases), len(component)),
    )
    maximum_reachable = min(case_count - 1, holdout_count * 2)
    reachable = {0}
    parents: dict[int, tuple[int, int]] = {}
    for component_index, component in enumerate(ranked):
        size = len(component)
        for subtotal in sorted(reachable, reverse=True):
            candidate = subtotal + size
            if candidate > maximum_reachable or candidate in reachable:
                continue
            reachable.add(candidate)
            parents[candidate] = (subtotal, component_index)

    choices: list[tuple[int, set[int]]] = [
        (total, _reconstruct_subset(total, parents)) for total in sorted(reachable) if 0 < total < case_count
    ]
    choices.extend(
        (len(component), {index})
        for index, component in enumerate(ranked)
        if maximum_reachable < len(component) < case_count
    )
    if not choices:
        raise HoldoutEvaluationError(
            "structural_split_impossible",
            "構造clusterを保持したtrain／holdout分割を作成できません。",
        )
    actual_count, selected_components = min(
        choices,
        key=lambda item: (
            abs(item[0] - holdout_count),
            0 if item[0] >= holdout_count else 1,
            item[0],
        ),
    )
    holdout = {case_index for component_index in selected_components for case_index in ranked[component_index]}
    if len(holdout) != actual_count or not holdout or len(holdout) == case_count:
        raise HoldoutEvaluationError(
            "structural_split_internal_error",
            "構造clusterを保持した分割の内部検証に失敗しました。",
        )

    exact_leaks = sum(len({member in holdout for member in members}) > 1 for members in clusters.exact_groups)
    near_leaks = sum((left in holdout) != (right in holdout) for left, right in clusters.near_pairs)
    component_leaks = sum(len({member in holdout for member in members}) > 1 for members in clusters.components)
    if exact_leaks or near_leaks or component_leaks:
        raise HoldoutEvaluationError(
            "structural_split_leakage_detected",
            "train／holdout間の構造cluster漏洩を検出しました。",
        )
    return holdout, {
        "actual_holdout_cases": actual_count,
        "train_cases": case_count - actual_count,
        "holdout_component_count": len(selected_components),
        "train_component_count": len(ranked) - len(selected_components),
        "cross_partition_exact_group_count": exact_leaks,
        "cross_partition_near_relationship_count": near_leaks,
        "cross_partition_component_count": component_leaks,
    }


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "percentage": round(numerator * 100.0 / denominator, 2) if denominator else None,
        "denominator_basis": "holdout_cases",
    }


def _validate_minimum_success_percentage(value: float) -> float:
    """最低成功率を検証し、正規化した有限のfloatを返す。"""

    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 100.0
    ):
        raise HoldoutEvaluationError(
            "minimum_success_percentage_invalid",
            "最低成功率は0〜100の有限値で指定してください。",
        )
    return float(value)


def _validate_official_acceptance_target(
    holdout_count: int,
    minimum_success_percentage: float,
) -> None:
    """公式受入試験の100件・同時成功50件契約を固定する。"""

    percentage = _validate_minimum_success_percentage(minimum_success_percentage)
    if (
        type(holdout_count) is not int
        or holdout_count != DEFAULT_HOLDOUT_COUNT
        or percentage != DEFAULT_MINIMUM_SUCCESS_PERCENTAGE
        or math.ceil(holdout_count * percentage / 100.0) != OFFICIAL_REQUIRED_JOINT_SUCCESSES
    ):
        raise HoldoutEvaluationError(
            "official_acceptance_target_not_fixed",
            "公式holdout受入試験は100件中50件の同時成功へ固定されています。",
        )


def _normalized_identity_set(
    identities: Sequence[str],
    *,
    empty_code: str,
) -> tuple[str, ...]:
    """SHA-256 identity集合を重複なしの決定的順序へ正規化する。"""

    if not identities:
        raise HoldoutEvaluationError(
            empty_code,
            "事前登録するidentity集合が空です。",
        )
    if len(identities) > MAX_EVALUATION_CASES:
        raise HoldoutEvaluationError(
            "evaluation_case_limit_exceeded",
            "事前登録するidentity件数が評価上限を超えています。",
        )
    if any(not isinstance(identity, str) or corpus.SHA256_RE.fullmatch(identity) is None for identity in identities):
        raise HoldoutEvaluationError(
            "pre_registration_identity_invalid",
            "事前登録するcase identityがSHA-256契約を満たしません。",
        )
    normalized = tuple(sorted(identities))
    if len(set(normalized)) != len(normalized):
        raise HoldoutEvaluationError(
            "pre_registration_identity_duplicate",
            "同じpartition内のcase identityが重複しています。",
        )
    return normalized


def _identity_set_commitment(identities: Sequence[str]) -> str:
    """identity値を公開せず、順序非依存の集合commitmentを返す。"""

    return corpus._canonical_sha256(
        {
            "domain": PRE_REGISTRATION_VERSION,
            "identity_type": "sha256",
            "identities": list(identities),
        }
    )


def build_pre_registration(
    reference_identities: Sequence[str],
    holdout_identities: Sequence[str],
    *,
    expected_holdout_count: int = DEFAULT_HOLDOUT_COUNT,
    minimum_success_percentage: float = DEFAULT_MINIMUM_SUCCESS_PERCENTAGE,
) -> dict[str, Any]:
    """解析成否を読まず、reference／holdout identityを公式契約へ封印する。"""

    _validate_official_acceptance_target(
        expected_holdout_count,
        minimum_success_percentage,
    )
    reference = _normalized_identity_set(
        reference_identities,
        empty_code="reference_identity_set_missing",
    )
    holdout = _normalized_identity_set(
        holdout_identities,
        empty_code="holdout_identity_set_missing",
    )
    if len(reference) + len(holdout) > MAX_EVALUATION_CASES:
        raise HoldoutEvaluationError(
            "evaluation_case_limit_exceeded",
            "referenceとholdoutのidentity総数が評価上限を超えています。",
        )
    if len(holdout) != expected_holdout_count:
        raise HoldoutEvaluationError(
            "pre_registration_holdout_count_not_exact",
            "公式holdoutのidentity集合は正確に100件必要です。",
        )
    if set(reference).intersection(holdout):
        raise HoldoutEvaluationError(
            "holdout_identity_not_new",
            "holdoutにはreferenceに存在しないSHA-256 identityだけを指定してください。",
        )
    return {
        "schema_version": PRE_REGISTRATION_SCHEMA_VERSION,
        "contract_version": PRE_REGISTRATION_VERSION,
        "target": {
            "family": TARGET_FAMILY,
            "holdout_cases": DEFAULT_HOLDOUT_COUNT,
            "minimum_joint_success_percentage": (DEFAULT_MINIMUM_SUCCESS_PERCENTAGE),
            "required_joint_successes": OFFICIAL_REQUIRED_JOINT_SUCCESSES,
        },
        "reference_identity_scope": {
            "identity_type": "sha256",
            "identity_count": len(reference),
            "identity_set_sha256": _identity_set_commitment(reference),
        },
        "holdout_identity_scope": {
            "identity_type": "sha256",
            "identity_count": len(holdout),
            "identity_set_sha256": _identity_set_commitment(holdout),
        },
        "selection_contract": {
            "identity_commitment_uses_outcomes": False,
            "holdout_identity_source": "private_pre_analysis_manifest",
            "registration_must_precede_holdout_analysis": True,
            "holdout_identity_disjoint_required": True,
            "structural_similarity_policy": "allowed_and_stratified",
            "external_family_hint_accepted": False,
            "known_hash_family_evidence_accepted": False,
            "candidate_only_accepted": False,
        },
    }


def _validate_pre_registration(
    value: Mapping[str, Any],
    reference_cases: Sequence[_CaseEvidence],
    holdout_cases: Sequence[_CaseEvidence],
    *,
    expected_holdout_count: int,
    minimum_success_percentage: float,
) -> dict[str, Any]:
    """事前登録を実際のidentity集合と固定評価契約へ厳密に再結合する。"""

    if not isinstance(value, Mapping):
        raise HoldoutEvaluationError(
            "pre_registration_schema_invalid",
            "holdout事前登録のJSON object契約が不正です。",
        )
    if (
        value.get("schema_version") != PRE_REGISTRATION_SCHEMA_VERSION
        or value.get("contract_version") != PRE_REGISTRATION_VERSION
    ):
        raise HoldoutEvaluationError(
            "pre_registration_schema_invalid",
            "holdout事前登録のschemaまたはcontract versionが不正です。",
        )
    expected = build_pre_registration(
        [case.digest for case in reference_cases],
        [case.digest for case in holdout_cases],
        expected_holdout_count=expected_holdout_count,
        minimum_success_percentage=minimum_success_percentage,
    )
    if dict(value) != expected:
        raise HoldoutEvaluationError(
            "pre_registration_commitment_mismatch",
            "事前登録と評価時のidentity集合または固定目標が一致しません。",
        )
    reference_scope = expected["reference_identity_scope"]
    holdout_scope = expected["holdout_identity_scope"]
    return {
        "status": "verified",
        "contract_version": PRE_REGISTRATION_VERSION,
        "identity_type": "sha256",
        "reference_identity_count": reference_scope["identity_count"],
        "holdout_identity_count": holdout_scope["identity_count"],
        "identity_commitments_match": True,
        "identity_commitment_uses_outcomes": False,
        "holdout_identity_source": "private_pre_analysis_manifest",
        "registration_must_precede_holdout_analysis": True,
        "temporal_order_proven_by_evaluator": False,
        "holdout_identity_disjoint_required": True,
        "structural_similarity_policy": "allowed_and_stratified",
        "raw_identity_values_included": False,
        "identity_commitments_included": False,
    }


def _read_pre_registration(path: Path) -> dict[str, Any]:
    """privateな事前登録JSONを通常fileの有界snapshotとして読む。"""

    try:
        value, _raw = corpus._read_json_snapshot(
            path,
            corpus._ReadBudget(),
            error_prefix="holdout_pre_registration",
        )
    except corpus.CorpusSummaryError as exc:
        raise HoldoutEvaluationError(
            f"pre_registration_{exc.code}",
            "holdout事前登録を安全に読み取れません。",
        ) from exc
    return value


def _read_identity_manifest(path: Path) -> tuple[str, ...]:
    """解析前に固定したprivate holdout SHA-256一覧を有界に読む。"""

    try:
        value, _raw = corpus._read_json_snapshot(
            path,
            corpus._ReadBudget(),
            error_prefix="holdout_identity_manifest",
        )
    except corpus.CorpusSummaryError as exc:
        raise HoldoutEvaluationError(
            f"identity_manifest_{exc.code}",
            "解析前holdout identity manifestを安全に読み取れません。",
        ) from exc
    if (
        set(value) != {"schema_version", "identity_type", "identities"}
        or value.get("schema_version") != IDENTITY_MANIFEST_SCHEMA_VERSION
        or value.get("identity_type") != "sha256"
        or not isinstance(value.get("identities"), list)
    ):
        raise HoldoutEvaluationError(
            "identity_manifest_schema_invalid",
            "解析前holdout identity manifestのschemaが不正です。",
        )
    return _normalized_identity_set(
        value["identities"],
        empty_code="holdout_identity_set_missing",
    )


def _collect_registered_identities(
    run_paths: Sequence[Path],
) -> tuple[str, ...]:
    """case成果物を開かず、検証済みrun summaryのidentityだけを収集する。"""

    if not 1 <= len(run_paths) <= corpus.MAX_RUNS:
        raise HoldoutEvaluationError(
            "pre_registration_run_count_invalid",
            "事前登録用runは1件以上、上限以下で指定してください。",
        )
    try:
        roots = [corpus._regular_directory(Path(path), code="run_directory_invalid") for path in run_paths]
        locations = _index_case_roots(roots, corpus._ReadBudget())
    except corpus.CorpusSummaryError as exc:
        raise HoldoutEvaluationError(
            f"sealed_run_{exc.code}",
            "事前登録用run summaryの検証に失敗しました。",
        ) from exc
    return _normalized_identity_set(
        tuple(locations),
        empty_code="pre_registration_identity_set_missing",
    )


def _public_input_counts(corpus_summary: Mapping[str, Any]) -> dict[str, Any]:
    """識別子やpathを含めず、seal検証結果の集計値だけを返す。"""

    counts = corpus_summary["counts"]
    integrity_clean = (
        counts["batch_errors"] == 0 and counts["invalid_unique_cases"] == 0 and counts["conflicting_case_sha256"] == 0
    )
    return {
        "run_count": corpus_summary["scope"]["run_count"],
        "input_units": counts["input_units"],
        "unique_valid_cases": counts["unique_valid_cases"],
        "batch_errors": counts["batch_errors"],
        "invalid_unique_cases": counts["invalid_unique_cases"],
        "conflicting_case_records": counts["conflicting_case_sha256"],
        "integrity_clean": integrity_clean,
    }


def _cluster_summary(clusters: _ClusterPlan) -> dict[str, Any]:
    """raw構造値を含まないcluster集計を返す。"""

    return {
        "structural_component_count": len(clusters.components),
        "non_singleton_component_count": sum(len(component) > 1 for component in clusters.components),
        "maximum_component_size": max(map(len, clusters.components), default=0),
        "exact_group_count": len(clusters.exact_groups),
        "exact_relationship_count": clusters.exact_relationship_count,
        "near_relationship_count": len(clusters.near_pairs),
        "exact_axis_available_case_counts": dict(clusters.exact_axis_case_counts),
        "logic_fingerprint_available_cases": (clusters.logic_fingerprint_case_count),
        "validated_profile_available_cases": clusters.profile_axis_case_count,
        "near_contract": {
            "minimum_independent_axes": 2,
            "logic_jaccard_minimum": (NEAR_JACCARD_NUMERATOR / NEAR_JACCARD_DENOMINATOR),
            "minimum_shared_logic_fingerprints": (MINIMUM_NEAR_SHARED_FINGERPRINTS),
            "validated_loader_or_route_profile_required": True,
        },
    }


def _success_metrics(
    cases: Sequence[_CaseEvidence],
    *,
    denominator_basis: str,
) -> dict[str, Any]:
    """同一case集合のfamily・C2・同時成功を同じ分母で返す。"""

    family_count = sum(case.family_confirmed for case in cases)
    c2_count = sum(case.c2_config_confirmed for case in cases)
    joint_count = sum(case.family_confirmed and case.c2_config_confirmed for case in cases)

    def rate(numerator: int) -> dict[str, Any]:
        value = _rate(numerator, len(cases))
        value["denominator_basis"] = denominator_basis
        return value

    return {
        "family_confirmed_without_disallowed_hints": rate(family_count),
        "c2_config_confirmed": rate(c2_count),
        "joint_success": rate(joint_count),
    }


def _case_failure_reason_counts(
    cases: Sequence[_CaseEvidence],
) -> dict[str, int]:
    """case集合の固定失敗理由だけを集計する。"""

    return dict(
        sorted(
            Counter(
                reason
                for case in cases
                for reason in (
                    case.family_failure_reason,
                    case.c2_failure_reason,
                )
                if reason is not None
            ).items()
        )
    )


def _reference_structure_strata(
    combined: Sequence[_CaseEvidence],
    clusters: _ClusterPlan,
    boundary: int,
) -> tuple[
    tuple[_CaseEvidence, ...],
    tuple[_CaseEvidence, ...],
    dict[str, int | str | bool],
]:
    """holdoutをreference構造成分との関係だけで既知／新規へ分ける。"""

    if not 0 < boundary < len(combined):
        raise HoldoutEvaluationError(
            "reference_holdout_boundary_invalid",
            "reference／holdoutの内部境界が不正です。",
        )
    known_indexes: set[int] = set()
    known_component_count = 0
    new_component_count = 0
    for component in clusters.components:
        has_reference = any(index < boundary for index in component)
        holdout_members = {index for index in component if index >= boundary}
        if not holdout_members:
            continue
        if has_reference:
            known_indexes.update(holdout_members)
            known_component_count += 1
        else:
            new_component_count += 1

    direct_exact_indexes = {
        index
        for members in clusters.exact_groups
        if any(member < boundary for member in members)
        for index in members
        if index >= boundary
    }
    direct_near_indexes = {
        index
        for left, right in clusters.near_pairs
        if (left < boundary) != (right < boundary)
        for index in (left, right)
        if index >= boundary
    }
    holdout_indexes = set(range(boundary, len(combined)))
    new_indexes = holdout_indexes - known_indexes
    if known_indexes.intersection(new_indexes) or (len(known_indexes) + len(new_indexes) != len(holdout_indexes)):
        raise HoldoutEvaluationError(
            "structure_stratification_internal_error",
            "既知／新規構造の内部集計が一致しません。",
        )
    known_cases = tuple(combined[index] for index in sorted(known_indexes))
    new_cases = tuple(combined[index] for index in sorted(new_indexes))
    return (
        known_cases,
        new_cases,
        {
            "classification_basis": "reference_structural_component_membership",
            "structural_similarity_allowed": True,
            "known_structure_holdout_cases": len(known_cases),
            "new_structure_holdout_cases": len(new_cases),
            "known_structure_component_count": known_component_count,
            "new_structure_component_count": new_component_count,
            "direct_exact_match_holdout_cases": len(direct_exact_indexes),
            "direct_near_match_holdout_cases": len(direct_near_indexes),
            "transitive_only_known_structure_holdout_cases": len(
                known_indexes - direct_exact_indexes - direct_near_indexes
            ),
        },
    )


def _assemble_evaluation(
    *,
    evaluation_mode: str,
    holdout_cases: Sequence[_CaseEvidence],
    requested_holdout_count: int,
    minimum_success_percentage: float,
    input_summary: Mapping[str, Any],
    input_integrity_clean: bool,
    split: Mapping[str, Any],
    pre_registration: Mapping[str, Any] | None = None,
    structure_strata: Mapping[
        str,
        Sequence[_CaseEvidence],
    ]
    | None = None,
    additional_gate_reasons: Sequence[str] = (),
) -> dict[str, Any]:
    """全モード共通の成功指標・安全境界・target gateを組み立てる。"""

    if (
        not isinstance(requested_holdout_count, int)
        or isinstance(requested_holdout_count, bool)
        or requested_holdout_count < 1
    ):
        raise HoldoutEvaluationError(
            "holdout_count_invalid",
            "holdout件数は正の整数で指定してください。",
        )
    minimum_success_percentage = _validate_minimum_success_percentage(minimum_success_percentage)
    metrics = _success_metrics(
        holdout_cases,
        denominator_basis="holdout_cases",
    )
    joint_count = metrics["joint_success"]["numerator"]
    failure_reasons = _case_failure_reason_counts(holdout_cases)
    required_successes = math.ceil(requested_holdout_count * minimum_success_percentage / 100.0)
    gate_reasons: list[str] = []
    if split["actual_holdout_cases"] != requested_holdout_count:
        gate_reasons.append("holdout_size_not_exact")
    if not input_integrity_clean:
        gate_reasons.append("input_integrity_not_clean")
    for reason in additional_gate_reasons:
        if reason not in gate_reasons:
            gate_reasons.append(reason)
    if joint_count < required_successes:
        gate_reasons.append("joint_success_target_not_met")

    structural_disjoint = not any(
        split.get(field, 0)
        for field in (
            "cross_partition_exact_group_count",
            "cross_partition_near_relationship_count",
            "cross_partition_component_count",
        )
    )
    identity_disjoint = split.get("cross_partition_identity_case_count", 0) == 0
    if structure_strata is not None:
        expected_keys = {"known_structure", "new_structure"}
        if set(structure_strata) != expected_keys:
            raise HoldoutEvaluationError(
                "structure_stratification_internal_error",
                "既知／新規構造の集計keyが不正です。",
            )
        stratified_identities = [case.digest for key in expected_keys for case in structure_strata[key]]
        if Counter(stratified_identities) != Counter(case.digest for case in holdout_cases):
            raise HoldoutEvaluationError(
                "structure_stratification_internal_error",
                "既知／新規構造の分母がholdout全体と一致しません。",
            )
        metrics["by_structure"] = {
            key: {
                "case_count": len(structure_strata[key]),
                **_success_metrics(
                    structure_strata[key],
                    denominator_basis=f"{key}_holdout_cases",
                ),
                "failure_reason_counts": _case_failure_reason_counts(structure_strata[key]),
            }
            for key in ("known_structure", "new_structure")
        }

    result = {
        "schema_version": SCHEMA_VERSION,
        "evaluation_mode": evaluation_mode,
        "target": {
            "family": TARGET_FAMILY,
            "requested_holdout_cases": requested_holdout_count,
            "minimum_joint_success_percentage": minimum_success_percentage,
            "required_joint_successes": required_successes,
        },
        "input": dict(input_summary),
        "split": dict(split),
        "success_contract": {
            "joint_condition": "family_confirmed_and_c2_config_confirmed",
            "family": {
                "target": TARGET_FAMILY,
                "allowed_evidence_sources": sorted(ALLOWED_FAMILY_SOURCES),
                "sample_identity_only_accepted": False,
                "external_family_hint_accepted": False,
                "unique_corroborated_candidate_required": True,
                "known_hash_family_evidence_accepted": False,
            },
            "c2_config": {
                "confirmed_config_required": True,
                "static_config_correlation_required": True,
                "control_role_required": True,
                "candidate_only_accepted": False,
            },
            "holdout_identity": {
                "identity_type": "sha256",
                "absent_from_reference_required": (evaluation_mode == "offline_sealed_reference_holdout"),
            },
            "structure_generalization": {
                "reference_similarity_allowed": (evaluation_mode == "offline_sealed_reference_holdout"),
                "known_and_new_structure_reported_separately": (structure_strata is not None),
                "success_threshold_changed_by_structure": False,
            },
        },
        "metrics": metrics,
        "failure_reason_counts": failure_reasons,
        "target_gate": {
            "status": "passed" if not gate_reasons else "failed",
            "observed_joint_successes": joint_count,
            "required_joint_successes": required_successes,
            "holdout_size_exact": (split["actual_holdout_cases"] == requested_holdout_count),
            "input_integrity_clean": input_integrity_clean,
            "reference_holdout_identity_disjoint": identity_disjoint,
            "reference_holdout_structurally_disjoint": structural_disjoint,
            "structural_similarity_allowed": (evaluation_mode == "offline_sealed_reference_holdout"),
            "pre_registration_verified": pre_registration is not None,
            "reason_codes": gate_reasons,
        },
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
            "subprocess_started": False,
            "case_identifiers_included": False,
            "raw_structure_values_included": False,
            "raw_config_included": False,
            "network_values_included": False,
            "source_names_included": False,
            "private_paths_included": False,
            "integrity_scope": ("report_semantic_seal_and_selected_artifact_digests"),
        },
    }
    if pre_registration is not None:
        result["pre_registration"] = dict(pre_registration)
    return result


def evaluate_runs(
    run_paths: Sequence[Path],
    *,
    holdout_count: int = DEFAULT_HOLDOUT_COUNT,
    minimum_success_percentage: float = DEFAULT_MINIMUM_SUCCESS_PERCENTAGE,
) -> dict[str, Any]:
    """封印済みroot caseをcluster分割し、holdoutの厳格な同時成功率を返す。"""

    if (
        not isinstance(minimum_success_percentage, (int, float))
        or isinstance(minimum_success_percentage, bool)
        or not math.isfinite(float(minimum_success_percentage))
        or not 0.0 <= float(minimum_success_percentage) <= 100.0
    ):
        raise HoldoutEvaluationError(
            "minimum_success_percentage_invalid",
            "最低成功率は0〜100の有限値で指定してください。",
        )
    minimum_success_percentage = float(minimum_success_percentage)
    cases, corpus_summary = _collect_case_evidence(run_paths)
    clusters = _cluster_cases(cases)
    holdout, partition = _partition_cases(cases, clusters, holdout_count)

    holdout_cases = [cases[index] for index in sorted(holdout)]
    family_count = sum(case.family_confirmed for case in holdout_cases)
    c2_count = sum(case.c2_config_confirmed for case in holdout_cases)
    joint_count = sum(case.family_confirmed and case.c2_config_confirmed for case in holdout_cases)
    failure_reasons = Counter(
        reason
        for case in holdout_cases
        for reason in (case.family_failure_reason, case.c2_failure_reason)
        if reason is not None
    )
    input_counts = corpus_summary["counts"]
    integrity_clean = (
        input_counts["batch_errors"] == 0
        and input_counts["invalid_unique_cases"] == 0
        and input_counts["conflicting_case_sha256"] == 0
    )
    required_successes = math.ceil(holdout_count * minimum_success_percentage / 100.0)
    gate_reasons = []
    if partition["actual_holdout_cases"] != holdout_count:
        gate_reasons.append("holdout_size_not_exact")
    if not integrity_clean:
        gate_reasons.append("input_integrity_not_clean")
    if joint_count < required_successes:
        gate_reasons.append("joint_success_target_not_met")
    gate_status = "passed" if not gate_reasons else "failed"

    non_singleton_components = sum(len(component) > 1 for component in clusters.components)
    maximum_component_size = max(map(len, clusters.components), default=0)
    return {
        "schema_version": SCHEMA_VERSION,
        "evaluation_mode": "offline_sealed_root_holdout",
        "target": {
            "family": TARGET_FAMILY,
            "requested_holdout_cases": holdout_count,
            "minimum_joint_success_percentage": minimum_success_percentage,
            "required_joint_successes": required_successes,
        },
        "input": {
            "run_count": corpus_summary["scope"]["run_count"],
            "input_units": input_counts["input_units"],
            "unique_valid_cases": input_counts["unique_valid_cases"],
            "batch_errors": input_counts["batch_errors"],
            "invalid_unique_cases": input_counts["invalid_unique_cases"],
            "conflicting_case_records": input_counts["conflicting_case_sha256"],
            "integrity_clean": integrity_clean,
        },
        "split": {
            "version": SPLIT_VERSION,
            "algorithm": "fixed_identity_ranked_structural_component_subset",
            "labels_or_outcomes_used": False,
            "family_or_config_values_used": False,
            "requested_holdout_cases": holdout_count,
            **partition,
            "holdout_size_deviation": partition["actual_holdout_cases"] - holdout_count,
            "structural_component_count": len(clusters.components),
            "non_singleton_component_count": non_singleton_components,
            "maximum_component_size": maximum_component_size,
            "exact_group_count": len(clusters.exact_groups),
            "exact_relationship_count": clusters.exact_relationship_count,
            "near_relationship_count": len(clusters.near_pairs),
            "exact_axis_available_case_counts": dict(clusters.exact_axis_case_counts),
            "logic_fingerprint_available_cases": clusters.logic_fingerprint_case_count,
            "validated_profile_available_cases": clusters.profile_axis_case_count,
            "near_contract": {
                "minimum_independent_axes": 2,
                "logic_jaccard_minimum": (NEAR_JACCARD_NUMERATOR / NEAR_JACCARD_DENOMINATOR),
                "minimum_shared_logic_fingerprints": (MINIMUM_NEAR_SHARED_FINGERPRINTS),
                "validated_loader_or_route_profile_required": True,
            },
        },
        "success_contract": {
            "joint_condition": "family_confirmed_and_c2_config_confirmed",
            "family": {
                "target": TARGET_FAMILY,
                "allowed_evidence_sources": sorted(ALLOWED_FAMILY_SOURCES),
                "sample_identity_only_accepted": False,
                "external_family_hint_accepted": False,
                "unique_corroborated_candidate_required": True,
            },
            "c2_config": {
                "confirmed_config_required": True,
                "static_config_correlation_required": True,
                "control_role_required": True,
                "candidate_only_accepted": False,
            },
        },
        "metrics": {
            "family_confirmed_without_disallowed_hints": _rate(
                family_count,
                len(holdout_cases),
            ),
            "c2_config_confirmed": _rate(c2_count, len(holdout_cases)),
            "joint_success": _rate(joint_count, len(holdout_cases)),
        },
        "failure_reason_counts": dict(sorted(failure_reasons.items())),
        "target_gate": {
            "status": gate_status,
            "observed_joint_successes": joint_count,
            "required_joint_successes": required_successes,
            "holdout_size_exact": partition["actual_holdout_cases"] == holdout_count,
            "input_integrity_clean": integrity_clean,
            "reason_codes": gate_reasons,
        },
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
            "subprocess_started": False,
            "case_identifiers_included": False,
            "raw_structure_values_included": False,
            "raw_config_included": False,
            "network_values_included": False,
            "source_names_included": False,
            "private_paths_included": False,
            "integrity_scope": "report_semantic_seal_and_selected_artifact_digests",
        },
    }


def _evaluate_reference_holdout_evidence(
    reference_cases: Sequence[_CaseEvidence],
    holdout_cases: Sequence[_CaseEvidence],
    reference_summary: Mapping[str, Any],
    holdout_summary: Mapping[str, Any],
    *,
    pre_registration: Mapping[str, Any],
    expected_holdout_count: int,
    minimum_success_percentage: float,
) -> dict[str, Any]:
    """referenceと完全holdoutの非公開構造を比較し、全holdoutを評価する。"""

    _validate_official_acceptance_target(
        expected_holdout_count,
        minimum_success_percentage,
    )
    if len(reference_cases) + len(holdout_cases) > MAX_EVALUATION_CASES:
        raise HoldoutEvaluationError(
            "evaluation_case_limit_exceeded",
            "referenceとholdoutのcase総数が評価上限を超えています。",
        )
    minimum_success_percentage = _validate_minimum_success_percentage(minimum_success_percentage)
    public_pre_registration = _validate_pre_registration(
        pre_registration,
        reference_cases,
        holdout_cases,
        expected_holdout_count=expected_holdout_count,
        minimum_success_percentage=minimum_success_percentage,
    )
    combined = [*reference_cases, *holdout_cases]
    clusters = _cluster_cases(combined)
    boundary = len(reference_cases)
    known_structure_cases, new_structure_cases, structure_summary = _reference_structure_strata(
        combined, clusters, boundary
    )

    def crosses_partition(members: Sequence[int]) -> bool:
        return any(index < boundary for index in members) and any(index >= boundary for index in members)

    cross_exact = sum(crosses_partition(members) for members in clusters.exact_groups)
    cross_near = sum((left < boundary) != (right < boundary) for left, right in clusters.near_pairs)
    cross_components = sum(crosses_partition(members) for members in clusters.components)
    identity_overlap = len(
        {case.digest for case in reference_cases}.intersection(case.digest for case in holdout_cases)
    )
    reference_components = sum(any(index < boundary for index in members) for members in clusters.components)
    holdout_components = sum(any(index >= boundary for index in members) for members in clusters.components)
    split = {
        "version": SPLIT_VERSION,
        "algorithm": "explicit_reference_and_full_holdout_structural_audit",
        "labels_or_outcomes_used": False,
        "family_or_config_values_used": False,
        "full_holdout_evaluated": True,
        "requested_holdout_cases": expected_holdout_count,
        "actual_holdout_cases": len(holdout_cases),
        "train_cases": len(reference_cases),
        "reference_cases": len(reference_cases),
        "holdout_component_count": holdout_components,
        "train_component_count": reference_components,
        "reference_component_count": reference_components,
        "cross_partition_identity_case_count": identity_overlap,
        "cross_partition_exact_group_count": cross_exact,
        "cross_partition_near_relationship_count": cross_near,
        "cross_partition_component_count": cross_components,
        "holdout_size_deviation": len(holdout_cases) - expected_holdout_count,
        **structure_summary,
        **_cluster_summary(clusters),
    }
    public_reference = _public_input_counts(reference_summary)
    public_holdout = _public_input_counts(holdout_summary)
    integrity_clean = public_reference["integrity_clean"] and public_holdout["integrity_clean"]
    gate_reasons = []
    if identity_overlap:
        gate_reasons.append("reference_holdout_identity_overlap")
    return _assemble_evaluation(
        evaluation_mode="offline_sealed_reference_holdout",
        holdout_cases=holdout_cases,
        requested_holdout_count=expected_holdout_count,
        minimum_success_percentage=minimum_success_percentage,
        input_summary={
            "reference": public_reference,
            "holdout": public_holdout,
            "integrity_clean": integrity_clean,
        },
        input_integrity_clean=integrity_clean,
        split=split,
        pre_registration=public_pre_registration,
        structure_strata={
            "known_structure": known_structure_cases,
            "new_structure": new_structure_cases,
        },
        additional_gate_reasons=gate_reasons,
    )


def evaluate_reference_holdout(
    reference_run_paths: Sequence[Path],
    holdout_run_paths: Sequence[Path],
    *,
    pre_registration: Mapping[str, Any] | None = None,
    expected_holdout_count: int = DEFAULT_HOLDOUT_COUNT,
    minimum_success_percentage: float = DEFAULT_MINIMUM_SUCCESS_PERCENTAGE,
) -> dict[str, Any]:
    """既知referenceと別収集の未知holdout全件を比較・評価する。"""

    if not reference_run_paths:
        raise HoldoutEvaluationError(
            "reference_run_missing",
            "reference modeには既知・開発群のrunが必要です。",
        )
    if not holdout_run_paths:
        raise HoldoutEvaluationError(
            "holdout_run_missing",
            "reference modeには未知holdoutのrunが必要です。",
        )
    if pre_registration is None:
        raise HoldoutEvaluationError(
            "pre_registration_required",
            "公式reference holdout評価にはidentity事前登録が必要です。",
        )
    reference_cases, reference_summary = _collect_case_evidence(reference_run_paths)
    holdout_cases, holdout_summary = _collect_case_evidence(holdout_run_paths)
    return _evaluate_reference_holdout_evidence(
        reference_cases,
        holdout_cases,
        reference_summary,
        holdout_summary,
        pre_registration=pre_registration,
        expected_holdout_count=expected_holdout_count,
        minimum_success_percentage=minimum_success_percentage,
    )


def _rate_text(rate: Mapping[str, Any]) -> str:
    if rate.get("denominator") in {None, 0}:
        return "計算対象なし"
    return f"{rate['numerator']}/{rate['denominator']} ({rate['percentage']:.2f}%)"


def render_markdown(summary: Mapping[str, Any]) -> str:
    """JSONと同じ母数・判定を持つ日本語Markdownを生成する。"""

    target = summary["target"]
    gate = summary["target_gate"]
    split = summary["split"]
    metrics = summary["metrics"]
    reference_mode = summary.get("evaluation_mode") == "offline_sealed_reference_holdout"
    left_partition = "reference" if reference_mode else "train"
    partition_heading = "reference／holdout境界監査" if reference_mode else "train／holdout分割"
    structure_metric_lines: list[str] = []
    structure_boundary_lines: list[str] = []
    if reference_mode:
        by_structure = metrics["by_structure"]
        known = by_structure["known_structure"]
        new = by_structure["new_structure"]
        structure_metric_lines = [
            "",
            "### 構造既知性別の成功",
            "",
            "| 構造区分 | case数 | family確定 | C2設定確定 | 同時成功 |",
            "|---|---:|---:|---:|---:|",
            (
                f"| 既知構造 | {known['case_count']} | "
                f"{_rate_text(known['family_confirmed_without_disallowed_hints'])} | "
                f"{_rate_text(known['c2_config_confirmed'])} | "
                f"{_rate_text(known['joint_success'])} |"
            ),
            (
                f"| 新規構造 | {new['case_count']} | "
                f"{_rate_text(new['family_confirmed_without_disallowed_hints'])} | "
                f"{_rate_text(new['c2_config_confirmed'])} | "
                f"{_rate_text(new['joint_success'])} |"
            ),
        ]
        structure_boundary_lines = [
            (f"- reference構造成分へ属する既知構造holdout: {split['known_structure_holdout_cases']}件"),
            (f"- reference構造成分へ属さない新規構造holdout: {split['new_structure_holdout_cases']}件"),
            ("- 構造類似は失格条件ではなく、既知構造への一般化成果として分離集計します。"),
        ]
    verdict = "達成" if gate["status"] == "passed" else "未達"
    lines = [
        "# ValleyRATオフラインholdout評価",
        "",
        "## 結論",
        "",
        (
            f"目標判定は**{verdict}**です。holdout {split['actual_holdout_cases']}件中、"
            f"family確定とC2設定確定の両方を満たしたのは"
            f"{metrics['joint_success']['numerator']}件でした。"
        ),
        (
            f"要求はholdout {target['requested_holdout_cases']}件で"
            f"{target['required_joint_successes']}件以上"
            f"（{target['minimum_joint_success_percentage']:.2f}%以上）です。"
        ),
        "",
        "## 評価指標",
        "",
        "| 指標 | 結果 |",
        "|---|---:|",
        (
            "| family確定（検体identity・外部family hintを根拠にしない） | "
            f"{_rate_text(metrics['family_confirmed_without_disallowed_hints'])} |"
        ),
        f"| 静的C2設定確定 | {_rate_text(metrics['c2_config_confirmed'])} |",
        f"| 同時成功 | {_rate_text(metrics['joint_success'])} |",
        *structure_metric_lines,
        "",
        f"## {partition_heading}",
        "",
        f"- {left_partition}: {split['train_cases']}件",
        f"- holdout: {split['actual_holdout_cases']}件",
        f"- 構造連結成分: {split['structural_component_count']}件",
        f"- exact group: {split['exact_group_count']}件",
        f"- near関係: {split['near_relationship_count']}件",
        (
            f"- {left_partition}／holdoutで重複するcase identity: "
            f"{split.get('cross_partition_identity_case_count', 0)}件"
        ),
        (f"- {left_partition}／holdoutをまたぐexact group: {split['cross_partition_exact_group_count']}件"),
        (f"- {left_partition}／holdoutをまたぐnear関係: {split['cross_partition_near_relationship_count']}件"),
        (f"- {left_partition}／holdoutをまたぐ構造連結成分: {split['cross_partition_component_count']}件"),
        *structure_boundary_lines,
        "- 分割順序にfamily、設定値、解析成否は使用していません。",
        (
            "- near判定は関数logic fingerprintの80%以上の重なりに加え、"
            "検証済みloader／route profileの共有を必須とします。"
        ),
        "",
        *(
            [
                "## 事前登録",
                "",
                "- holdout identityはSHA-256集合commitmentへ事前に固定済みです。",
                "- 評価時のreference／holdout identity集合と事前登録を再照合しています。",
                "- 評価器単独では事前登録の作成時刻を証明しないため、外部の変更不能な監査記録が必要です。",
                "- 個別identity値と集合commitment値は公開評価結果へ含めません。",
                "",
            ]
            if reference_mode
            else []
        ),
        "## 目標ゲート",
        "",
        f"- status: {gate['status']}",
        ("- 固定reason code: " + ("、".join(gate["reason_codes"]) if gate["reason_codes"] else "なし")),
        "",
        "## 成功条件",
        "",
        "- familyは構造detectorと対応handlerの一意な相関でValleyRATまで確定していること。",
        "- 検体identityだけの一致、外部family hint、候補だけの判定は成功に含めないこと。",
        "- C2設定は確認済み静的configとcontrol roleの通信設定が相関していること。",
        "- family確定とC2設定確定の片方だけでは成功に含めないこと。",
        *(
            [
                "- holdoutのSHA-256 identityはreferenceに存在しないこと。",
                "- referenceと構造が類似するholdoutも分母へ含め、既知構造として別集計すること。",
            ]
            if reference_mode
            else []
        ),
        "",
        "## 失敗理由",
        "",
        "| 固定reason code | holdout case数 |",
        "|---|---:|",
    ]
    for reason, count in summary["failure_reason_counts"].items():
        lines.append(f"| `{reason}` | {count} |")
    if not summary["failure_reason_counts"]:
        lines.append("| なし | 0 |")
    lines.extend(
        [
            "",
            "## 安全境界",
            "",
            "- 読み込むのは封印済みJSON成果物だけです。",
            "- 検体の読込み・実行、network接続、subprocess起動は行いません。",
            "- case識別子、通信先の値、raw config、source name、private pathは出力しません。",
            "",
        ]
    )
    return "\n".join(lines)


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ変換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    """オフラインholdout評価CLIの引数parserを返す。"""

    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="append",
        type=Path,
        help=(
            "評価対象の封印済みone-shot出力root。reference指定時は"
            "未知holdoutとして全件を評価します。繰返し指定できます。"
        ),
    )
    parser.add_argument(
        "--reference-run",
        action="append",
        type=Path,
        help=(
            "既知・開発群の封印済みone-shot出力root。指定すると"
            "reference／完全holdout境界監査を行います。繰返し指定できます。"
        ),
    )
    parser.add_argument(
        "--holdout-count",
        type=int,
        default=DEFAULT_HOLDOUT_COUNT,
        help=("single-setで要求するholdout件数。公式reference modeでは100に固定されます。"),
    )
    parser.add_argument(
        "--minimum-success-percentage",
        type=float,
        default=DEFAULT_MINIMUM_SUCCESS_PERCENTAGE,
        help=("family・C2設定の同時成功に要求する最低割合。既定値は50です。公式reference modeでは50に固定されます。"),
    )
    registration = parser.add_mutually_exclusive_group()
    registration.add_argument(
        "--pre-registration",
        type=Path,
        help=("解析結果を確認する前に作成したidentity事前登録JSON。公式reference modeでは必須です。"),
    )
    parser.add_argument(
        "--holdout-identity-manifest",
        type=Path,
        help=("事前登録作成時に使うprivateな解析前SHA-256一覧JSON。評価modeでは指定できません。"),
    )
    registration.add_argument(
        "--write-pre-registration",
        type=Path,
        help=(
            "解析前identity manifestとreference summaryだけを読み、公式100件holdoutの事前登録JSONを作成して終了します。"
        ),
    )
    parser.add_argument("--output-json", type=Path, help="CI向けJSONの出力先。")
    parser.add_argument("--output-markdown", type=Path, help="日本語Markdownの出力先。")
    parser.add_argument(
        "--fail-below-target",
        action="store_true",
        help="目標未達時に終了code 1を返します。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLIを実行し、明示出力またはstdoutへ決定的JSONを書き出す。"""

    args = build_parser().parse_args(argv)
    try:
        run_paths = list(args.run or [])
        input_roots = [*run_paths, *(args.reference_run or [])]
        corpus._validate_output_paths(
            (
                args.output_json,
                args.output_markdown,
                args.write_pre_registration,
            ),
            input_roots,
        )
        if args.pre_registration is not None:
            registration_input = args.pre_registration.resolve()
            evaluation_outputs = {
                path.resolve() for path in (args.output_json, args.output_markdown) if path is not None
            }
            if registration_input in evaluation_outputs:
                raise HoldoutEvaluationError(
                    "pre_registration_output_collision",
                    "事前登録を評価結果の出力先として上書きできません。",
                )
        if args.write_pre_registration:
            if not args.reference_run:
                raise HoldoutEvaluationError(
                    "reference_run_missing",
                    "事前登録の作成には既知・開発群のrunが必要です。",
                )
            if args.holdout_identity_manifest is None:
                raise HoldoutEvaluationError(
                    "holdout_identity_manifest_required",
                    "事前登録の作成には解析前holdout identity manifestが必要です。",
                )
            if run_paths:
                raise HoldoutEvaluationError(
                    "pre_registration_run_input_disallowed",
                    "事前登録作成時は解析後holdout runを指定できません。",
                )
            if args.output_json or args.output_markdown or args.fail_below_target:
                raise HoldoutEvaluationError(
                    "pre_registration_mode_conflict",
                    "事前登録作成と評価結果出力optionは同時指定できません。",
                )
            if args.write_pre_registration.resolve() == args.holdout_identity_manifest.resolve():
                raise HoldoutEvaluationError(
                    "identity_manifest_output_collision",
                    "解析前identity manifestを事前登録出力で上書きできません。",
                )
            _validate_official_acceptance_target(
                args.holdout_count,
                args.minimum_success_percentage,
            )
            registration_value = build_pre_registration(
                _collect_registered_identities(args.reference_run),
                _read_identity_manifest(args.holdout_identity_manifest),
                expected_holdout_count=args.holdout_count,
                minimum_success_percentage=args.minimum_success_percentage,
            )
            corpus._atomic_write_text(
                args.write_pre_registration,
                json.dumps(
                    registration_value,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n",
            )
            print("holdout identity事前登録JSONを出力しました。")
            return 0
        if args.holdout_identity_manifest is not None:
            raise HoldoutEvaluationError(
                "identity_manifest_evaluation_disallowed",
                "解析前identity manifestは事前登録作成時だけ指定できます。",
            )
        if not run_paths:
            raise HoldoutEvaluationError(
                "holdout_run_missing",
                "holdout評価には解析済みrunが必要です。",
            )
        if args.reference_run:
            if args.pre_registration is None:
                raise HoldoutEvaluationError(
                    "pre_registration_required",
                    "公式reference holdout評価にはidentity事前登録が必要です。",
                )
            summary = evaluate_reference_holdout(
                args.reference_run,
                run_paths,
                pre_registration=_read_pre_registration(args.pre_registration),
                expected_holdout_count=args.holdout_count,
                minimum_success_percentage=args.minimum_success_percentage,
            )
        else:
            if args.pre_registration is not None:
                raise HoldoutEvaluationError(
                    "pre_registration_requires_reference",
                    "事前登録はreference holdout評価でだけ指定できます。",
                )
            summary = evaluate_runs(
                run_paths,
                holdout_count=args.holdout_count,
                minimum_success_percentage=args.minimum_success_percentage,
            )
        rendered_json = (
            json.dumps(
                summary,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )
        if args.output_json:
            corpus._atomic_write_text(args.output_json, rendered_json)
        else:
            print(rendered_json, end="")
        if args.output_markdown:
            corpus._atomic_write_text(
                args.output_markdown,
                render_markdown(summary),
            )
    except HoldoutEvaluationError as exc:
        error_code = exc.code
        message = "封印済み成果物のholdout評価に失敗しました。"
    except corpus.CorpusSummaryError as exc:
        error_code = f"sealed_corpus_{exc.code}"
        message = "封印済み成果物または出力境界の検証に失敗しました。"
    except (OSError, ValueError):
        error_code = "holdout_io_failed"
        message = "holdout評価の入出力処理に失敗しました。"
    else:
        if args.output_json:
            print("holdout評価JSONを出力しました。")
        if args.fail_below_target and summary["target_gate"]["status"] != "passed":
            return 1
        return 0

    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "error",
                "error_code": error_code,
                "message_ja": message,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
