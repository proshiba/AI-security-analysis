#!/usr/bin/env python3
"""固定200件の分割production jobを全体再検証し、1 caseずつdatastoreへ引き渡す。"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

COMMON = Path(__file__).resolve().parent
REPOSITORY = COMMON.parents[1]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner  # noqa: E402
import archive_analysis_datastore  # noqa: E402
import malwarebazaar_selection_contract as selection_contract  # noqa: E402
import publish_malwarebazaar_partitioned_collection as partitioned  # noqa: E402
import stage_case_analysis_datastore as case_staging  # noqa: E402

SCHEMA_VERSION = "analysis-datastore-partitioned-coordinator/v1"
RECEIPT_BINDING_SCHEMA_VERSION = 1
EXTERNALIZED_RECEIPT_BINDING_SCHEMA_VERSION = (
    "analysis-datastore-externalized-receipt-binding/v1"
)
MAX_RECEIPT_BYTES = 1024 * 1024
OBJECT_URI_RE = re.compile(r"s3://([^/]+)/(.+)\Z")
OUTPUT_HANDLING_WARNING_JA = (
    "case処理のJSONにはrepository外のprivate絶対pathと後続CLI引数が含まれます。"
    "標準出力を解析repository内のfileへredirect、tee、保存しないでください。"
)


class PartitionedDatastoreError(RuntimeError):
    """分割job全体を安全なcase archiveへ昇格できない場合の例外。"""


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        """日本語化したhelpを返す。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


@dataclass(frozen=True)
class CaseJobBinding:
    """取得時hash、実解析root、production jobの一意な結合。"""

    requested_sha256: str
    case_sha256: str
    job_id: str
    job_root: Path = field(repr=False)
    case_state: str = "complete"
    source_replay_verified: bool = True


@dataclass(frozen=True)
class PartitionedDatastorePlan:
    """全source・全jobを再検証した後だけ生成されるcase保管計画。"""

    repository: Path
    collection_id: str
    source_root: Path
    temporary_root: Path
    source_manifest_sha256: str
    selection_commitment_sha256: str
    bindings: Mapping[str, CaseJobBinding]
    job_root_case_sha256s: Mapping[str, tuple[str, ...]]
    job_analysis_manifests: Mapping[str, Mapping[str, Any]] = field(repr=False)
    case_follow_on_lineage_documents: Mapping[
        str,
        Mapping[str, Any] | None,
    ] = field(default_factory=dict, repr=False)
    case_state_counts: Mapping[str, int] = field(
        default_factory=lambda: {"complete": 0, "partial": 0}
    )
    publication_stage: str = "complete"
    source_replay_verified: bool = True
    source_replay_unverified_job_count: int = 0
    allow_partial_staging: bool = False
    externalize_shared_derived_cases: bool = False
    shared_derived_documents: Mapping[str, Mapping[str, Any]] = field(
        default_factory=dict,
        repr=False,
    )
    shared_derived_job_ids: Mapping[str, str] = field(default_factory=dict)
    root_shared_derived_sha256s: Mapping[str, tuple[str, ...]] = field(
        default_factory=dict,
        repr=False,
    )


def _sha256(value: Any, *, label: str) -> str:
    """小文字64桁SHA-256だけを受理する。"""

    if not isinstance(value, str) or analysis_job_runner.SHA256_RE.fullmatch(value) is None:
        raise PartitionedDatastoreError(f"{label}が小文字64桁SHA-256ではありません")
    return value


def _regular_json_with_digest(path: Path, *, max_bytes: int) -> tuple[dict[str, Any], str]:
    """通常fileを単一handleで読み、strict JSON objectとdigestを返す。"""

    try:
        payload = analysis_job_runner._read_regular_file_once(path, max_bytes=max_bytes)
        document = analysis_job_runner._decode_json_object_strict(payload)
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise PartitionedDatastoreError(f"JSONを安全に固定できません: {path.name}") from exc
    return document, hashlib.sha256(payload).hexdigest()


def _require_staging_job(
    validation: Mapping[str, Any],
    *,
    request: analysis_job_runner.JobRequest,
    allow_partial_staging: bool,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """完成jobまたは明示許可された厳格な途中jobだけを受理する。"""

    result = validation.get("result")
    summary = validation.get("summary")
    counts = validation.get("counts")
    if not isinstance(result, Mapping) or not isinstance(summary, Mapping) or not isinstance(counts, Mapping):
        raise PartitionedDatastoreError(f"completed job再検証結果が不正です: {request.job_id}")
    cases = summary.get("cases")
    derived_cases = summary.get("derived_cases")
    derived_counts = summary.get("derived_counts")
    follow_on = summary.get("follow_on_analysis")
    if (
        not isinstance(cases, list)
        or len(cases) != len(request.inputs)
        or not isinstance(derived_cases, list)
        or not isinstance(derived_counts, Mapping)
        or not isinstance(follow_on, Mapping)
        or any(
            counts.get(key) != 0
            for key in ("duplicates", "errors", "triaged_unknown", "failed")
        )
        or counts.get("analyzed") != len(request.inputs)
        or type(counts.get("complete")) is not int
        or type(counts.get("partial")) is not int
        or counts.get("complete", -1) < 0
        or counts.get("partial", -1) < 0
        or counts.get("complete", 0) + counts.get("partial", 0)
        != len(request.inputs)
        or any(
            not isinstance(item, Mapping)
            or item.get("case_state") not in {"complete", "partial"}
            for item in cases
        )
        or any(
            not isinstance(item, Mapping)
            or item.get("case_state") not in {"complete", "partial"}
            for item in derived_cases
        )
        or any(
            type(derived_counts.get(key)) is not int
            or derived_counts.get(key, -1) < 0
            for key in (
                "analyzed",
                "complete",
                "triaged_unknown",
                "partial",
                "failed",
            )
        )
        or any(derived_counts.get(key) != 0 for key in ("triaged_unknown", "failed"))
        or derived_counts.get("analyzed") != len(derived_cases)
        or derived_counts.get("complete", 0) + derived_counts.get("partial", 0)
        != derived_counts.get("analyzed")
    ):
        raise PartitionedDatastoreError(
            f"許可外状態／failed／重複または集計不一致のjobは全体preflightで拒否します: {request.job_id}"
        )
    observed_states = Counter(str(item["case_state"]) for item in cases)
    if (
        observed_states.get("complete", 0) != counts.get("complete")
        or observed_states.get("partial", 0) != counts.get("partial")
    ):
        raise PartitionedDatastoreError(
            f"job summaryとcountのcase状態が一致しません: {request.job_id}"
        )
    observed_derived_states = Counter(
        str(item["case_state"]) for item in derived_cases
    )
    if (
        observed_derived_states.get("complete", 0)
        != derived_counts.get("complete")
        or observed_derived_states.get("partial", 0)
        != derived_counts.get("partial")
    ):
        raise PartitionedDatastoreError(
            f"job summaryとcountのderived case状態が一致しません: {request.job_id}"
        )
    partial = (
        counts.get("partial", 0) > 0
        or derived_counts.get("partial", 0) > 0
    )
    synthetic_partial = validation.get("staging_state") == "partial"
    if partial:
        if not allow_partial_staging:
            raise PartitionedDatastoreError(
                f"途中jobのstagingには--allow-partial-stagingが必要です: {request.job_id}"
            )
        if follow_on.get("status") not in {
            "complete",
            "partial",
            "no_retained_payloads",
        }:
            raise PartitionedDatastoreError(
                f"途中jobのfollow-on状態が不正です: {request.job_id}"
            )
        if synthetic_partial:
            if (
                result.get("accepted") is not False
                or result.get("analysis_state") != "failed"
            ):
                raise PartitionedDatastoreError(
                    f"failed partial jobのrunner状態が不正です: {request.job_id}"
                )
        elif (
            result.get("accepted") is not True
            or result.get("analysis_state") != "partial"
        ):
            raise PartitionedDatastoreError(
                f"completed partial jobのrunner状態が不正です: {request.job_id}"
            )
    elif (
        synthetic_partial
        or result.get("accepted") is not True
        or result.get("analysis_state") != "complete"
        or follow_on.get("status") not in {"complete", "no_retained_payloads"}
    ):
        raise PartitionedDatastoreError(
            f"completed jobのrunner状態が不正です（partial不一致）: {request.job_id}"
        )
    return result, summary


def _require_complete_job(
    validation: Mapping[str, Any],
    *,
    request: analysis_job_runner.JobRequest,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """互換用に、途中stagingを許可しない完成job契約を検証する。"""

    return _require_staging_job(
        validation,
        request=request,
        allow_partial_staging=False,
    )


def _load_contract_input_manifest(
    job_root: Path,
    *,
    artifacts: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    """runnerが再検証したanalysis contract bundleから入力manifestを再取得する。"""

    relative = artifacts.get("analysis_contract_bundle")
    expected_sha256 = artifacts.get("analysis_contract_bundle_sha256")
    if (
        relative != "contract-inputs/analysis-contract-bundle.json"
        or not isinstance(expected_sha256, str)
        or analysis_job_runner.SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise PartitionedDatastoreError("analysis contract bundle参照が不正です")
    document, observed_sha256 = _regular_json_with_digest(
        job_root / "contract-inputs" / "analysis-contract-bundle.json",
        max_bytes=analysis_job_runner.MAX_ANALYSIS_CONTRACT_BUNDLE_BYTES,
    )
    if not hmac.compare_digest(observed_sha256, expected_sha256):
        raise PartitionedDatastoreError("analysis contract bundleのSHA-256が一致しません")
    raw_manifest = document.get("input_manifest")
    if not isinstance(raw_manifest, list):
        raise PartitionedDatastoreError("analysis contract bundleにinput_manifestがありません")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(raw_manifest):
        if not isinstance(item, dict) or set(item) != {
            "source_name",
            "unit_source_name",
            "sha256",
            "read_succeeded",
        }:
            raise PartitionedDatastoreError(f"input_manifest[{index}]のschemaが不正です")
        normalized.append(dict(item))
    return tuple(normalized)


def _source_items(source_manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """完全検証済みsource manifestを要求hash索引へ変換する。"""

    try:
        selection_contract.validate_item_metadata_binding(
            source_manifest,
            expected_hashes=tuple(source_manifest.get("selected_hashes") or ()),
        )
    except selection_contract.SelectionMetadataContractError as exc:
        raise PartitionedDatastoreError(
            f"source manifestのcommit済みmetadata結合が不正です: {exc}"
        ) from exc
    raw_items = source_manifest.get("items")
    if not isinstance(raw_items, list):
        raise PartitionedDatastoreError("source manifestにitemsがありません")
    items: dict[str, Mapping[str, Any]] = {}
    for item in raw_items:
        digest = item.get("sha256") if isinstance(item, Mapping) else None
        digest = _sha256(digest, label="source item SHA-256")
        if digest in items:
            raise PartitionedDatastoreError("source itemが重複しています")
        items[digest] = item
    return items


def _job_case_bindings(
    *,
    request: analysis_job_runner.JobRequest,
    job_root: Path,
    validation: Mapping[str, Any],
    source_items: Mapping[str, Mapping[str, Any]],
    allow_partial_staging: bool = False,
) -> tuple[CaseJobBinding, ...]:
    """再検証済みsnapshot、契約、reportからrequest入力をroot caseへ結合する。"""

    result, summary = _require_staging_job(
        validation,
        request=request,
        allow_partial_staging=allow_partial_staging,
    )
    artifacts = validation.get("staging_artifacts") or result.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise PartitionedDatastoreError(f"completed jobにartifact参照がありません: {request.job_id}")
    try:
        bundle = analysis_job_runner._rehydrate_input_snapshot_bundle(job_root, request, artifacts)
        analysis_job_runner.verify_input_snapshot_bundle(bundle, job_dir=job_root)
    except analysis_job_runner.JobContractError as exc:
        raise PartitionedDatastoreError(f"入力snapshotを再構成できません: {request.job_id}") from exc
    contract_inputs = _load_contract_input_manifest(job_root, artifacts=artifacts)
    if len(contract_inputs) != len(bundle.inputs) or len(bundle.inputs) != len(request.inputs):
        raise PartitionedDatastoreError(f"request、snapshot、input manifest件数が一致しません: {request.job_id}")

    requested_by_source_path: dict[str, str] = {}
    for request_input in request.inputs:
        path = PurePosixPath(request_input)
        requested = _sha256(path.name, label="partition request hash")
        expected_source_path = (path / f"{requested}.zip").as_posix()
        if expected_source_path in requested_by_source_path:
            raise PartitionedDatastoreError("partition requestのsource pathが重複しています")
        requested_by_source_path[expected_source_path] = requested
    if {item.source_relative_path for item in bundle.inputs} != set(requested_by_source_path):
        raise PartitionedDatastoreError(f"requestとjob snapshotのsource path集合が一致しません: {request.job_id}")

    case_items = summary.get("cases")
    if not isinstance(case_items, list):
        raise PartitionedDatastoreError("再検証済みsummaryにcasesがありません")
    cases_by_sha256 = {
        item.get("sha256"): item
        for item in case_items
        if isinstance(item, Mapping) and isinstance(item.get("sha256"), str)
    }
    bindings_by_requested: dict[str, CaseJobBinding] = {}
    observed_actual: set[str] = set()
    for snapshot, contract_input in zip(bundle.inputs, contract_inputs, strict=True):
        requested = requested_by_source_path[snapshot.source_relative_path]
        source_item = source_items.get(requested)
        actual = _sha256(contract_input.get("sha256"), label="analyzed root SHA-256")
        root_summary = cases_by_sha256.get(actual)
        if (
            source_item is None
            or source_item.get("zip_sha256") != snapshot.sha256
            or source_item.get("zip_size") != snapshot.size
            or contract_input.get("read_succeeded") is not True
            or contract_input.get("source_name") != snapshot.path.name
            or not isinstance(contract_input.get("unit_source_name"), str)
            or actual in observed_actual
            or not isinstance(root_summary, Mapping)
            or root_summary.get("source_name") != contract_input.get("unit_source_name")
        ):
            raise PartitionedDatastoreError(f"source、snapshot、root caseを一意に結合できません: {request.job_id}")
        report, _report_sha256 = case_staging._read_json(
            job_root / "analysis" / "cases" / actual / "report.json",
            label="partitioned root report",
        )
        case_state = root_summary.get("case_state")
        if allow_partial_staging:
            try:
                _validated_report, report_stage = (
                    partitioned.publisher.load_validated_source_report(
                        job_root / "analysis" / "cases" / actual,
                        actual,
                        allow_function_staging=True,
                        expected_contract=partitioned._analysis_contract(validation),
                    )
                )
            except (OSError, TypeError, ValueError) as exc:
                raise PartitionedDatastoreError(
                    f"root reportの途中staging契約を検証できません: {request.job_id}"
                ) from exc
            expected_stage = (
                "analysis_followup_pending"
                if case_state == "partial"
                else "complete"
            )
            if report_stage != expected_stage:
                raise PartitionedDatastoreError(
                    f"root summaryとreportの途中状態が一致しません: {request.job_id}"
                )
        sample = report.get("sample")
        if (
            not isinstance(sample, Mapping)
            or sample.get("sha256") != actual
            or sample.get("input_kind") != "authenticated_single_member_zip"
            or sample.get("outer_sha256") != snapshot.sha256
            or sample.get("outer_size") != snapshot.size
            or not isinstance(sample.get("member_name"), str)
            or not sample["member_name"]
            or "/" in sample["member_name"].replace("\\", "/")
        ):
            raise PartitionedDatastoreError(f"root reportがsource archiveへ束縛されていません: {request.job_id}")
        observed_actual.add(actual)
        bindings_by_requested[requested] = CaseJobBinding(
            requested_sha256=requested,
            case_sha256=actual,
            job_id=request.job_id,
            job_root=job_root,
            case_state=str(case_state),
            source_replay_verified=(
                validation.get("source_replay_verified", True) is True
            ),
        )
    ordered_requested = [PurePosixPath(value).name for value in request.inputs]
    if set(bindings_by_requested) != set(ordered_requested):
        raise PartitionedDatastoreError(f"job case bindingに欠落または余剰があります: {request.job_id}")
    return tuple(bindings_by_requested[value] for value in ordered_requested)


def _analysis_output_matches(
    job_root: Path,
    expected: Mapping[str, Any],
) -> bool:
    """analysis treeの集計とexact content manifest SHA-256を同時に照合する。"""

    expected_tree = expected.get("tree")
    expected_sha256 = expected.get("sha256")
    if (
        not isinstance(expected_tree, Mapping)
        or not isinstance(expected_sha256, str)
        or analysis_job_runner.SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise PartitionedDatastoreError("保存済みanalysis tree commitmentが不正です")
    try:
        observed = analysis_job_runner.analysis_output_content_manifest(job_root / "analysis")
        observed_sha256 = analysis_job_runner.analysis_output_content_sha256(observed)
    except analysis_job_runner.JobContractError as exc:
        raise PartitionedDatastoreError("job analysis treeを再照合できません") from exc
    return observed.get("tree") == expected_tree and hmac.compare_digest(
        observed_sha256,
        expected_sha256,
    )


def _validated_global_binding_map(
    bindings: Sequence[CaseJobBinding],
    *,
    selection_hashes: Sequence[str],
) -> dict[str, CaseJobBinding]:
    """全jobの結合が固定選定を順序付きで一意に被覆することを確認する。"""

    requested_order = tuple(item.requested_sha256 for item in bindings)
    expected_order = tuple(selection_hashes)
    actual_values = [item.case_sha256 for item in bindings]
    if requested_order != expected_order:
        raise PartitionedDatastoreError("4 jobの要求case順序が固定200件選定と一致しません")
    if len(set(actual_values)) != len(actual_values):
        raise PartitionedDatastoreError("異なるsource caseが同じ解析rootへ結合されています")
    binding_map = {item.requested_sha256: item for item in bindings}
    if len(binding_map) != len(expected_order):
        raise PartitionedDatastoreError("case binding集合が固定選定を一意に被覆しません")
    return binding_map


def _bind_materialized_derived_jobs(
    observed: Mapping[str, str],
    *,
    job_id: str,
    child_sha256s: Sequence[str],
) -> dict[str, str]:
    """derived SHA-256がproduction job境界をまたがないことを固定する。"""

    result = dict(observed)
    for child_value in sorted(child_sha256s):
        child = _sha256(child_value, label="materialized derived SHA-256")
        previous_job = result.get(child)
        if previous_job is not None and previous_job != job_id:
            raise PartitionedDatastoreError(
                "同一materialized derived SHA-256が複数production jobに存在します"
            )
        result[child] = job_id
    return result


def _reject_materialized_derived_root_overlap(
    materialized_derived_job_ids: Mapping[str, str],
    bindings: Mapping[str, CaseJobBinding],
) -> None:
    """derived SHA-256と全requested／actual rootの交差を拒否する。"""

    root_sha256s = {
        digest
        for binding in bindings.values()
        for digest in (binding.requested_sha256, binding.case_sha256)
    }
    overlap = set(materialized_derived_job_ids) & root_sha256s
    if overlap:
        raise PartitionedDatastoreError(
            "materialized derived SHA-256が別のrequested／actual rootと重複しています"
        )


def prepare_partitioned_datastore_plan(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    selection_manifest_path: Path,
    batch_manifest_path: Path,
    job_roots: Sequence[Path],
    temporary_root: Path,
    expected_timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
    allow_partial_staging: bool = False,
    externalize_shared_derived_cases: bool = False,
) -> PartitionedDatastorePlan:
    """全source・全partition・全許可済みjobを先に検証し、case結合を固定する。"""

    if type(externalize_shared_derived_cases) is not bool:
        raise PartitionedDatastoreError("共有derived externalization許可値はbooleanである必要があります")
    if case_staging.COLLECTION_RE.fullmatch(collection_id) is None:
        raise PartitionedDatastoreError("collection IDが不正です")
    repository = case_staging._validate_existing_directory(repository, label="repository")
    source_root = case_staging._validate_existing_directory(source_root, label="source root")
    temporary_root = case_staging._validate_existing_directory(temporary_root, label="temporary root")
    if case_staging._is_within(source_root, repository):
        raise PartitionedDatastoreError("source rootはrepository外へ分離してください")
    expected_selection = case_staging._absolute(source_root / "manifest.json")
    observed_selection = case_staging._absolute(selection_manifest_path)
    if os.path.normcase(os.fspath(expected_selection)) != os.path.normcase(os.fspath(observed_selection)):
        raise PartitionedDatastoreError("selection manifestはsource-root/manifest.jsonを指定してください")
    if any(
        case_staging._is_within(temporary_root, value) or case_staging._is_within(value, temporary_root)
        for value in (repository, source_root)
    ):
        raise PartitionedDatastoreError("temporary rootはrepositoryとsource rootから分離してください")
    try:
        publication_plan = partitioned.load_publication_plan(
            observed_selection,
            batch_manifest_path,
        )
        ordered_roots = partitioned._ordered_job_roots(publication_plan, job_roots)
    except partitioned.PublicationContractError as exc:
        raise PartitionedDatastoreError(str(exc)) from exc
    (
        source_manifest,
        source_manifest_sha256,
        source_cases,
        _source_sidecar_commitments,
    ) = case_staging._validate_source_manifest(source_root)
    if source_manifest != publication_plan.selection_manifest:
        raise PartitionedDatastoreError("staging source manifestとpartition selection manifestが一致しません")
    if tuple(source_manifest["selected_hashes"]) != publication_plan.selection_hashes:
        raise PartitionedDatastoreError("source選定順序が再構築済みpartitionと一致しません")
    if set(source_cases) != set(publication_plan.selection_hashes):
        raise PartitionedDatastoreError("source directory集合が固定選定と一致しません")
    source_items = _source_items(source_manifest)

    all_bindings: list[CaseJobBinding] = []
    job_root_cases: dict[str, tuple[str, ...]] = {}
    job_analysis_manifests: dict[str, Mapping[str, Any]] = {}
    case_follow_on_lineage_documents: dict[
        str,
        Mapping[str, Any] | None,
    ] = {}
    case_state_counts: Counter[str] = Counter()
    derived_partial_present = False
    shared_derived_documents: dict[str, Mapping[str, Any]] = {}
    shared_derived_job_ids: dict[str, str] = {}
    root_shared_children: dict[str, set[str]] = {}
    materialized_derived_job_ids: dict[str, str] = {}
    source_replay_unverified_jobs = 0
    baseline_contract: dict[str, Any] | None = None
    for request, job_root in zip(publication_plan.requests, ordered_roots, strict=True):
        if case_staging._is_within(job_root, repository):
            raise PartitionedDatastoreError("completed jobはrepository外へ分離してください")
        if case_staging._is_within(job_root, source_root) or case_staging._is_within(
            source_root,
            job_root,
        ):
            raise PartitionedDatastoreError("completed jobとsource rootは相互に分離してください")
        if any(
            case_staging._is_within(temporary_root, value) or case_staging._is_within(value, temporary_root)
            for value in (job_root,)
        ):
            raise PartitionedDatastoreError("temporary rootはcompleted jobから分離してください")
        try:
            validation = partitioned._revalidate_job_for_staging(
                job_root=job_root,
                request=request,
                temporary_root=temporary_root,
                expected_timeout_seconds=expected_timeout_seconds,
                allow_partial_staging=allow_partial_staging,
            )
        except partitioned.PublicationContractError as exc:
            raise PartitionedDatastoreError(
                f"jobの全体再検証に失敗しました: {request.job_id}"
            ) from exc
        contract = partitioned._analysis_contract(validation)
        if baseline_contract is None:
            baseline_contract = contract
        elif contract != baseline_contract:
            raise PartitionedDatastoreError("job間のanalysis contractが一致しません")
        bindings = _job_case_bindings(
            request=request,
            job_root=job_root,
            validation=validation,
            source_items=source_items,
            allow_partial_staging=allow_partial_staging,
        )
        validated_summary = validation.get("summary")
        validated_derived_counts = (
            validated_summary.get("derived_counts")
            if isinstance(validated_summary, Mapping)
            else None
        )
        if (
            isinstance(validated_derived_counts, Mapping)
            and validated_derived_counts.get("partial", 0) > 0
        ):
            derived_partial_present = True
        case_state_counts.update(item.case_state for item in bindings)
        if validation.get("source_replay_verified", True) is False:
            source_replay_unverified_jobs += 1
        actual_roots = tuple(item.case_sha256 for item in bindings)
        validated_lineage = case_staging._validate_one_shot_lineage(
            job_root / "analysis",
            source_case_sha256s=set(actual_roots),
        )
        materialized_in_job = {
            child
            for root_digest in actual_roots
            for child in validated_lineage.descendants_by_root[root_digest]
        }
        materialized_derived_job_ids = _bind_materialized_derived_jobs(
            materialized_derived_job_ids,
            job_id=request.job_id,
            child_sha256s=tuple(materialized_in_job),
        )
        if externalize_shared_derived_cases:
            job_shared_documents = (
                case_staging.build_shared_derived_externalization_documents(
                    validated_lineage,
                    collection_id=collection_id,
                    allow_partial_derived_cases=allow_partial_staging,
                )
            )
            for child, document in sorted(job_shared_documents.items()):
                if child in shared_derived_documents:
                    raise PartitionedDatastoreError(
                        "同一shared childが複数production jobに存在します"
                    )
                shared_derived_documents[child] = document
                shared_derived_job_ids[child] = request.job_id
                owners = document.get("owners")
                if not isinstance(owners, list) or any(
                    owner not in actual_roots for owner in owners
                ):
                    raise PartitionedDatastoreError(
                        "shared child owner集合がproduction job root集合と一致しません"
                    )
                for owner in owners:
                    root_shared_children.setdefault(str(owner), set()).add(child)
        for root_digest in actual_roots:
            if root_digest in case_follow_on_lineage_documents:
                raise PartitionedDatastoreError(
                    "異なるjobでfollow-on lineage rootが重複しています"
                )
            case_follow_on_lineage_documents[root_digest] = (
                case_staging.build_follow_on_lineage_case_document(
                    validated_lineage,
                    collection_id=collection_id,
                    case_sha256=root_digest,
                )
            )
        expected_analysis = validation.get("analysis_output")
        expected_analysis_sha256 = validation.get("analysis_output_sha256")
        if (
            not isinstance(expected_analysis, Mapping)
            or not isinstance(expected_analysis_sha256, str)
            or analysis_job_runner.SHA256_RE.fullmatch(expected_analysis_sha256) is None
        ):
            raise PartitionedDatastoreError("runner再検証結果にanalysis tree commitmentがありません")
        analysis_commitment = {
            "tree": dict(expected_analysis),
            "sha256": expected_analysis_sha256,
        }
        if not _analysis_output_matches(job_root, analysis_commitment):
            raise PartitionedDatastoreError("job analysis treeが全体再検証後に変更されました")
        job_root_cases[request.job_id] = actual_roots
        job_analysis_manifests[request.job_id] = analysis_commitment
        all_bindings.extend(bindings)

    binding_map = _validated_global_binding_map(
        all_bindings,
        selection_hashes=publication_plan.selection_hashes,
    )
    _reject_materialized_derived_root_overlap(
        materialized_derived_job_ids,
        binding_map,
    )
    if (
        case_state_counts.get("complete", 0)
        + case_state_counts.get("partial", 0)
        != len(publication_plan.selection_hashes)
        or set(case_state_counts) - {"complete", "partial"}
    ):
        raise PartitionedDatastoreError("全jobの完了／途中case集計が固定選定と一致しません")
    publication_stage = (
        "partial_followup_required"
        if case_state_counts.get("partial", 0) > 0 or derived_partial_present
        else "complete"
    )
    return PartitionedDatastorePlan(
        repository=repository,
        collection_id=collection_id,
        source_root=source_root,
        temporary_root=temporary_root,
        source_manifest_sha256=source_manifest_sha256,
        selection_commitment_sha256=publication_plan.selection_commitment_sha256,
        bindings=binding_map,
        job_root_case_sha256s=job_root_cases,
        job_analysis_manifests=job_analysis_manifests,
        case_follow_on_lineage_documents=case_follow_on_lineage_documents,
        case_state_counts={
            "complete": case_state_counts.get("complete", 0),
            "partial": case_state_counts.get("partial", 0),
        },
        publication_stage=publication_stage,
        source_replay_verified=source_replay_unverified_jobs == 0,
        source_replay_unverified_job_count=source_replay_unverified_jobs,
        allow_partial_staging=allow_partial_staging,
        externalize_shared_derived_cases=externalize_shared_derived_cases,
        shared_derived_documents=dict(sorted(shared_derived_documents.items())),
        shared_derived_job_ids=dict(sorted(shared_derived_job_ids.items())),
        root_shared_derived_sha256s={
            root: tuple(sorted(children))
            for root, children in sorted(root_shared_children.items())
        },
    )


def _validate_staging_acquisition(
    source_path: Path,
    *,
    plan: PartitionedDatastorePlan,
    binding: CaseJobBinding,
) -> None:
    """再利用stagingを現在のselectionとcase/job結合へ再束縛する。"""

    document, _digest = _regular_json_with_digest(
        source_path / "derived" / "source-acquisition.case.json",
        max_bytes=case_staging.MAX_JSON_BYTES,
    )
    if (
        document.get("schema_version") != case_staging.ACQUISITION_SCHEMA_VERSION
        or document.get("collection_id") != plan.collection_id
        or document.get("case_sha256") != binding.case_sha256
        or document.get("provider_requested_sha256")
        != (binding.requested_sha256 if binding.requested_sha256 != binding.case_sha256 else None)
        or document.get("source_manifest_sha256") != plan.source_manifest_sha256
        or document.get("selection_commitment_sha256") != plan.selection_commitment_sha256
    ):
        raise PartitionedDatastoreError("既存stagingを現在のselection／job bindingへ束縛できません")


def _receipt_paths(receipt_root: Path, target: str) -> tuple[Path, Path]:
    """private receiptとsource bindingの固定pathを返す。"""

    try:
        target = archive_analysis_datastore.validate_target(target)
    except archive_analysis_datastore.DatastoreError as exc:
        raise PartitionedDatastoreError("receipt targetが不正です") from exc
    root = case_staging._validate_existing_directory(receipt_root, label="receipt root")
    case_staging._reject_reparse_components(root, label="receipt root")
    parents: list[Path] = []
    for name in ("archive-reports", "archive-bindings"):
        child = root / name
        root_io = archive_analysis_datastore._extended_length_path(root)
        child_io = archive_analysis_datastore._extended_length_path(child)
        before = root_io.lstat()
        if not os.path.lexists(child_io):
            try:
                os.mkdir(child_io)
            except FileExistsError:
                pass
            except OSError as exc:
                raise PartitionedDatastoreError("receipt subdirectoryを作成できません") from exc
        after = root_io.lstat()
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or case_staging._is_reparse(after)
        ):
            raise PartitionedDatastoreError("receipt root identityが作成中に変更されました")
        parent = case_staging._validate_existing_directory(
            child_io,
            label="receipt subdirectory",
        )
        case_staging._reject_reparse_components(parent, label="receipt subdirectory")
        if parent.parent != root_io:
            raise PartitionedDatastoreError("receipt subdirectoryが検証済み直親から外れました")
        parents.append(child)
    return (
        parents[0] / f"{target}.json",
        parents[1] / f"{target}.json",
    )


def _validated_receipt_binding_context(
    staged_case: Mapping[str, Any],
    expected: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """externalization receiptをlive plan由来の固定fieldへ束縛する。"""

    if expected is None:
        return None
    if not isinstance(expected, Mapping):
        raise PartitionedDatastoreError("externalization receipt contextがobjectではありません")
    role = expected.get("source_role")
    schemas = {
        "shared_derived": {
            "source_role",
            "child_sha256",
            "child_case_state",
            "provenance_sha256",
            "externalization_document_sha256",
            "source_follow_on_sha256",
            "owner_set_commitment_sha256",
            "edge_set_commitment_sha256",
        },
        "analysis_case_externalized_shared_child": {
            "source_role",
            "externalized_shared_reference_sha256",
        },
    }
    allowed = schemas.get(role)
    if allowed is None or set(expected) != allowed:
        raise PartitionedDatastoreError("externalization receipt context schemaが不正です")
    normalized = dict(expected)
    for key, value in normalized.items():
        if key in {"source_role", "child_case_state"}:
            continue
        normalized[key] = _sha256(value, label=f"externalization receipt {key}")
    if role == "shared_derived":
        normalized["child_sha256"] = _sha256(
            expected.get("child_sha256"),
            label="externalization receipt child SHA-256",
        )
        if normalized.get("child_case_state") not in {"complete", "partial"}:
            raise PartitionedDatastoreError("externalization receipt child状態が不正です")
    for key, value in normalized.items():
        if key == "source_role":
            continue
        if staged_case.get(key) != value:
            raise PartitionedDatastoreError(
                "staging handoffがexternalization receipt contextと一致しません"
            )
    return normalized


def _reverify_receipt(
    *,
    repository: Path,
    receipt_root: Path,
    staged_case: Mapping[str, Any],
    aws_cli: Path | None,
    region: str,
    expected_follow_on_lineage_sha256: str | None = None,
    expected_binding_context: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """既存receiptをlocal sourceとS3 HeadObjectへ再束縛し、必要ならbindingを作る。"""

    target = staged_case.get("target")
    if not isinstance(target, str):
        raise PartitionedDatastoreError("staging handoff targetが不正です")
    expected_lineage_sha256 = (
        _sha256(
            expected_follow_on_lineage_sha256,
            label="expected follow-on lineage SHA-256",
        )
        if expected_follow_on_lineage_sha256 is not None
        else None
    )
    if staged_case.get("follow_on_lineage_sha256") != expected_lineage_sha256:
        raise PartitionedDatastoreError(
            "staging handoffのfollow-on lineage commitmentが不正です"
        )
    binding_context = _validated_receipt_binding_context(
        staged_case,
        expected_binding_context,
    )
    report_path, binding_path = _receipt_paths(receipt_root, target)
    report_exists = os.path.lexists(report_path)
    binding_exists = os.path.lexists(binding_path)
    if not report_exists and not binding_exists:
        return None
    if binding_exists and not report_exists:
        raise PartitionedDatastoreError("source bindingだけが残る不完全なreceipt状態です")
    report, report_sha256 = _regular_json_with_digest(report_path, max_bytes=MAX_RECEIPT_BYTES)
    s3 = report.get("s3_verification")
    object_uri = report.get("object_uri")
    match = OBJECT_URI_RE.fullmatch(object_uri) if isinstance(object_uri, str) else None
    expected_key_prefix = f"{archive_analysis_datastore.DEFAULT_PREFIX}/{target}/"
    if (
        report.get("schema_version") != "analysis-datastore-upload-report/v1"
        or report.get("status") != "verified"
        or report.get("target") != target
        or report.get("local_source_deleted") is not False
        or report.get("source_tree_commitment_verified") is not True
        or report.get("source_tree_sha256") != staged_case.get("source_tree_sha256")
        or report.get("file_count") != staged_case.get("file_count")
        or report.get("total_uncompressed_size") != staged_case.get("total_size")
        or not isinstance(report.get("archive_size"), int)
        or isinstance(report.get("archive_size"), bool)
        or report["archive_size"] <= 0
        or not isinstance(report.get("archive_sha256"), str)
        or analysis_job_runner.SHA256_RE.fullmatch(report["archive_sha256"]) is None
        or not isinstance(report.get("manifest_sha256"), str)
        or analysis_job_runner.SHA256_RE.fullmatch(report["manifest_sha256"]) is None
        or not isinstance(s3, Mapping)
        or s3.get("server_side_encryption") != "AES256"
        or match is None
        or match.group(1) != archive_analysis_datastore.DEFAULT_BUCKET
        or not match.group(2).startswith(expected_key_prefix)
    ):
        raise PartitionedDatastoreError("既存receiptがcase source／S3保管契約と一致しません")
    if binding_context is None:
        binding_document = {
            "schema_version": RECEIPT_BINDING_SCHEMA_VERSION,
            "target": target,
            "source_role": "analysis_case",
            "source_tree_sha256": staged_case["source_tree_sha256"],
            "follow_on_lineage_sha256": expected_lineage_sha256,
            "file_count": staged_case["file_count"],
            "total_size": staged_case["total_size"],
            "archive_report_sha256": report_sha256,
            "local_source_deleted": False,
        }
    else:
        binding_document = {
            "schema_version": EXTERNALIZED_RECEIPT_BINDING_SCHEMA_VERSION,
            "target": target,
            "source_role": binding_context["source_role"],
            "source_tree_sha256": staged_case["source_tree_sha256"],
            "follow_on_lineage_sha256": expected_lineage_sha256,
            "file_count": staged_case["file_count"],
            "total_size": staged_case["total_size"],
            "archive_report_sha256": report_sha256,
            "binding_context": binding_context,
            "local_source_deleted": False,
        }
    if binding_exists:
        existing_binding, _binding_sha256 = _regular_json_with_digest(
            binding_path,
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if existing_binding != binding_document:
            raise PartitionedDatastoreError("既存receipt bindingが現在のcase sourceと一致しません")
    try:
        aws = archive_analysis_datastore.find_aws_cli(aws_cli)
        response = archive_analysis_datastore._run_aws(
            aws,
            [
                "s3api",
                "head-object",
                "--bucket",
                match.group(1),
                "--key",
                match.group(2),
                "--region",
                region,
                "--output",
                "json",
            ],
            expect_json=True,
        )
        archive_analysis_datastore.verify_head_object(
            response,
            expected_size=report["archive_size"],
            archive_sha256=report["archive_sha256"],
            manifest_sha256=report["manifest_sha256"],
            target=target,
            source_tree_sha256=staged_case["source_tree_sha256"],
        )
    except (archive_analysis_datastore.DatastoreError, OSError) as exc:
        raise PartitionedDatastoreError("既存receiptのS3 objectを再検証できません") from exc
    refreshed_report_path, refreshed_binding_path = _receipt_paths(
        receipt_root,
        target,
    )
    if refreshed_report_path != report_path or refreshed_binding_path != binding_path:
        raise PartitionedDatastoreError("receipt pathがremote再検証中に変更されました")
    refreshed_report, refreshed_report_sha256 = _regular_json_with_digest(
        report_path,
        max_bytes=MAX_RECEIPT_BYTES,
    )
    if refreshed_report != report or refreshed_report_sha256 != report_sha256:
        raise PartitionedDatastoreError("receipt reportがremote再検証中に変更されました")
    if binding_exists:
        refreshed_binding, _refreshed_binding_sha256 = _regular_json_with_digest(
            binding_path,
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if refreshed_binding != binding_document:
            raise PartitionedDatastoreError("receipt bindingがremote再検証中に変更されました")
    binding_created = False
    if not binding_exists:
        if case_staging._is_within(binding_path, repository):
            raise PartitionedDatastoreError("receipt bindingをrepository内へ作成できません")
        analysis_job_runner.atomic_json(binding_path, binding_document)
        persisted_binding, _binding_sha256 = _regular_json_with_digest(
            binding_path,
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if persisted_binding != binding_document:
            raise PartitionedDatastoreError("receipt bindingの保存後検証に失敗しました")
        binding_created = True
    return {
        "target": target,
        "status": "verified_reused",
        "archive_sha256": report["archive_sha256"],
        "manifest_sha256": report["manifest_sha256"],
        "archive_report_sha256": report_sha256,
        "source_tree_sha256": staged_case["source_tree_sha256"],
        "follow_on_lineage_sha256": expected_lineage_sha256,
        "file_count": staged_case["file_count"],
        "total_size": staged_case["total_size"],
        "remote_reverified": True,
        "receipt_binding_created": binding_created,
        **(
            {
                key: value
                for key, value in binding_context.items()
                if key != "source_role"
            }
            if binding_context is not None
            else {}
        ),
    }


def _shared_binding_context(
    document: Mapping[str, Any],
    staged: Mapping[str, Any],
) -> dict[str, Any]:
    """shared derived receiptへ束縛するlive plan fieldを返す。"""

    return {
        "source_role": "shared_derived",
        "child_sha256": document["child_sha256"],
        "child_case_state": document["child_case_state"],
        "provenance_sha256": staged["provenance_sha256"],
        "externalization_document_sha256": case_staging._canonical_sha256(document),
        "source_follow_on_sha256": document["source_follow_on_sha256"],
        "owner_set_commitment_sha256": document["owner_set_commitment_sha256"],
        "edge_set_commitment_sha256": document["edge_set_commitment_sha256"],
    }


def coordinate_externalized_shared_derived(
    plan: PartitionedDatastorePlan,
    *,
    child_sha256: str,
    output_root: Path,
    receipt_root: Path,
    aws_cli: Path | None = None,
    region: str = archive_analysis_datastore.DEFAULT_REGION,
) -> dict[str, Any]:
    """共有derivedをrootより先にstageし、既存receiptがあればremote再検証する。"""

    child = _sha256(child_sha256, label="--shared-child-sha256")
    if not plan.externalize_shared_derived_cases:
        raise PartitionedDatastoreError("共有derived externalizationがplanで明示許可されていません")
    document = plan.shared_derived_documents.get(child)
    job_id = plan.shared_derived_job_ids.get(child)
    if document is None or job_id is None:
        raise PartitionedDatastoreError("指定shared childが検証済みexternalization planにありません")
    job_roots = {
        binding.job_root
        for binding in plan.bindings.values()
        if binding.job_id == job_id
    }
    if len(job_roots) != 1:
        raise PartitionedDatastoreError("shared childのproduction job rootが一意ではありません")
    job_root = next(iter(job_roots))
    receipt_root = case_staging._validate_existing_directory(
        receipt_root,
        label="receipt root",
    )
    output = case_staging._absolute(output_root)
    if case_staging._is_within(receipt_root, plan.repository):
        raise PartitionedDatastoreError("receipt rootはrepository外へ分離してください")
    if any(
        case_staging._is_within(receipt_root, value)
        or case_staging._is_within(value, receipt_root)
        or case_staging._is_within(output, value)
        or case_staging._is_within(value, output)
        for value in (
            plan.source_root,
            job_root,
            plan.temporary_root,
            plan.repository,
        )
    ) or case_staging._is_within(receipt_root, output) or case_staging._is_within(
        output,
        receipt_root,
    ):
        raise PartitionedDatastoreError(
            "共有derived receipt rootとstagingはrepository、source、job、temporary rootから分離してください"
        )
    expected_analysis = plan.job_analysis_manifests[job_id]
    expected_analysis_sha256 = _sha256(
        expected_analysis.get("sha256"),
        label="analysis output SHA-256",
    )
    if not _analysis_output_matches(job_root, expected_analysis):
        raise PartitionedDatastoreError("shared childのanalysis treeがplan後に変更されました")
    live_lineage = case_staging._validate_one_shot_lineage(
        job_root / "analysis",
        source_case_sha256s=set(plan.job_root_case_sha256s[job_id]),
    )
    live_documents = case_staging.build_shared_derived_externalization_documents(
        live_lineage,
        collection_id=plan.collection_id,
        allow_partial_derived_cases=plan.allow_partial_staging,
    )
    if live_documents.get(child) != document:
        raise PartitionedDatastoreError(
            "shared childのlive graphがplan commitmentと一致しません"
        )
    target = case_staging._shared_derived_target(plan.collection_id, child)
    if os.path.lexists(
        archive_analysis_datastore._extended_length_path(output / target)
    ):
        staged = case_staging.reuse_externalized_shared_derived_staging(
            output_root=output,
            collection_id=plan.collection_id,
            child_sha256=child,
            allow_partial_derived_cases=plan.allow_partial_staging,
            expected_analysis_output_sha256=expected_analysis_sha256,
            expected_externalization_document=document,
        )
    else:
        staged = case_staging.stage_externalized_shared_derived_case(
            repository=plan.repository,
            collection_id=plan.collection_id,
            one_shot_root=job_root / "analysis",
            output_root=output,
            expected_run_root_sha256s=plan.job_root_case_sha256s[job_id],
            child_sha256=child,
            allow_partial_derived_cases=plan.allow_partial_staging,
            expected_analysis_output_sha256=expected_analysis_sha256,
            expected_externalization_document=document,
        )
    if (
        staged.get("target") != target
        or staged.get("child_sha256") != child
        or staged.get("externalization_document_sha256")
        != case_staging._canonical_sha256(document)
    ):
        raise PartitionedDatastoreError("shared staging handoffがplanと一致しません")
    if not _analysis_output_matches(job_root, expected_analysis):
        raise PartitionedDatastoreError("shared staging中にanalysis treeが変更されました")
    binding_context = _shared_binding_context(document, staged)
    reused = _reverify_receipt(
        repository=plan.repository,
        receipt_root=receipt_root,
        staged_case=staged,
        aws_cli=aws_cli,
        region=region,
        expected_binding_context=binding_context,
    )
    source_path = case_staging._absolute(Path(str(staged["source_path"])))
    if source_path != output / target:
        raise PartitionedDatastoreError("shared stagingがowned output root外を返しました")
    if reused is not None:
        cleanup = case_staging.remove_externalized_shared_staging_after_verified_archive(
            output_root=output,
            source_path=source_path,
            collection_id=plan.collection_id,
            child_sha256=child,
            archive_result=reused,
            allow_partial_derived_cases=plan.allow_partial_staging,
            expected_analysis_output_sha256=expected_analysis_sha256,
            expected_externalization_document=document,
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "verified_reused",
            "collection_id": plan.collection_id,
            "child_sha256": child,
            "job_id": job_id,
            "archive_result": reused,
            "owned_staging_removed": cleanup.get("removed") is True,
            "source_deleted": False,
            "sample_executed": False,
            "network_contacted": True,
            "network_contact_purpose": "datastore_receipt_reverification",
            "c2_contacted": False,
            "s3_upload_performed": False,
            "output_handling_warning_ja": OUTPUT_HANDLING_WARNING_JA,
        }
    report_path, _binding_path = _receipt_paths(receipt_root, target)
    archive_arguments = [
        *staged["archive_arguments"],
        "--bucket",
        archive_analysis_datastore.DEFAULT_BUCKET,
        "--region",
        region,
        "--report",
        os.fspath(report_path),
    ]
    if aws_cli is not None:
        archive_arguments.extend(("--aws-cli", os.fspath(aws_cli)))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "staging_ready",
        "collection_id": plan.collection_id,
        "child_sha256": child,
        "job_id": job_id,
        "source_path": os.fspath(source_path),
        "source_tree_sha256": staged["source_tree_sha256"],
        "file_count": staged["file_count"],
        "total_size": staged["total_size"],
        "archive_arguments": archive_arguments,
        "sample_executed": False,
        "network_contacted": False,
        "s3_upload_performed": False,
        "source_deleted": False,
        "output_handling_warning_ja": OUTPUT_HANDLING_WARNING_JA,
    }


def coordinate_partitioned_case(
    plan: PartitionedDatastorePlan,
    *,
    requested_sha256: str,
    output_root: Path,
    receipt_root: Path,
    aws_cli: Path | None = None,
    region: str = archive_analysis_datastore.DEFAULT_REGION,
) -> dict[str, Any]:
    """全体preflight済み計画から1 caseだけをstageし、upload前handoffを返す。"""

    requested = _sha256(requested_sha256, label="--case-sha256")
    binding = plan.bindings.get(requested)
    if binding is None:
        raise PartitionedDatastoreError("指定caseが全体preflight済みselectionにありません")
    receipt_root = case_staging._validate_existing_directory(receipt_root, label="receipt root")
    if case_staging._is_within(receipt_root, plan.repository):
        raise PartitionedDatastoreError("receipt rootはrepository外へ分離してください")
    output = case_staging._absolute(output_root)
    if (
        case_staging._is_within(receipt_root, plan.source_root)
        or case_staging._is_within(plan.source_root, receipt_root)
        or case_staging._is_within(receipt_root, binding.job_root)
        or case_staging._is_within(binding.job_root, receipt_root)
        or case_staging._is_within(receipt_root, output)
        or case_staging._is_within(output, receipt_root)
        or case_staging._is_within(receipt_root, plan.temporary_root)
        or case_staging._is_within(plan.temporary_root, receipt_root)
        or case_staging._is_within(output, plan.temporary_root)
        or case_staging._is_within(plan.temporary_root, output)
    ):
        raise PartitionedDatastoreError(
            "receipt rootとstagingはsource、job、temporary rootから分離してください"
        )
    expected_analysis = plan.job_analysis_manifests[binding.job_id]
    expected_analysis_sha256 = _sha256(
        expected_analysis.get("sha256"),
        label="analysis output SHA-256",
    )
    if not _analysis_output_matches(binding.job_root, expected_analysis):
        raise PartitionedDatastoreError("job analysis treeが全体preflight後に変更されました")
    live_lineage = case_staging._validate_one_shot_lineage(
        binding.job_root / "analysis",
        source_case_sha256s=set(
            plan.job_root_case_sha256s[binding.job_id]
        ),
    )
    verified_shared_receipts: dict[str, Mapping[str, Any]] = {}
    expected_shared_reference: Mapping[str, Any] | None = None
    root_shared_children = plan.root_shared_derived_sha256s.get(
        binding.case_sha256,
        (),
    )
    if plan.externalize_shared_derived_cases:
        live_shared_documents = (
            case_staging.build_shared_derived_externalization_documents(
                live_lineage,
                collection_id=plan.collection_id,
                allow_partial_derived_cases=plan.allow_partial_staging,
            )
        )
        planned_job_documents = {
            child: document
            for child, document in plan.shared_derived_documents.items()
            if plan.shared_derived_job_ids.get(child) == binding.job_id
        }
        if live_shared_documents != planned_job_documents:
            raise PartitionedDatastoreError(
                "live shared-derived planが全体preflight commitmentと一致しません"
            )
        observed_root_children = case_staging._shared_children_for_root(
            live_shared_documents,
            root_sha256=binding.case_sha256,
        )
        if tuple(root_shared_children) != observed_root_children:
            raise PartitionedDatastoreError("rootのshared child集合がplanと一致しません")
        for child in root_shared_children:
            shared_result = coordinate_externalized_shared_derived(
                plan,
                child_sha256=child,
                output_root=output,
                receipt_root=receipt_root,
                aws_cli=aws_cli,
                region=region,
            )
            if shared_result.get("status") != "verified_reused":
                raise PartitionedDatastoreError(
                    "root staging前にshared child archiveをuploadし、receiptをremote再検証してください"
                )
            archive_result = shared_result.get("archive_result")
            if not isinstance(archive_result, Mapping):
                raise PartitionedDatastoreError("shared child receipt結果がありません")
            verified_shared_receipts[child] = archive_result
        if root_shared_children:
            if live_lineage.graph_sha256 is None:
                raise PartitionedDatastoreError("shared childにfollow-on graph commitmentがありません")
            expected_shared_reference = (
                case_staging.build_shared_derived_reference_document(
                    collection_id=plan.collection_id,
                    root_sha256=binding.case_sha256,
                    source_follow_on_sha256=live_lineage.graph_sha256,
                    externalization_documents=live_shared_documents,
                    verified_receipts=verified_shared_receipts,
                )
            )
    rejected_lineage_reasons = tuple(
        reason
        for reason in live_lineage.unsafe_reasons_by_root[binding.case_sha256]
        if not (
            plan.allow_partial_staging
            and reason == "derived_child_incomplete"
        )
        and not (
            reason == "shared_or_cross_root_child"
            and bool(root_shared_children)
            and expected_shared_reference is not None
        )
    )
    if rejected_lineage_reasons:
        raise PartitionedDatastoreError(
            "live follow-on lineageを安全に分離できません: "
            + ", ".join(rejected_lineage_reasons)
        )
    if binding.case_sha256 not in plan.case_follow_on_lineage_documents:
        raise PartitionedDatastoreError(
            "planにroot別follow-on lineage commitmentがありません"
        )
    planned_lineage_document = plan.case_follow_on_lineage_documents[
        binding.case_sha256
    ]
    live_lineage_document = case_staging.build_follow_on_lineage_case_document(
        live_lineage,
        collection_id=plan.collection_id,
        case_sha256=binding.case_sha256,
    )
    if live_lineage_document != planned_lineage_document:
        raise PartitionedDatastoreError(
            "live follow-on lineageが全体preflight commitmentと一致しません"
        )
    expected_lineage_document = planned_lineage_document
    expected_lineage_sha256 = (
        case_staging._canonical_sha256(expected_lineage_document)
        if expected_lineage_document is not None
        else None
    )
    target = case_staging._datastore_target(plan.collection_id, binding.case_sha256)
    if os.path.lexists(
        archive_analysis_datastore._extended_length_path(output / target)
    ):
        staged = case_staging.reuse_case_staging(
            output_root=output,
            collection_id=plan.collection_id,
            case_sha256=binding.case_sha256,
            allow_partial_derived_cases=plan.allow_partial_staging,
            expected_analysis_output_sha256=expected_analysis_sha256,
            expected_follow_on_lineage_document=expected_lineage_document,
            expected_externalized_shared_reference_document=(
                expected_shared_reference
            ),
        )
    else:
        stage_arguments = {
            "repository": plan.repository,
            "collection_id": plan.collection_id,
            "source_root": plan.source_root,
            "one_shot_root": binding.job_root / "analysis",
            "output_root": output,
            "case_sha256s": [binding.case_sha256],
            "source_requested_sha256": binding.requested_sha256,
            "expected_run_root_sha256s": plan.job_root_case_sha256s[binding.job_id],
            "allow_partial_derived_cases": plan.allow_partial_staging,
            "expected_analysis_output_sha256": expected_analysis_sha256,
            "expected_follow_on_lineage_document": expected_lineage_document,
        }
        if expected_shared_reference is None:
            staged = case_staging.stage_cases_without_ghidra(**stage_arguments)
        else:
            staged = case_staging._stage_cases_without_ghidra(
                **stage_arguments,
                externalized_shared_receipts=verified_shared_receipts,
            )
    cases = staged.get("cases")
    if (
        staged.get("case_count") != 1
        or not isinstance(cases, list)
        or len(cases) != 1
        or not isinstance(cases[0], Mapping)
        or cases[0].get("case_sha256") != binding.case_sha256
        or cases[0].get("target") != target
        or cases[0].get("follow_on_lineage_sha256")
        != expected_lineage_sha256
        or cases[0].get("externalized_shared_reference_sha256")
        != (
            case_staging._canonical_sha256(expected_shared_reference)
            if expected_shared_reference is not None
            else None
        )
    ):
        raise PartitionedDatastoreError("case staging helperのhandoffが指定caseと一致しません")
    staged_case = dict(cases[0])
    source_value = staged_case.get("source_path")
    if not isinstance(source_value, str):
        raise PartitionedDatastoreError("case staging helperがsource pathを返しませんでした")
    source_path = case_staging._absolute(Path(source_value))
    if source_path != output / target:
        raise PartitionedDatastoreError("case staging helperがowned output root外を返しました")
    _validate_staging_acquisition(source_path, plan=plan, binding=binding)
    if not _analysis_output_matches(binding.job_root, expected_analysis):
        raise PartitionedDatastoreError("job analysis treeがcase staging中に変更されました")

    root_binding_context = (
        {
            "source_role": "analysis_case_externalized_shared_child",
            "externalized_shared_reference_sha256": (
                case_staging._canonical_sha256(expected_shared_reference)
            ),
        }
        if expected_shared_reference is not None
        else None
    )
    reused = _reverify_receipt(
        repository=plan.repository,
        receipt_root=receipt_root,
        staged_case=staged_case,
        aws_cli=aws_cli,
        region=region,
        expected_follow_on_lineage_sha256=expected_lineage_sha256,
        expected_binding_context=root_binding_context,
    )
    if reused is not None:
        cleanup = case_staging.remove_case_staging_after_verified_archive(
            output_root=output,
            source_path=source_path,
            collection_id=plan.collection_id,
            case_sha256=binding.case_sha256,
            archive_result=reused,
            allow_partial_derived_cases=plan.allow_partial_staging,
            expected_analysis_output_sha256=expected_analysis_sha256,
            expected_follow_on_lineage_document=expected_lineage_document,
            expected_externalized_shared_reference_document=(
                expected_shared_reference
            ),
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "verified_reused",
            "collection_id": plan.collection_id,
            "case_sha256": binding.case_sha256,
            "provider_requested_sha256": (
                binding.requested_sha256 if binding.requested_sha256 != binding.case_sha256 else None
            ),
            "job_id": binding.job_id,
            "case_state": binding.case_state,
            "publication_stage": plan.publication_stage,
            "source_replay_verified": binding.source_replay_verified,
            "archive_result": reused,
            "owned_staging_removed": cleanup.get("removed") is True,
            "source_deleted": False,
            "sample_executed": False,
            "network_contacted": True,
            "network_contact_purpose": "datastore_receipt_reverification",
            "c2_contacted": False,
            "s3_upload_performed": False,
            "output_handling_warning_ja": OUTPUT_HANDLING_WARNING_JA,
        }

    report_path, _binding_path = _receipt_paths(receipt_root, target)
    archive_arguments = [
        *staged_case["archive_arguments"],
        "--bucket",
        archive_analysis_datastore.DEFAULT_BUCKET,
        "--region",
        region,
        "--report",
        os.fspath(report_path),
    ]
    if aws_cli is not None:
        archive_arguments.extend(("--aws-cli", os.fspath(aws_cli)))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "staging_ready",
        "collection_id": plan.collection_id,
        "case_sha256": binding.case_sha256,
        "provider_requested_sha256": (
            binding.requested_sha256 if binding.requested_sha256 != binding.case_sha256 else None
        ),
        "job_id": binding.job_id,
        "case_state": binding.case_state,
        "publication_stage": plan.publication_stage,
        "source_replay_verified": binding.source_replay_verified,
        "source_path": os.fspath(source_path),
        "source_tree_sha256": staged_case["source_tree_sha256"],
        "file_count": staged_case["file_count"],
        "total_size": staged_case["total_size"],
        "archive_arguments": archive_arguments,
        "sample_executed": False,
        "network_contacted": False,
        "s3_upload_performed": False,
        "output_handling_warning_ja": OUTPUT_HANDLING_WARNING_JA,
    }


def _timeout_argument(value: str) -> int:
    """runner timeout契約を上限内の整数へ変換する。"""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeoutは整数で指定してください") from exc
    if not 1 <= parsed <= analysis_job_runner.MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"timeoutは1..{analysis_job_runner.MAX_TIMEOUT_SECONDS}秒で指定してください"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """全体preflightと単一case handoff用CLI parserを返す。"""

    parser = JapaneseArgumentParser(
        description=__doc__,
        epilog=(
            "重要: case処理の標準出力にはprivate絶対pathとarchive引数が含まれます。"
            "標準出力を解析repository内へredirect、tee、保存しないでください。"
        ),
    )
    parser.add_argument("--repository", type=Path, default=REPOSITORY, help="解析repository。")
    parser.add_argument("--selection-manifest", required=True, type=Path, help="取得完了した固定200件manifest。")
    parser.add_argument("--batch-manifest", required=True, type=Path, help="検証対象batch-manifest.json。")
    parser.add_argument("--source-root", required=True, type=Path, help="暗号化source ZIPを保持するprivate root。")
    parser.add_argument(
        "--job-root",
        required=True,
        action="append",
        type=Path,
        help="completed production job directory。最大4回指定します。",
    )
    parser.add_argument("--collection-id", required=True, help="case archiveへ使用するcollection ID。")
    parser.add_argument("--temporary-root", required=True, type=Path, help="job全体再検証用のprivate一時root。")
    parser.add_argument(
        "--expected-timeout-seconds",
        type=_timeout_argument,
        default=analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
        help=f"production jobのtimeout契約。既定{analysis_job_runner.DEFAULT_TIMEOUT_SECONDS}秒。",
    )
    parser.add_argument(
        "--allow-partial-staging",
        action="store_true",
        help=(
            "terminal failed／exit 2／invalid_analysis_stateのjobを、固定root、"
            "report seal、安全フラグ、既知blockerを全件再検証できた場合だけ"
            "case単位で保管可能にします。途中caseは完了件数へ含めません。"
        ),
    )
    parser.add_argument(
        "--externalize-shared-derived",
        action="store_true",
        help=(
            "共有derived leafを独立targetへ先行保管します。既定のshared拒否は維持され、"
            "このflagとremote再検証済みreceiptが揃ったrootだけ外部参照へ置換します。"
        ),
    )
    parser.add_argument(
        "--ghidra-not-requested",
        required=True,
        action="store_true",
        help="Ghidra artifactを要求せず、sourceと静的解析jobだけを保管します。",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight-only", action="store_true", help="全体再検証だけを行い、stagingしません。")
    action.add_argument("--case-sha256", help="固定選定側のSHA-256。1回につき1件だけstageします。")
    action.add_argument(
        "--shared-child-sha256",
        help="共有derived childのSHA-256。rootより先に独立targetへstageします。",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        help="repository外の単一case staging専用root。標準出力もrepository内へ保存しません。",
    )
    parser.add_argument(
        "--receipt-root",
        type=Path,
        help="repository外のreceipt／binding保存root。",
    )
    parser.add_argument("--aws-cli", type=Path, help="receipt再検証と後続archive用AWS CLI path。")
    parser.add_argument(
        "--region",
        default=archive_analysis_datastore.DEFAULT_REGION,
        help="datastore bucketのAWS region。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """全partitionをfail-closed検証し、必要なら単一case handoffを返す。"""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        plan = prepare_partitioned_datastore_plan(
            repository=arguments.repository,
            collection_id=arguments.collection_id,
            source_root=arguments.source_root,
            selection_manifest_path=arguments.selection_manifest,
            batch_manifest_path=arguments.batch_manifest,
            job_roots=arguments.job_root,
            temporary_root=arguments.temporary_root,
            expected_timeout_seconds=arguments.expected_timeout_seconds,
            allow_partial_staging=arguments.allow_partial_staging,
            externalize_shared_derived_cases=(
                arguments.externalize_shared_derived
            ),
        )
        if arguments.preflight_only:
            result = {
                "schema_version": SCHEMA_VERSION,
                "status": "preflight_complete",
                "collection_id": plan.collection_id,
                "selection_commitment_sha256": plan.selection_commitment_sha256,
                "case_count": len(plan.bindings),
                "job_count": len(plan.job_root_case_sha256s),
                "all_jobs_complete": plan.publication_stage == "complete",
                "publication_stage": plan.publication_stage,
                "case_state_counts": dict(plan.case_state_counts),
                "source_replay_verified": plan.source_replay_verified,
                "source_replay_unverified_job_count": (
                    plan.source_replay_unverified_job_count
                ),
                "case_job_binding_unique": True,
                "shared_derived_externalization_enabled": (
                    plan.externalize_shared_derived_cases
                ),
                "shared_derived_target_count": len(plan.shared_derived_documents),
                "sample_executed": False,
                "network_contacted": False,
                "s3_upload_performed": False,
                "output_handling_warning_ja": OUTPUT_HANDLING_WARNING_JA,
            }
        else:
            if arguments.output_root is None or arguments.receipt_root is None:
                raise PartitionedDatastoreError(
                    "staging actionには--output-rootと--receipt-rootが必要です"
                )
            if arguments.shared_child_sha256 is not None:
                if not arguments.externalize_shared_derived:
                    raise PartitionedDatastoreError(
                        "--shared-child-sha256には--externalize-shared-derivedが必要です"
                    )
                result = coordinate_externalized_shared_derived(
                    plan,
                    child_sha256=arguments.shared_child_sha256,
                    output_root=arguments.output_root,
                    receipt_root=arguments.receipt_root,
                    aws_cli=arguments.aws_cli,
                    region=arguments.region,
                )
            else:
                result = coordinate_partitioned_case(
                    plan,
                    requested_sha256=arguments.case_sha256,
                    output_root=arguments.output_root,
                    receipt_root=arguments.receipt_root,
                    aws_cli=arguments.aws_cli,
                    region=arguments.region,
                )
    except (
        PartitionedDatastoreError,
        case_staging.CaseStagingError,
        partitioned.PublicationContractError,
        archive_analysis_datastore.DatastoreError,
        OSError,
    ) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
