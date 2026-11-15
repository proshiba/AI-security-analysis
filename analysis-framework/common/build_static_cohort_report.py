#!/usr/bin/env python3
"""固定選定の静的解析結果をfamily・構造・通信の証拠境界を保って集計する。"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = COMMON_ROOT.parents[1]
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import analysis_contract  # noqa: E402
import build_malwarebazaar_job_requests as partitioner  # noqa: E402
import c2_analysis_contract  # noqa: E402
import orchestration_outcome  # noqa: E402
import summarize_one_shot_corpus as corpus  # noqa: E402
from malwarebazaar_selection_contract import validate_item_metadata_binding  # noqa: E402

SCHEMA_VERSION = "static-cohort-report/v1"
CODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,255}")
SECTION_RE = re.compile(r"[.A-Za-z0-9_-]{1,32}")
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_. -]{0,99}")
MAX_STRUCTURE_LAYERS = 4096
MAX_STRUCTURE_RECORDS = 16384
CONTROL_ROLES = frozenset(
    {"c2", "control", "control_endpoint", "command_and_control", "exfil", "exfiltration", "exfiltration_endpoint", "configured_external_c2"}
)
NON_CONTROL_TOKENS = frozenset(
    {"candidate", "delivery", "download", "stage", "dead_drop", "resolver", "decoy", "legitimate", "context", "shared", "payload"}
)


class StaticCohortReportError(ValueError):
    """固定選定、case封印、安全性または出力境界の不整合。"""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _code(value: Any, fallback: str = "unrecognized") -> str:
    return value if isinstance(value, str) and CODE_RE.fullmatch(value) else fallback


def _integer(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _boolean(value: Any) -> bool | None:
    return value if type(value) is bool else None


def _safe_label(value: Any) -> dict[str, Any]:
    if value is None:
        return {"value": None, "redacted": False}
    if isinstance(value, str) and LABEL_RE.fullmatch(value):
        return {"value": value, "redacted": False}
    return {"value": None, "redacted": True, "sha256": _digest(value)}


def _artifact(
    case_dir: Path, report: Mapping[str, Any], name: str, budget: corpus._ReadBudget
) -> dict[str, Any] | None:
    if name not in report["artifact_sha256"]:
        return None
    document, _ = corpus._case_artifact(case_dir, report, name, budget)
    return document


def _structure(
    layers: Mapping[str, Any] | None,
    generic: Mapping[str, Any] | None,
    *,
    expected_root_sha256: str | None = None,
) -> dict[str, Any]:
    """構造値を許可項目だけへ投影し、文字列走査IOCや生コードを混入させない。"""
    records: list[dict[str, Any]] = []
    steps = layers.get("steps", []) if isinstance(layers, Mapping) else []
    step_by_sha: dict[str, Mapping[str, Any]] = {}
    if not isinstance(steps, list) or len(steps) > MAX_STRUCTURE_LAYERS:
        raise StaticCohortReportError("static-layers stepsが配列ではないか上限超過です")
    for step in steps:
        if not isinstance(step, Mapping):
            raise StaticCohortReportError("static-layers stepがobjectではありません")
        layer = step.get("input_layer", {})
        value = step.get("report", {})
        if not isinstance(layer, Mapping) or not isinstance(value, Mapping):
            raise StaticCohortReportError("static stepのinput layerまたはreportがobjectではありません")
        digest = layer.get("sha256")
        if not isinstance(digest, str) or corpus.SHA256_RE.fullmatch(digest) is None or digest in step_by_sha:
            raise StaticCohortReportError("static stepのinput SHA-256が不正または重複しています")
        if value.get("sha256") is not None and value.get("sha256") != digest:
            raise StaticCohortReportError("static step reportのSHA-256がinput layerと一致しません")
        step_by_sha[digest] = value
    raw_layers = layers.get("layers", []) if isinstance(layers, Mapping) else []
    if not isinstance(raw_layers, list) or len(raw_layers) > MAX_STRUCTURE_LAYERS or layers is not None and not raw_layers:
        raise StaticCohortReportError("static layer一覧が不正または過大です")
    structure_record_count = len(raw_layers) + len(steps)
    for layer in raw_layers:
        if not isinstance(layer, Mapping):
            raise StaticCohortReportError("static layerがobjectではありません")
        digest = layer.get("sha256")
        parent = layer.get("parent_sha256")
        if not isinstance(digest, str) or corpus.SHA256_RE.fullmatch(digest) is None:
            raise StaticCohortReportError("static layerのSHA-256が不正です")
        if parent is not None and (not isinstance(parent, str) or corpus.SHA256_RE.fullmatch(parent) is None):
            raise StaticCohortReportError("static layer親SHA-256が不正です")
        step = step_by_sha.get(digest, {})
        pe = step.get("pe", {})
        pe = pe if isinstance(pe, Mapping) else {}
        elf = step.get("elf", {})
        if not isinstance(elf, Mapping) or not elf:
            elf = generic.get("elf", {}) if isinstance(generic, Mapping) and layer.get("depth") == 0 else {}
        elf = elf if isinstance(elf, Mapping) else {}
        segments = elf.get("load_segments", [])
        segment_records = []
        if isinstance(segments, list):
            structure_record_count += len(segments)
            if structure_record_count > MAX_STRUCTURE_RECORDS:
                raise StaticCohortReportError("構造metadataの総record数が上限を超えています")
            for segment in segments:
                if isinstance(segment, Mapping):
                    address = segment.get("virtual_address")
                    segment_records.append({"offset": _integer(segment.get("offset")), "virtual_address": address if isinstance(address, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", address) else None, "file_size": _integer(segment.get("file_size")), "memory_size": _integer(segment.get("memory_size"))})
        sections = pe.get("sections", [])
        if not isinstance(sections, list):
            sections = []
        structure_record_count += len(sections)
        if structure_record_count > MAX_STRUCTURE_RECORDS:
            raise StaticCohortReportError("構造metadataの総record数が上限を超えています")
        section_records = []
        for section in sections:
            if not isinstance(section, Mapping):
                continue
            name = section.get("name")
            section_records.append(
                {
                    "name": name if isinstance(name, str) and SECTION_RE.fullmatch(name) else None,
                    "name_sha256": _digest(name),
                    "raw_size": _integer(section.get("raw_size")),
                    "virtual_size": _integer(section.get("virtual_size")),
                    "entropy": section.get("entropy") if type(section.get("entropy")) in {int, float} else None,
                }
            )
        markers = pe.get("packer_markers", [])
        if isinstance(markers, list):
            structure_record_count += len(markers)
            if structure_record_count > MAX_STRUCTURE_RECORDS:
                raise StaticCohortReportError("構造metadataの総record数が上限を超えています")
        records.append(
            {
                "sha256": digest,
                "parent_sha256": parent,
                "size": _integer(layer.get("size")),
                "depth": _integer(layer.get("depth")),
                "format": _code(layer.get("format")),
                "transform": _code(layer.get("transform")),
                "pe": {
                    "machine": _code(pe.get("machine")) if pe else None,
                    "is_dotnet": _boolean(pe.get("is_dotnet")),
                    "is_go": _boolean(pe.get("is_go")),
                    "classification": _code(pe.get("classification")) if pe else None,
                    "imports": _integer(pe.get("imports")),
                    "sections": section_records,
                    "packer_markers": sorted({_code(item) for item in markers}) if isinstance(markers, list) else [],
                    "overlay_size": _integer(pe.get("overlay_size")),
                    "containerized": _boolean(pe.get("containerized")),
                } if pe else None,
                "elf": {"bits": _integer(elf.get("bits")), "byte_order": _code(elf.get("byte_order")), "machine": _integer(elf.get("machine")), "load_segments": segment_records} if elf else None,
            }
        )
    digests = {item["sha256"] for item in records}
    if len(digests) != len(records):
        raise StaticCohortReportError("static layer SHA-256が重複しています")
    if set(step_by_sha) - digests:
        raise StaticCohortReportError("static stepがlayer一覧に存在しないSHA-256を参照しています")
    if any(item["parent_sha256"] is not None and item["parent_sha256"] not in digests for item in records):
        raise StaticCohortReportError("static layerの親が同case内に存在しません")
    if records:
        roots = [item for item in records if item["parent_sha256"] is None]
        if len(roots) != 1:
            raise StaticCohortReportError("static layerは一意なrootを持つ必要があります")
        root = roots[0]
        if root["depth"] != 0:
            raise StaticCohortReportError("static layer rootのdepthが0ではありません")
        if expected_root_sha256 is not None and root["sha256"] != expected_root_sha256:
            raise StaticCohortReportError("static layer rootのSHA-256がcase identityと一致しません")
        if isinstance(generic, Mapping) and generic.get("sha256") is not None and generic.get("sha256") != root["sha256"]:
            raise StaticCohortReportError("generic構造のSHA-256がstatic layer rootと一致しません")
        by_digest = {item["sha256"]: item for item in records}
        for item in records:
            parent = item["parent_sha256"]
            if parent is None:
                continue
            if item["depth"] is None or by_digest[parent]["depth"] is None or item["depth"] != by_digest[parent]["depth"] + 1:
                raise StaticCohortReportError("static layerのdepthが親と整合しないかcycleがあります")
    return {
        "availability": "sealed_artifact" if layers is not None else "not_available",
        "root_type": _code(generic.get("type")) if isinstance(generic, Mapping) else "unrecognized",
        "layer_count": len(records),
        "layers": records,
        "format_counts": dict(sorted(Counter(item["format"] for item in records).items())),
        "transform_counts": dict(sorted(Counter(item["transform"] for item in records).items())),
        "raw_layer_names_included": False,
    }


def _endpoint(item: Any, *, source: str, qualified: bool) -> dict[str, Any] | None:
    """封印された意味endpointだけを再無害化する。汎用文字列候補は読まない。"""
    if isinstance(item, str):
        value = orchestration_outcome._endpoint_from_text(item)
        role = "unresolved"
    elif isinstance(item, Mapping):
        text = next((item[key] for key in ("endpoint", "url", "uri", "address", "value") if isinstance(item.get(key), str)), None)
        value = orchestration_outcome._endpoint_from_text(text) if text is not None else None
        if value is None and isinstance(item.get("host"), str):
            host = orchestration_outcome._valid_host(item["host"])
            port = item.get("port")
            if host is not None and (port is None or type(port) is int and 1 <= port <= 65535):
                value = {
                    "host": host,
                    "port": port,
                    "scheme": item.get("scheme") if item.get("scheme") in {"http", "https", "ftp", "tcp", "udp"} else None,
                    "path": orchestration_outcome._sanitize_url_path(item.get("path", "")) if isinstance(item.get("path", ""), str) else None,
                }
        role = _code(item.get("role"), "unresolved").casefold()
    else:
        return None
    if value is None:
        return None
    control = role in CONTROL_ROLES and not any(token in role for token in NON_CONTROL_TOKENS)
    return {
        **value,
        "role": role,
        "source": source,
        "source_record_sha256": _digest(item),
        "evidence_level": "qualified_static_c2" if qualified and control else "qualified_static_non_c2" if qualified else "candidate_only",
        "is_c2_static": qualified and control,
        "c2_protocol_confirmed_by_reporter": False,
        "liveness_confirmed": False,
    }


def _network(orchestration: Mapping[str, Any], c2_document: Mapping[str, Any] | None, digest: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    rejected = 0
    for output_name in ("outputs", "candidate_outputs"):
        outputs = orchestration.get(output_name, {})
        if not isinstance(outputs, Mapping):
            raise StaticCohortReportError("orchestration outputsがobjectではありません")
        for field in ("network_endpoints", "qualified_network_endpoints"):
            items = outputs.get(field, [])
            if not isinstance(items, list):
                raise StaticCohortReportError("orchestration endpoint一覧が配列ではありません")
            for item in items:
                record = _endpoint(item, source=f"orchestration.{output_name}.{field}", qualified=output_name == "outputs" and field == "qualified_network_endpoints")
                if record is None:
                    rejected += 1
                else:
                    records.append(record)
    validation = None
    outcome = "not_available"
    protocol_status = "not_available"
    if c2_document is not None:
        validation = c2_analysis_contract.validate_contract(c2_document, digest)
        if not validation.get("daily_ready"):
            raise StaticCohortReportError("sealed C2契約が有効な途中または完了状態ではありません")
        c2 = c2_document.get("c2", {})
        c2 = c2 if isinstance(c2, Mapping) else {}
        outcome = _code(c2.get("outcome"))
        protocol = c2.get("protocol", {})
        protocol_status = _code(protocol.get("status")) if isinstance(protocol, Mapping) else "unrecognized"
        items = c2.get("endpoints", [])
        if not isinstance(items, list):
            raise StaticCohortReportError("sealed C2契約のendpoint一覧が配列ではありません")
        for item in items:
            record = _endpoint(item, source="c2-analysis.c2.endpoints", qualified=False)
            if record is None:
                rejected += 1
            else:
                records.append(record)
    return {
        "endpoints": records,
        "endpoint_record_count": len(records),
        "rejected_endpoint_record_count": rejected,
        "qualified_static_c2_count": len({_digest({key: item[key] for key in ("host", "port", "scheme", "path")}) for item in records if item["is_c2_static"]}),
        "reported_c2_outcome": outcome,
        "reported_protocol_status": protocol_status,
        "c2_contract_complete": bool(validation and validation.get("complete")),
        "confirmation_performed_by_reporter": False,
        "generic_string_iocs_included": False,
    }


def _stage_locators(case_dir: Path, report: Mapping[str, Any], budget: corpus._ReadBudget) -> list[dict[str, Any]]:
    """成功handlerが明示した非C2配布先を、raw configと分離して保持する。"""
    records = []
    for execution in report.get("handler_executions", []):
        if not isinstance(execution, Mapping) or execution.get("status") != "succeeded":
            continue
        relative = execution.get("result")
        if not isinstance(relative, str):
            continue
        wrapper = _artifact(case_dir, report, relative, budget)
        if wrapper is None:
            raise StaticCohortReportError("成功handlerの結果がreportへ封印されていません")
        if wrapper.get("executed_sample") is not False or wrapper.get("network_contacted") is not False:
            raise StaticCohortReportError("handler結果の非実行・非通信契約が不正です")
        result = wrapper.get("result")
        config = result.get("config") if isinstance(result, Mapping) else None
        locators = config.get("stage_locators", []) if isinstance(config, Mapping) else []
        if not isinstance(locators, list):
            raise StaticCohortReportError("stage locator一覧が配列ではありません")
        for locator in locators:
            if not isinstance(locator, Mapping) or locator.get("c2_confirmation") is not False:
                continue
            role = locator.get("role")
            if role not in {"payload_delivery", "stage_download", "dead_drop", "shared_resolver"}:
                continue
            projected = _endpoint(locator, source="handler.config.stage_locators", qualified=False)
            if projected is not None:
                records.append(projected)
    return records


def _next_action(case: Mapping[str, Any]) -> tuple[str, str]:
    if case["network"]["qualified_static_c2_count"]:
        return "P1", "終端通信関数と設定decoderの対応、protocol根拠を追加確認する。"
    if case["config"]["candidate_only"]:
        return "P1", "候補設定の独立detector根拠と同一layer上の通信処理を確認する。"
    if case["structure"]["layer_count"] > 1:
        return "P1", "復元済み最深layerのfamily設定と通信処理を静的に確認する。"
    return "P2", "未対応container、復号処理、または完全SHA-256一致の既存公開成果物を確認する。"


def _provider(metadata: Mapping[str, Any]) -> dict[str, Any]:
    first_seen = metadata.get("first_seen")
    return {
        "family_label": _safe_label(metadata.get("signature")),
        "family_confirmation": False,
        "file_type": _code(metadata.get("file_type")),
        "first_seen": first_seen if isinstance(first_seen, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", first_seen) else None,
    }


def _metadata_and_acquired(
    manifest: Mapping[str, Any], selection: partitioner.FixedSelection, *, allow_incomplete: bool
) -> tuple[dict[str, Mapping[str, Any]], set[str]]:
    """未取得を選定から除外せず、取得済みsubsetだけを固定metadataへ照合する。"""
    items = manifest.get("items")
    if not isinstance(items, list):
        raise StaticCohortReportError("取得itemsが配列ではありません")
    metadata = {item["sha256_hash"]: item for item in manifest["selected_metadata"]}
    acquired = [item.get("sha256") if isinstance(item, Mapping) else None for item in items]
    if any(not isinstance(digest, str) for digest in acquired) or len(set(acquired)) != len(acquired) or any(digest not in metadata for digest in acquired):
        raise StaticCohortReportError("取得済みsubsetに重複または選定外caseがあります")
    expected_order = [digest for digest in selection.hashes if digest in acquired]
    if acquired != expected_order:
        raise StaticCohortReportError("取得済みsubsetの順序が固定選定と一致しません")
    complete = manifest.get("complete")
    if type(complete) is not bool:
        raise StaticCohortReportError("取得completeがboolではありません")
    if complete and len(acquired) != len(selection.hashes):
        raise StaticCohortReportError("complete取得manifestに欠落があります")
    if not allow_incomplete and (not complete or len(acquired) != len(selection.hashes)):
        raise StaticCohortReportError("固定選定が期待件数の完全取得状態ではありません")
    if acquired:
        subset = {
            "selected_hashes": acquired,
            "selected_metadata": [metadata[digest] for digest in acquired],
            "items": items,
        }
        validate_item_metadata_binding(subset, expected_hashes=acquired)
    return metadata, set(acquired)


def _accepted_runs(
    roots: Sequence[Path], selected: set[str], budget: corpus._ReadBudget, *, allow_incomplete: bool
) -> tuple[list[Path], list[dict[str, Any]], dict[str, str]]:
    """失敗・実行途中のproduction jobを成果物採用前に除外する。"""
    accepted = []
    excluded = []
    unavailable: dict[str, str] = {}
    for ordinal, root in enumerate(roots):
        status_path = root.parent / "status.json"
        if not status_path.exists():
            accepted.append(root)
            continue
        status, status_raw = corpus._read_json_snapshot(status_path, budget, error_prefix="production_job_status")
        state = _code(status.get("state"))
        result_path = root.parent / "result.json"
        result = None
        if result_path.exists():
            result, _ = corpus._read_json_snapshot(result_path, budget, error_prefix="production_job_result")
        valid = state in {"completed", "completed_partial"} and status.get("terminal") is True and isinstance(result, Mapping) and result.get("accepted") is True
        if valid:
            accepted.append(root)
            continue
        if not allow_incomplete:
            raise StaticCohortReportError("失敗または未完了のproduction jobは採用できません")
        request, request_raw = corpus._read_json_snapshot(root.parent / "request.json", budget, error_prefix="excluded_job_request")
        inputs = request.get("inputs")
        if not isinstance(inputs, list) or not inputs or any(not isinstance(value, str) or value not in selected for value in inputs) or len(set(inputs)) != len(inputs):
            raise StaticCohortReportError("除外jobの入力が固定選定の一意subsetではありません")
        reason = "analysis_job_failed" if status.get("terminal") is True else "analysis_job_not_finished"
        for digest in inputs:
            unavailable[digest] = reason
        excluded.append({"run_ordinal": ordinal, "state": state, "reason": reason, "selected_inputs": inputs, "status_sha256": hashlib.sha256(status_raw).hexdigest(), "request_sha256": hashlib.sha256(request_raw).hexdigest(), "analysis_artifacts_adopted": False})
    return accepted, excluded, unavailable


def _unavailable_case(
    digest: str, metadata: Mapping[str, Any], *, acquired: bool, reason: str
) -> dict[str, Any]:
    """取得・解析の欠落を明記し、provider metadataだけで構造やfamilyを補わない。"""
    return {
        "selection_sha256": digest,
        "case_sha256": digest,
        "case_sha256_verified_by_analysis": False,
        "acquired": acquired,
        "analysis_present": False,
        "unavailable_reason": reason,
        "provider": _provider(metadata),
        "family": {"selected_families": [], "resolution_status": "unresolved", "resolved_family": None},
        "config": {"status": "not_available", "confirmed_recovered": False, "candidate_only": False},
        "case_state": "not_analyzed",
        "analysis_complete": False,
        "handler_status_counts": {},
        "automation_gap": {"status": "not_available", "reason": reason},
        "failure_reason_codes": [reason],
        "diagnostic_reason_codes": [],
        "root_terminal_payload": {"status": "not_available", "reason": reason, "reached": None, "terminal_status": None},
        "structure": _structure(None, None),
        "network": {"endpoints": [], "endpoint_record_count": 0, "rejected_endpoint_record_count": 0, "qualified_static_c2_count": 0, "reported_c2_outcome": "not_available", "reported_protocol_status": "not_available", "c2_contract_complete": False, "confirmation_performed_by_reporter": False, "generic_string_iocs_included": False, "stage_locators": [], "stage_locator_count": 0},
        "integrity": {"report_semantic_seal_verified": False, "all_manifest_artifact_hashes_verified": False},
        "followup": {"required": True, "priority": "P0", "next_minimum_step_ja": "固定選定を変更せず取得を再開する。" if not acquired else "容量・失敗理由を解消し、同じ検体をproduction静的解析へ再入力する。"},
    }


def build_report(
    selection_manifest: Path, runs: Sequence[Path], *, expected_count: int = 100, allow_incomplete_collection: bool = False
) -> dict[str, Any]:
    """固定選定全件を封印済みrootへ一意に対応させ、非公開集計を返す。"""
    if type(expected_count) is not int or not 1 <= expected_count <= 200:
        raise StaticCohortReportError("expected countは1..200で指定してください")
    if type(allow_incomplete_collection) is not bool or not 0 <= len(runs) <= 4 or (not runs and not allow_incomplete_collection):
        raise StaticCohortReportError("通常集計は1～4 run、不完全集計は0～4 runで指定してください")
    budget = corpus._ReadBudget()
    manifest, manifest_raw = corpus._read_json_snapshot(selection_manifest, budget, error_prefix="selection_manifest")
    selection = partitioner.validate_fixed_selection(manifest)
    if len(selection.hashes) != expected_count:
        raise StaticCohortReportError("固定選定が期待件数と一致しません")
    metadata_by_sha, acquired_set = _metadata_and_acquired(manifest, selection, allow_incomplete=allow_incomplete_collection)
    roots = [corpus._regular_directory(Path(run), code="run_directory_invalid") for run in runs]
    if len(set(roots)) != len(roots):
        raise StaticCohortReportError("同じrunを重複指定できません")
    roots, excluded_runs, unavailable_reasons = _accepted_runs(roots, set(selection.hashes), budget, allow_incomplete=allow_incomplete_collection)
    observations = corpus._selected_root_report_observations(roots, budget)
    by_sha = {item["digest"]: item for item in observations}
    if len(by_sha) != len(observations):
        raise StaticCohortReportError("runをまたいで同じcase SHA-256が重複しています")
    registry, _ = corpus._read_json_snapshot(corpus.FAMILY_REGISTRY_PATH, budget, error_prefix="family_registry")
    registered = corpus._registered_family_ids(registry)
    audit_by_sha: dict[str, dict[str, Any]] = {}
    used_cases: set[str] = set()
    selected_set = set(selection.hashes)
    for observation in observations:
        matches = selected_set & {observation["digest"], observation["outer_sha256"]}
        if len(matches) > 1:
            raise StaticCohortReportError("1 caseが複数の固定選定SHA-256へ一致しています")
        if not matches:
            continue
        selected_sha = next(iter(matches))
        if selected_sha in audit_by_sha or observation["digest"] in used_cases:
            raise StaticCohortReportError("固定選定とcaseの対応が一意ではありません")
        terminal = corpus._root_terminal_record(observation, budget)
        audit_by_sha[selected_sha] = {
            "case_sha256": observation["digest"],
            "root_terminal_payload": {key: value for key, value in terminal.items() if not key.startswith("_")},
        }
        used_cases.add(observation["digest"])
    if not allow_incomplete_collection and set(audit_by_sha) != selected_set:
        raise StaticCohortReportError("固定選定SHA-256のroot caseが不足しています")
    if not set(audit_by_sha) <= acquired_set:
        raise StaticCohortReportError("未取得の検体へ解析結果が結び付けられています")
    summary_roots: set[str] = set()
    summary_derived: set[str] = set()
    for root in roots:
        summary, _ = corpus._read_json_snapshot(root / "summary.json", budget, error_prefix="run_summary")
        validated = corpus._validate_run_summary(summary)
        if validated["errors"] or validated["duplicates"]:
            raise StaticCohortReportError("runにerrorまたはduplicateがあります")
        for digest in validated["cases"]:
            if digest in summary_roots:
                raise StaticCohortReportError("run summary間でroot caseが重複しています")
            summary_roots.add(digest)
        derived = summary.get("derived_cases", [])
        if not isinstance(derived, list):
            raise StaticCohortReportError("derived case一覧が配列ではありません")
        for item in derived:
            digest = item.get("sha256") if isinstance(item, Mapping) else None
            if not isinstance(digest, str) or corpus.SHA256_RE.fullmatch(digest) is None or digest in summary_derived:
                raise StaticCohortReportError("derived case identityが不正または重複しています")
            summary_derived.add(digest)
    if summary_roots != used_cases:
        raise StaticCohortReportError("run summaryのroot集合と固定選定のroot集合が一致しません")
    if set(by_sha) - used_cases != summary_derived or summary_derived & used_cases:
        raise StaticCohortReportError("case treeに未申告の選定外caseまたはrootとのderived衝突があります")
    cases = []
    for selected_sha in selection.hashes:
        if selected_sha not in audit_by_sha:
            acquired = selected_sha in acquired_set
            cases.append(_unavailable_case(selected_sha, metadata_by_sha[selected_sha], acquired=acquired, reason="sample_not_acquired" if not acquired else unavailable_reasons.get(selected_sha, "analysis_not_started")))
            continue
        audited = audit_by_sha[selected_sha]
        observation = by_sha[audited["case_sha256"]]
        case_dir, report = observation["case_dir"], observation["report"]
        errors = analysis_contract.verify_artifact_hashes(case_dir, report["artifact_sha256"])
        if errors:
            raise StaticCohortReportError("case封印成果物のSHA-256検証に失敗しました")
        base = corpus._case_record(observation["run_root"], observation["digest"], budget, expected_family=None, registered_families=registered)
        orchestration = _artifact(case_dir, report, "orchestration.json", budget)
        if orchestration is None:
            raise StaticCohortReportError("封印済みorchestrationがありません")
        structure = _structure(_artifact(case_dir, report, "static-layers.json", budget), _artifact(case_dir, report, "generic-triage.json", budget), expected_root_sha256=observation["digest"])
        provider = metadata_by_sha[selected_sha]
        record = {
            "selection_sha256": selected_sha,
            "case_sha256": observation["digest"],
            "case_sha256_verified_by_analysis": True,
            "acquired": True,
            "analysis_present": True,
            "unavailable_reason": None,
            "provider": _provider(provider),
            "family": base["family"],
            "config": base["config"],
            "case_state": base["case_state"],
            "analysis_complete": False,
            "handler_status_counts": base["handler_status_counts"],
            "automation_gap": base["automation_gap"],
            "failure_reason_codes": base["failure_reason_codes"],
            "diagnostic_reason_codes": base["diagnostic_reason_codes"],
            "root_terminal_payload": audited["root_terminal_payload"],
            "structure": structure,
            "network": _network(orchestration, _artifact(case_dir, report, "c2-analysis.json", budget), observation["digest"]),
            "integrity": {"report_semantic_seal_verified": True, "all_manifest_artifact_hashes_verified": True, "report_sha256": observation["report_sha256"], "artifact_sha256": dict(sorted(report["artifact_sha256"].items()))},
        }
        record["network"]["stage_locators"] = _stage_locators(case_dir, report, budget)
        record["network"]["stage_locator_count"] = len(record["network"]["stage_locators"])
        record["analysis_complete"] = (
            base["case_state"] == "complete"
            and record["network"]["c2_contract_complete"]
            and record["root_terminal_payload"]["reached"] is True
        )
        priority, next_step = _next_action(record)
        record["followup"] = {"required": not record["analysis_complete"], "priority": priority, "next_minimum_step_ja": next_step}
        cases.append(record)
    clusters: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        if not case["analysis_present"]:
            continue
        structure = case["structure"]
        axes = {"root_type": structure["root_type"], "formats": structure["format_counts"], "transforms": structure["transform_counts"], "pe_shapes": [{key: layer["pe"].get(key) for key in ("machine", "is_dotnet", "is_go", "classification", "imports", "sections", "packer_markers")} for layer in structure["layers"] if layer["pe"]], "elf_shapes": [layer["elf"] for layer in structure["layers"] if layer["elf"]]}
        identity = _digest(axes)
        case["structure"]["exact_shape_sha256"] = identity
        clusters[identity].append(case["case_sha256"])
    for observation in observations:
        _, raw_after = corpus._read_json_snapshot(observation["report_path"], budget, error_prefix="report_recheck")
        if hashlib.sha256(raw_after).hexdigest() != observation["report_sha256"]:
            raise StaticCohortReportError("集計中にcase reportが変化しました")
    _, manifest_after = corpus._read_json_snapshot(selection_manifest, budget, error_prefix="selection_manifest_recheck")
    if manifest_after != manifest_raw:
        raise StaticCohortReportError("集計中に固定選定manifestが変化しました")
    acquisition_incomplete = manifest.get("complete") is not True
    analysis_incomplete = len(audit_by_sha) != expected_count or bool(excluded_runs)
    incomplete = acquisition_incomplete or analysis_incomplete
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "incomplete" if incomplete else "complete" if all(case["analysis_complete"] for case in cases) else "processed_followup_required",
        "complete": not incomplete and all(case["analysis_complete"] for case in cases),
        "scope": {"expected_count": expected_count, "selected_count": len(cases), "run_count": len(roots), "root_cases_only": True, "out_of_scope_derived_case_count": len(observations) - len(audit_by_sha), "selection_mode": selection.selection_mode, "incomplete_collection_opt_in": allow_incomplete_collection},
        "coverage": {"selected": expected_count, "acquired": len(acquired_set), "pending_acquisition": expected_count - len(acquired_set), "analyzed": len(audit_by_sha), "pending_analysis": expected_count - len(audit_by_sha), "known_c2_evaluation_case_count": sum(case["network"]["reported_c2_outcome"] != "not_available" for case in cases), "unavailable_reason_counts": dict(sorted(Counter(case["unavailable_reason"] for case in cases if not case["analysis_present"]).items()))},
        "excluded_runs": excluded_runs,
        "commitments": {"selection_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(), "selection_commitment_sha256": selection.selection_commitment_sha256, "case_records_sha256": _digest(cases)},
        "metrics": {
            "provider_family_labels": dict(sorted(Counter(case["provider"]["family_label"]["value"] or "unlabeled_or_redacted" for case in cases).items())),
            "provider_file_types": dict(sorted(Counter(case["provider"]["file_type"] for case in cases).items())),
            "resolved_families": dict(sorted(Counter(case["family"]["resolved_family"] for case in cases if case["family"]["resolution_status"] == "resolved").items())),
            "family_resolved_count": sum(case["family"]["resolution_status"] == "resolved" for case in cases),
            "config_confirmed_count": sum(case["config"]["confirmed_recovered"] for case in cases),
            "config_candidate_only_count": sum(case["config"]["candidate_only"] for case in cases),
            "qualified_static_c2_case_count": sum(case["network"]["qualified_static_c2_count"] > 0 for case in cases),
            "c2_contract_complete_count": sum(case["network"]["c2_contract_complete"] for case in cases),
            "stage_locator_case_count": sum(case["network"]["stage_locator_count"] > 0 for case in cases),
            "terminal_reached_count": sum(case["root_terminal_payload"]["reached"] is True for case in cases),
            "complete_count": sum(case["analysis_complete"] for case in cases),
            "case_state_counts": dict(sorted(Counter(case["case_state"] for case in cases).items())),
            "structural_layer_count": sum(case["structure"]["layer_count"] for case in cases),
        },
        "structure_clusters": [{"exact_shape_sha256": key, "case_count": len(values), "case_sha256": sorted(values), "family_attribution_allowed": False, "campaign_attribution_allowed": False} for key, values in sorted(clusters.items())],
        "cases": cases,
        "evidence_boundaries": {"provider_label_is_family_confirmation": False, "config_candidate_is_confirmed_config": False, "payload_delivery_is_c2": False, "static_c2_extraction_is_liveness": False, "reporter_performs_confirmation": False, "structure_cluster_is_family_or_campaign": False},
        "safety": {"sample_opened": False, "sample_executed": False, "network_contacted": False, "subprocess_started": False, "raw_config_included": False, "credentials_included": False, "private_paths_included": False},
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    """全caseの主結果を日本語Markdownへ出し、詳細JSONの保持を明示する。"""
    metrics = report["metrics"]
    coverage = report["coverage"]
    lines = ["# 固定選定検体の静的解析集計", "", f"状態: `{report['status']}`。対象は{report['scope']['selected_count']}件。検体実行と外部通信は行っていません。", "", "## 取得・解析カバレッジ", "", f"- 固定選定: {coverage['selected']}件", f"- 取得済み: {coverage['acquired']}件、未取得: {coverage['pending_acquisition']}件", f"- 採用可能な解析: {coverage['analyzed']}件、解析未取得: {coverage['pending_analysis']}件", "", "未取得・未解析はC2なしではありません。以下の成功件数は採用できた解析成果物だけを対象とし、固定選定の母数を減らしていません。", "", "## 集計", "", f"- 静的family解決: {metrics['family_resolved_count']}件", f"- 設定復元: {metrics['config_confirmed_count']}件、候補のみ: {metrics['config_candidate_only_count']}件", f"- qualified static C2抽出case: {metrics['qualified_static_c2_case_count']}件", f"- C2契約上の完了: {metrics['c2_contract_complete_count']}件", f"- 終端payload到達: {metrics['terminal_reached_count']}件", f"- 検体単位の完了: {metrics['complete_count']}件", "", "provider label、配布URL、静的C2、protocol確認、生存確認は別の証拠です。本集計は再確認を行わず、sealとhashが一致する成果物から投影しています。", "", "## 検体別結果", "", "| SHA-256 | provider label | 静的family | 設定 | 静的C2数 | 構造layer数 | 状態 |", "|---|---|---|---|---:|---:|---|"]
    for case in report["cases"]:
        label = case["provider"]["family_label"]["value"] or "未ラベル"
        family = case["family"]["resolved_family"] or "未解決"
        lines.append(f"| `{case['case_sha256']}` | {label} | {family} | `{case['config']['status']}` | {case['network']['qualified_static_c2_count']} | {case['structure']['layer_count']} | `{case['case_state']}` |")
    lines.extend(["", "全件のlayer、変換、endpointの役割・確度、blocker、次の最小手順、artifact hashは同じdirectoryの`summary.json`へ保持しています。Markdownの要約によって取得済みJSON記録を切り捨てません。", "", "## 安全境界", "", "- 検体本体を読み込まず、封印された解析JSONだけを集計します。", "- family label単独、構造cluster単独、配布URLだけでfamilyまたはC2を確定しません。", "- URLのuserinfo、query、fragment、秘密値様pathを再無害化します。", "- 出力はrepository外に限定します。公開case生成器、完了validator、ライブ確認の代替には使用しません。", ""])
    return "\n".join(lines)


def write_report(output_directory: Path, report: Mapping[str, Any], *, runs: Sequence[Path], selection_manifest: Path) -> None:
    """入力を上書きせず、repository外へJSONと日本語Markdownをatomic出力する。"""
    destination = output_directory.resolve()
    if destination == REPOSITORY_ROOT or REPOSITORY_ROOT in destination.parents:
        raise StaticCohortReportError("非公開集計の出力先はrepository外に限定します")
    for root in [*(Path(run).resolve() for run in runs), selection_manifest.resolve().parent]:
        if destination == root or root in destination.parents:
            raise StaticCohortReportError("入力runまたは取得source内へ集計を出力できません")
    corpus._validate_output_paths([destination / "summary.json", destination / "REPORT.md"], runs, additional_inputs=[selection_manifest])
    corpus._atomic_write_text(destination / "summary.json", json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
    corpus._atomic_write_text(destination / "REPORT.md", render_markdown(report))


def main(argv: list[str] | None = None) -> int:
    """固定選定と最大4 runを受け、検証後だけ非公開集計を生成する。"""
    parser = partitioner.JapaneseArgumentParser(description=__doc__)
    parser.add_argument("--selection-manifest", required=True, type=Path, help="完全取得済みの固定選定manifest。")
    parser.add_argument("--run", action="append", type=Path, default=[], help="production jobのanalysis directory。最大4回。")
    parser.add_argument("--expected-count", type=int, default=100, help="期待する固定選定件数。既定100、最大200。")
    parser.add_argument("--output-directory", required=True, type=Path, help="repository外の新しい集計directory。")
    parser.add_argument("--allow-incomplete-collection", action="store_true", help="未取得・未解析を明示し固定選定全件をincompleteとして集計する。既定では拒否する。")
    args = parser.parse_args(argv)
    if len(args.run) > 4 or (not args.run and not args.allow_incomplete_collection):
        parser.error("通常集計は1～4 run、不完全集計は0～4 runで指定してください")
    try:
        report = build_report(args.selection_manifest, args.run, expected_count=args.expected_count, allow_incomplete_collection=args.allow_incomplete_collection)
        write_report(args.output_directory, report, runs=args.run, selection_manifest=args.selection_manifest)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "rejected", "error_type": type(exc).__name__}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "complete": report["complete"], "scope": report["scope"], "coverage": report["coverage"], "metrics": report["metrics"]}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
