#!/usr/bin/env python3
"""監査済みmetadataから、人間レビュー必須の有界再解析候補だけを純粋に計画する。"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Mapping

COMMON = Path(__file__).resolve().parent
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import automation_failure_inventory as inventory
import remediation_registry as registry

SCHEMA_VERSION = 1
PLAN_TYPE = "review_only_automation_reanalysis_plan"
MAX_CANDIDATES = 64
MAX_REPAIRS = 128
MAX_REASONS = 128
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_INPUT_NODES = 2_000_000
MAX_CASE_NODES = 20_000
MAX_CASE_TEXT_BYTES = 256 * 1024
CASE_KEYS = frozenset({"sha256", "catalog_family", "record_valid", "recorded_case_state",
    "metadata_findings", "blockers", "improvement_actions", "config", "url_role_counts",
    "c2_recorded_outcome", "c2_metadata_contract_complete", "fingerprints", "automatic_retry_allowed",
    "change_decision", "changed_dimensions"})
TOP_KEYS = frozenset({"schema_version", "inventory_type", "catalog_sha256", "scope",
    "full_artifact_seals_verified", "sample_bytes_read", "network_contacted", "automatic_dispatch_allowed",
    "coverage", "recorded_case_state_counts", "metadata_finding_case_counts", "blocker_case_counts",
    "improvement_priorities", "family_coverage", "change_decision_counts", "url_role_counts", "limits",
    "cases", "inventory_sha256"})
FINGERPRINTS = frozenset({"implementation_contract", "input", "evidence"})
HISTORY_KEYS = frozenset({"change_decision", "changed_dimensions"})


class ReanalysisPlanError(ValueError):
    """検証失敗を、入力値を含まない固定error codeで表す。"""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReanalysisPlanError(code)


def _strings(value: Any) -> bool:
    return (isinstance(value, list) and len(value) <= MAX_REASONS and
        all(isinstance(item, str) and len(item) <= 255 for item in value) and value == sorted(set(value)))


def _bounded_shape(value: Any, *, max_nodes: int = MAX_INPUT_NODES,
                   max_text_bytes: int = MAX_INPUT_BYTES, check=None) -> None:
    _require(type(max_nodes) is int and 1 <= max_nodes <= MAX_INPUT_NODES and
        type(max_text_bytes) is int and 1 <= max_text_bytes <= MAX_INPUT_BYTES,
        "input_structure_profile_invalid")
    pending, observed, text_bytes = [(value, 0)], 0, 0
    def count_text(text: str) -> int:
        _require(len(text) <= max_text_bytes, "input_string_limit")
        try:
            return len(text.encode("utf-8"))
        except UnicodeError as exc:
            raise ReanalysisPlanError("input_text_invalid") from exc
    while pending:
        item, depth = pending.pop()
        observed += 1
        if check is not None and observed % 1024 == 0:
            check()
        _require(observed <= max_nodes and depth <= inventory.MAX_DEPTH, "input_structure_limit")
        _require(type(item) in {dict, list, str, int, float, bool, type(None)}, "input_value_type_invalid")
        if isinstance(item, float):
            _require(math.isfinite(item), "input_nonfinite_number")
        if isinstance(item, (dict, list)):
            _require(len(item) + len(pending) + observed <= max_nodes, "input_structure_limit")
            if isinstance(item, dict):
                _require(all(type(key) is str for key in item), "input_key_invalid")
                text_bytes += sum(count_text(key) for key in item)
                children = item.values()
            else:
                children = item
            pending.extend((child, depth + 1) for child in children)
        elif isinstance(item, str):
            text_bytes += count_text(item)
        elif type(item) is int:
            _require(item.bit_length() <= 128, "input_integer_limit")
        _require(text_bytes <= max_text_bytes, "input_text_bytes_limit")


def _estimate_json_tokens(raw: bytes, check) -> None:
    # decoderのallocation前に、keyを含むJSON token開始数を保守的に上限確認する。
    in_string = escaped = primitive = False
    count = 0
    for offset, byte in enumerate(raw):
        if offset % 65536 == 0:
            check()
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
            continue
        if byte == 34:
            count += 1
            in_string, primitive = True, False
        elif byte in (123, 91):
            count += 1
            primitive = False
        elif byte in (125, 93, 58, 44, 32, 9, 10, 13):
            primitive = False
        elif not primitive:
            count += 1
            primitive = True
        _require(count <= MAX_INPUT_NODES, "input_preallocation_token_limit")


class _InputSnapshot:
    def __init__(self, path: Path):
        self.path = path.absolute()
        self.guard = inventory._Reader(self.path.parent, max_files=2,
            max_bytes=2 * MAX_INPUT_BYTES, seconds=inventory.MAX_SECONDS)
        self.identity = None
        self.digest = None

    def _raw(self) -> bytes:
        guard = self.guard
        guard._check()
        _require(guard.files < 2, "input_snapshot_read_count_limit")
        guard._ancestors(self.path.parent)
        before = inventory._io(self.path).lstat()
        _require(not inventory._linked(before) and stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "input_snapshot_file_unsafe")
        _require(before.st_size <= MAX_INPUT_BYTES and guard.used + before.st_size <= 2 * MAX_INPUT_BYTES,
            "input_snapshot_bytes_limit")
        if self.identity is not None:
            _require(inventory._identity(before) == self.identity, "input_snapshot_changed")
        chunks, size = [], 0
        with inventory._io(self.path).open("rb") as stream:
            opened = os.fstat(stream.fileno())
            _require(inventory._identity(before)[:-1] == inventory._identity(opened)[:-1], "input_snapshot_changed")
            while True:
                guard._check()
                chunk = stream.read(min(65536, MAX_INPUT_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                _require(size <= MAX_INPUT_BYTES and guard.used + size <= 2 * MAX_INPUT_BYTES,
                    "input_snapshot_bytes_limit")
                chunks.append(chunk)
            _require(inventory._identity(opened) == inventory._identity(os.fstat(stream.fileno())),
                "input_snapshot_changed")
        _require(size == before.st_size and inventory._identity(before) ==
            inventory._identity(inventory._io(self.path).lstat()), "input_snapshot_changed")
        guard._ancestors(self.path.parent)
        guard.used += size
        guard.files += 1
        if self.identity is None:
            # 検証済みlstat identityを固定し、read終了後の別lstatとのraceを作らない。
            self.identity = inventory._identity(before)
        guard._check()
        return b"".join(chunks)

    def read(self) -> dict[str, Any]:
        _require(self.identity is None, "input_snapshot_read_count_limit")
        raw = self._raw()
        self.digest = hashlib.sha256(raw).hexdigest()
        _estimate_json_tokens(raw, self.guard._check)
        self.guard._check()
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=inventory._pairs,
                parse_constant=inventory._constant)
        except (UnicodeError, ValueError, RecursionError, inventory.InventoryError) as exc:
            raise ReanalysisPlanError("input_json_invalid") from exc
        self.guard._check()
        _require(isinstance(value, dict), "inventory_schema_invalid")
        _bounded_shape(value, check=self.guard._check)
        self.guard._check()
        return value

    def verify(self) -> None:
        _require(self.identity is not None and self.digest is not None, "input_snapshot_not_read")
        raw = self._raw()
        _require(hashlib.sha256(raw).hexdigest() == self.digest, "input_snapshot_changed")
        # 専用input profileの再読込を終えてから、共用readerのdirectory snapshotも再検証する。
        # guardにはfile snapshotを登録しないため、旧8 MiB profileでの再読込は発生しない。
        self.guard.verify()
        self.guard._check()


def _plan_limits(max_candidates: int, max_repairs: int) -> None:
    _require(type(max_candidates) is int and 1 <= max_candidates <= MAX_CANDIDATES and
        type(max_repairs) is int and 1 <= max_repairs <= MAX_REPAIRS, "plan_limits_invalid")


def _validate_inventory(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    _require(type(document) is dict, "inventory_schema_invalid")
    _bounded_shape(document)
    _require(set(document) == TOP_KEYS, "inventory_schema_invalid")
    _require(type(document["schema_version"]) is int and document["schema_version"] == 1 and
        document["inventory_type"] == inventory.INVENTORY_TYPE and
        document["scope"] == "public_metadata_recorded_status_only", "inventory_schema_invalid")
    _require(all(document[key] is False for key in ("sample_bytes_read", "network_contacted",
        "automatic_dispatch_allowed", "full_artifact_seals_verified")), "inventory_safety_invalid")
    limits = document["limits"]
    _require(isinstance(limits, dict) and set(limits) == {"max_cases", "max_files_including_reverification",
        "max_bytes_including_reverification", "wall_seconds"}, "inventory_limits_invalid")
    try:
        inventory._validate_limits(max_cases=limits["max_cases"], max_files=limits["max_files_including_reverification"],
            max_bytes=limits["max_bytes_including_reverification"], seconds=limits["wall_seconds"])
    except inventory.InventoryError as exc:
        raise ReanalysisPlanError("inventory_limits_invalid") from exc
    try:
        commitment = inventory._hash({key: value for key, value in document.items() if key != "inventory_sha256"})
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReanalysisPlanError("inventory_commitment_invalid") from exc
    _require(document["inventory_sha256"] == commitment, "inventory_commitment_invalid")
    values = document["cases"]
    _require(isinstance(values, list) and len(values) <= limits["max_cases"], "inventory_case_limit_or_structure")
    result = {}
    for row in values:
        _bounded_shape(row, max_nodes=MAX_CASE_NODES, max_text_bytes=MAX_CASE_TEXT_BYTES)
        _require(isinstance(row, dict) and set(row) == CASE_KEYS, "inventory_case_schema_invalid")
        digest = row["sha256"]
        _require(isinstance(digest, str) and inventory.SHA.fullmatch(digest) is not None,
            "inventory_case_identity_invalid")
        _require(digest not in result, "inventory_duplicate_case")
        _require(type(row["record_valid"]) is bool and row["automatic_retry_allowed"] is False,
            "inventory_case_safety_invalid")
        _require(all(_strings(row[key]) for key in ("metadata_findings", "blockers", "improvement_actions",
            "changed_dimensions")), "inventory_case_reason_invalid")
        _require(isinstance(row["change_decision"], str) and
            row["change_decision"] in {"comparison_unknown", "unchanged_no_retry", "successor_review_required"},
            "inventory_history_invalid")
        _require(set(row["changed_dimensions"]) <= FINGERPRINTS, "inventory_history_invalid")
        fingerprints = row["fingerprints"]
        _require(isinstance(fingerprints, dict) and set(fingerprints) == FINGERPRINTS,
            "inventory_fingerprints_invalid")
        _require(all(value is None or isinstance(value, str) and inventory.SHA.fullmatch(value) is not None
            for value in fingerprints.values()), "inventory_fingerprints_invalid")
        _require(isinstance(row["catalog_family"], str) and inventory.ID.fullmatch(row["catalog_family"]) is not None,
            "inventory_family_invalid")
        _require(isinstance(row["recorded_case_state"], str) and row["recorded_case_state"] in
            {"unknown", "complete", "partial", "failed", "triaged_unknown", "assessment_only_complete"},
            "inventory_case_state_invalid")
        _require(type(row["c2_metadata_contract_complete"]) is bool and isinstance(row["c2_recorded_outcome"], str) and
            row["c2_recorded_outcome"] in {"unknown", "invalid", "confirmed", "unresolved", "no_c2_capability_verified"},
            "inventory_c2_state_invalid")
        roles = row["url_role_counts"]
        _require(isinstance(roles, dict) and set(roles) <= set(inventory.URL_ROLES.values()) | {"unknown", "unknown_structure"} and
            all(type(count) is int and 0 <= count <= inventory.MAX_NODES for count in roles.values()),
            "inventory_url_role_counts_invalid")
        config = row["config"]
        _require(isinstance(config, dict) and set(config) == {"status", "required", "recorded_confirmed", "candidate_recorded"},
            "inventory_config_schema_invalid")
        _require((config["required"] is None or type(config["required"]) is bool) and
            type(config["recorded_confirmed"]) is bool and type(config["candidate_recorded"]) is bool and
            isinstance(config["status"], str) and config["status"] in
            {"unknown", "recorded_confirmed", "candidate_only", "required_missing", "not_required"},
            "inventory_config_state_invalid")
        result[digest] = row
    _require(list(result) == sorted(result), "inventory_case_order_invalid")
    return result


def _policies(row: dict[str, Any]) -> tuple[list[tuple[str, registry.PlannerPolicySpec]], bool]:
    result = []
    unknown = False
    for blocker in row["blockers"]:
        policy = registry.planner_policy_for_blocker(blocker)
        # inventoryはdynamic family suffixを除去する。その場合はcatalog identityのfamilyだけで補完する。
        if policy is None and blocker in {"selected_family_has_no_automatic_handler", "selected_family_has_no_valid_handler_evidence"}:
            policy = registry.planner_policy_for_blocker(blocker + ":" + row["catalog_family"])
        if policy is None:
            unknown = True
        else:
            result.append((blocker, policy))
    return sorted(result, key=lambda pair: (pair[1].priority, pair[1].action_id, pair[0])), unknown


def build_plan(document: Mapping[str, Any], current_document: Mapping[str, Any],
               catalog: Mapping[str, Any], *, catalog_sha256: str,
               max_candidates: int = MAX_CANDIDATES, max_repairs: int = MAX_REPAIRS) -> dict[str, Any]:
    """現在の検証済み監査snapshotと一致する記録だけから、実行権限のない候補計画を生成する。"""
    _plan_limits(max_candidates, max_repairs)
    rows = _validate_inventory(document)
    current = _validate_inventory(current_document)
    _bounded_shape(catalog)
    _require(isinstance(catalog, dict) and set(catalog) == {"schema_version", "cases"} and
        type(catalog["schema_version"]) is int and catalog["schema_version"] == 1 and
        isinstance(catalog["cases"], dict) and len(catalog["cases"]) <= inventory.MAX_CASES,
        "catalog_schema_invalid")
    _require(type(catalog_sha256) is str and inventory.SHA.fullmatch(catalog_sha256) is not None,
        "catalog_commitment_invalid")
    _require(document["catalog_sha256"] == catalog_sha256 == current_document["catalog_sha256"],
        "catalog_commitment_mismatch")
    _require(set(rows) == set(current) == set(catalog["cases"]), "catalog_case_set_mismatch")
    _require(all(document[key] == current_document[key] for key in TOP_KEYS -
        {"inventory_sha256", "change_decision_counts", "limits", "cases"}), "inventory_summary_drift")
    candidates, repairs, skipped = [], [], 0
    for digest, row in rows.items():
        identity = catalog["cases"][digest]
        _require(isinstance(identity, dict) and identity.get("case_id") == "sha256:" + digest,
            "catalog_identity_invalid")
        _require(isinstance(identity.get("case_kind"), str), "catalog_identity_invalid")
        if identity["case_kind"] in {"malware", "unclassified"}:
            try:
                _path, family = inventory._case_path(Path("identity-only"), digest, identity)
            except inventory.InventoryError as exc:
                raise ReanalysisPlanError("catalog_identity_invalid") from exc
            _require(row["catalog_family"] == family, "catalog_family_mismatch")
        else:
            _require(row["catalog_family"] == "out_of_scope" and row["record_valid"] is False,
                "catalog_nonmalware_record_invalid")
        # self-hashだけでは認証にならない。現snapshotから独立再投影された全fieldを照合する。
        expected = current[digest]
        _require(inventory._hash({k: v for k, v in row.items() if k not in HISTORY_KEYS}) ==
            inventory._hash({k: v for k, v in expected.items() if k not in HISTORY_KEYS}), "inventory_evidence_drift")
        policies, unknown = _policies(row)
        proof = {"case_id": "sha256:" + digest, "catalog_identity_sha256": inventory._hash({
            key: identity.get(key) for key in ("case_id", "case_kind", "family", "version_key", "canonical_path")}),
            "inventory_case_sha256": inventory._hash(row), "fingerprints": dict(row["fingerprints"])}
        missing_proof = any(value is None for value in row["fingerprints"].values())
        # producerの構造不明countは既知の記録欠落であり、抽出jobへ渡さない。
        url_structure_unknown = row["url_role_counts"].get("unknown_structure", 0) > 0
        if not row["record_valid"] or row["metadata_findings"] or unknown or missing_proof or url_structure_unknown:
            reasons = []
            if not row["record_valid"]:
                reasons.append("record_invalid_or_legacy")
            if row["metadata_findings"]:
                reasons.append("metadata_missing_invalid_or_unbound")
            if url_structure_unknown:
                reasons.append("url_endpoint_structure_unknown")
            if unknown:
                reasons.append("unregistered_blocker_review_required")
            if missing_proof:
                reasons.append("fingerprint_proof_missing")
            repairs.append({"case_sha256": digest, "action_id": "review_machine_readable_blocker",
                "plan_kind": "metadata_repair_review", "priority": 0, "reason_codes": sorted(reasons),
                "proof": proof, "analysis_job_candidate": False, "human_review_required": True,
                "automatic_dispatch_allowed": False})
            continue
        if not policies:
            skipped += 1
            continue
        # 同じaction/phase/証拠前提の重複を除き、最小の次手順から順に並べる。
        actions = {}
        for blocker, policy in policies:
            key = (policy.action_id, policy.target_phase, policy.changed_evidence)
            item = actions.setdefault(key, {"action_id": policy.action_id, "target_phase": policy.target_phase,
                "priority": policy.priority, "required_changed_evidence": list(policy.changed_evidence),
                "blocker_codes": []})
            item["blocker_codes"].append(blocker)
        ordered = sorted(actions.values(), key=lambda item: (item["priority"], item["action_id"], str(item["target_phase"])))
        _require(set(row["improvement_actions"]) == {item["action_id"] for item in ordered},
            "remediation_registry_projection_mismatch")
        candidates.append({"case_sha256": digest, "plan_kind": "static_remediation_candidate",
            "minimum_next_action": ordered[0]["action_id"], "priority": ordered[0]["priority"],
            "actions": ordered, "proof": proof, "decision": "successor_review_required",
            "human_review_required": True, "automatic_dispatch_allowed": False,
            "same_workflow_resume_allowed": False, "automatic_retry_allowed": False,
            "current_implementation_matches_saved_contract_verified": False,
            "reason_codes": ["saved_contract_is_not_current_implementation_proof", "human_review_required"]})
    counts = Counter(item["minimum_next_action"] for item in candidates)
    candidates.sort(key=lambda item: (item["priority"], -counts[item["minimum_next_action"]],
        item["minimum_next_action"], item["case_sha256"]))
    repairs.sort(key=lambda item: item["case_sha256"])
    omitted_candidates, omitted_repairs = candidates[max_candidates:], repairs[max_repairs:]
    result = {"schema_version": SCHEMA_VERSION, "plan_type": PLAN_TYPE, "scope": "metadata_only_review_plan",
        "source_inventory_sha256": document["inventory_sha256"],
        "current_inventory_sha256": current_document["inventory_sha256"], "catalog_sha256": catalog_sha256,
        "human_review_required": True, "job_execution_attempted": False, "sample_bytes_read": False,
        "network_contacted": False, "automatic_dispatch_allowed": False,
        "candidate_count": len(candidates), "repair_record_count": len(repairs), "no_action_record_count": skipped,
        "job_candidates": candidates[:max_candidates], "metadata_repairs": repairs[:max_repairs],
        "omissions": {"candidate_count": len(omitted_candidates), "repair_count": len(omitted_repairs),
            "candidate_sha256": inventory._hash(omitted_candidates), "repair_sha256": inventory._hash(omitted_repairs)},
        "limits": {"max_candidates": max_candidates, "max_repairs": max_repairs},
        "analysis_success_rate_measured": False}
    result["plan_sha256"] = inventory._hash(result)
    _require(len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= MAX_OUTPUT_BYTES,
        "plan_output_bytes_limit")
    return result


def main(argv: list[str] | None = None) -> int:
    """固定metadataの現在snapshotを再検証し、private保存向けJSONを標準出力へ返す。"""
    parser = argparse.ArgumentParser(description="人間レビュー専用の有界再解析計画を生成します。job実行、resume、通信は行いません。")
    parser.add_argument("--inventory", type=Path, required=True, help="保存したmetadata監査JSON")
    parser.add_argument("--repository", type=Path, default=Path.cwd(), help="元catalogを持つリポジトリ")
    parser.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES, help="保持するcase候補上限")
    parser.add_argument("--max-repairs", type=int, default=MAX_REPAIRS, help="保持するrecord修復レビュー上限")
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        _plan_limits(args.max_candidates, args.max_repairs)
        _require(args.inventory.suffix.casefold() == ".json" and args.inventory.name.casefold() not in
            {"creds.json", "credentials.json"}, "inventory_json_metadata_required")
        source_path = args.inventory.absolute()
        source_reader = _InputSnapshot(source_path)
        source = source_reader.read()
        _validate_inventory(source)
        reader = inventory._Reader(args.repository, max_files=2, max_bytes=16 * 1024 * 1024,
            seconds=inventory.MAX_SECONDS)
        catalog, catalog_hash = reader.read(reader.root / "analysis-results/catalog/cases.json")
        remaining = inventory.MAX_SECONDS - (time.monotonic() - started)
        _require(remaining > 0, "plan_wall_clock_limit")
        current = inventory._inventory(reader.root, seconds=remaining)
        result = build_plan(source, current, catalog, catalog_sha256=catalog_hash,
            max_candidates=args.max_candidates, max_repairs=args.max_repairs)
        source_reader.verify()
        reader.verify()
        _require(time.monotonic() - started < inventory.MAX_SECONDS, "plan_wall_clock_limit")
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (ReanalysisPlanError, inventory.InventoryError, OSError) as exc:
        code = str(exc) if isinstance(exc, ReanalysisPlanError) else "metadata_snapshot_verification_failed"
        print(json.dumps({"error": code, "plan_created": False}), file=sys.stderr)
        return 2
    except (TypeError, ValueError, RecursionError):
        print(json.dumps({"error": "metadata_schema_verification_failed", "plan_created": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
