#!/usr/bin/env python3
"""公開catalogの記録状態を有界・読取専用で監査し、自動化改善の優先度を集計する。"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any

COMMON = Path(__file__).resolve().parent
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_analysis_contract
import remediation_registry
import summarize_one_shot_corpus as corpus

SCHEMA_VERSION = 1
INVENTORY_TYPE = "catalog_automation_failure_inventory"
SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
FILES = ("report.json", "orchestration.json", "c2-analysis.json", "route-config-candidates.json")
MAX_CASES = 10_000
MAX_FILES = 80_004
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SECONDS = 300
MAX_NODES = 200_000
MAX_DEPTH = 64
URL_ROLES = {
    "c2": "c2", "static_config_c2": "c2", "static_config_c2_candidate": "c2_candidate",
    "c2_candidate": "c2_candidate", "distribution": "distribution", "download": "distribution",
    "payload_download": "staging", "stage_download": "staging", "staging": "staging",
    "configuration": "configuration", "config": "configuration", "config_url": "configuration",
    "decoy": "decoy", "context_only": "context_only", "not_c2": "not_c2",
    "exfiltration": "exfiltration", "exfil": "exfiltration",
}


class InventoryError(ValueError):
    """秘密値を含まない固定codeで監査境界違反を表す。"""


def _validate_limits(*, max_cases: int = MAX_CASES, max_files: int,
                     max_bytes: int, seconds: float) -> None:
    values = ((max_cases, MAX_CASES), (max_files, MAX_FILES), (max_bytes, MAX_TOTAL_BYTES))
    if any(type(value) is not int or not 1 <= value <= ceiling for value, ceiling in values):
        raise InventoryError("resource_limit_invalid")
    if (type(seconds) not in {int, float} or not 0 < seconds <= MAX_SECONDS
            or not math.isfinite(seconds)):
        raise InventoryError("wall_clock_limit_invalid")


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate_json_key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise InventoryError("nonfinite_json_value")


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InventoryError("invalid_json") from exc
    if not isinstance(value, dict):
        raise InventoryError("json_object_required")
    nodes, pending = 0, [(value, 0)]
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InventoryError("json_structure_limit")
        if isinstance(item, float) and not math.isfinite(item):
            raise InventoryError("nonfinite_json_value")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        pending.extend((child, depth + 1) for child in children)
        if len(pending) > MAX_NODES:
            raise InventoryError("json_structure_limit")
    return value


def _io(path: Path) -> Path:
    value = os.path.abspath(path)
    return Path("\\\\?\\" + value) if os.name == "nt" and not value.startswith("\\\\") else Path(value)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


class _Reader:
    def __init__(self, root: Path, *, max_files: int, max_bytes: int, seconds: float):
        _validate_limits(max_files=max_files, max_bytes=max_bytes, seconds=seconds)
        self.root = Path(os.path.abspath(root))
        if str(self.root).startswith("\\\\"):
            raise InventoryError("network_path_not_allowed")
        self.max_files, self.max_bytes = max_files, max_bytes
        self.deadline, self.used, self.files = time.monotonic() + seconds, 0, 0
        self.snapshots: dict[Path, tuple[tuple[int, ...], str]] = {}
        self.directories: dict[Path, tuple[int, ...]] = {}
        self.missing_paths: set[Path] = set()
        self._ancestors(self.root)

    def _check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise InventoryError("wall_clock_limit")

    def _directory_identity(self, directory: Path, info: os.stat_result) -> tuple[int, ...]:
        identity = _identity(info)
        # 監査rootより上の共用祖先で起きる無関係なsibling変更はmembership監査の対象外。
        # device/inode/typeによる祖先identityとreparse拒否は維持する。
        return identity if directory == self.root or self.root in directory.parents else identity[:3]

    def _ancestors(self, path: Path) -> None:
        for directory in [*reversed(path.parents), path]:
            self._check()
            info = _io(directory).lstat()
            if _linked(info) or not stat.S_ISDIR(info.st_mode):
                raise InventoryError("unsafe_directory")
            # directoryのmembership変更もsnapshot変更として扱う。
            current = self._directory_identity(directory, info)
            if directory in self.directories and self.directories[directory] != current:
                raise InventoryError("directory_changed")
            self.directories[directory] = current

    def read(self, path: Path, *, optional: bool = False) -> tuple[dict[str, Any] | None, str | None]:
        self._check()
        if self.files >= self.max_files:
            raise InventoryError("snapshot_budget_limit")
        path = Path(os.path.abspath(path))
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise InventoryError("path_outside_repository") from exc
        self._ancestors(path.parent)
        try:
            before = _io(path).lstat()
        except FileNotFoundError:
            if optional:
                if path in self.snapshots:
                    raise InventoryError("file_changed") from None
                self.missing_paths.add(path)
                self.files += 1
                return None, None
            raise InventoryError("required_metadata_missing") from None
        if path in self.missing_paths:
            raise InventoryError("missing_metadata_changed")
        if _linked(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InventoryError("unsafe_metadata_file")
        if before.st_size > MAX_FILE_BYTES:
            raise InventoryError("file_bytes_limit")
        if self.files + 1 > self.max_files or self.used + before.st_size > self.max_bytes:
            raise InventoryError("snapshot_budget_limit")
        with _io(path).open("rb") as stream:
            opened = os.fstat(stream.fileno())
            # Windowsのlstatとfstatでctimeの意味が異なるため、ctimeは同一source内だけで照合する。
            if _identity(before)[:-1] != _identity(opened)[:-1]:
                raise InventoryError("file_changed")
            chunks, size = [], 0
            while True:
                self._check()
                chunk = stream.read(min(65536, MAX_FILE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES or self.used + size > self.max_bytes:
                    raise InventoryError("snapshot_budget_limit")
                chunks.append(chunk)
            if _identity(opened) != _identity(os.fstat(stream.fileno())):
                raise InventoryError("file_changed")
        if size != before.st_size or _identity(before) != _identity(_io(path).lstat()):
            raise InventoryError("file_changed")
        self._ancestors(path.parent)
        raw = b"".join(chunks)
        digest = hashlib.sha256(raw).hexdigest()
        self.used += size
        self.files += 1
        self.snapshots[path] = (_identity(before), digest)
        return _json(raw), digest

    def verify(self) -> None:
        # 再読込分も同じfiles/bytes/time予算へ算入する。
        for path, (identity, digest) in list(self.snapshots.items()):
            self._check()
            if _identity(_io(path).lstat()) != identity:
                raise InventoryError("file_changed")
            _value, current = self.read(path)
            if current != digest:
                raise InventoryError("file_changed")
        for path in self.missing_paths:
            self._check()
            if self.files >= self.max_files:
                raise InventoryError("snapshot_budget_limit")
            self.files += 1
            try:
                _io(path).lstat()
            except FileNotFoundError:
                pass
            else:
                raise InventoryError("missing_metadata_changed")
        for directory, identity in self.directories.items():
            self._check()
            info = _io(directory).lstat()
            if _linked(info) or self._directory_identity(directory, info) != identity:
                raise InventoryError("directory_changed")


def _case_path(root: Path, digest: str, item: Any) -> tuple[Path, str]:
    if not SHA.fullmatch(digest) or not isinstance(item, dict):
        raise InventoryError("catalog_identity_invalid")
    family, version, relative = item.get("family"), item.get("version_key"), item.get("canonical_path")
    if not isinstance(family, str) or not ID.fullmatch(family):
        raise InventoryError("catalog_family_invalid")
    if not isinstance(version, str) or not VERSION.fullmatch(version) or version.endswith("."):
        raise InventoryError("catalog_version_invalid")
    expected = f"analysis-results/malware/{family}/versions/{version}/cases/{digest}"
    if relative != expected or item.get("case_id") != f"sha256:{digest}":
        raise InventoryError("catalog_path_invalid")
    return root / relative, family


def _url_counts(orchestration: dict[str, Any] | None) -> dict[str, int]:
    if orchestration is None:
        return {}
    endpoints = orchestration["outputs"].get("network_endpoints")
    if not isinstance(endpoints, list) or len(endpoints) > 4096:
        return {"unknown_structure": 1}
    counts, seen = Counter(), set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            counts["unknown_structure"] += 1
            continue
        value = endpoint.get("value") or endpoint.get("url")
        if isinstance(value, str) and value.casefold().startswith(("http://", "https://")):
            url_identity = value
        elif (isinstance(endpoint.get("scheme"), str) and endpoint["scheme"] in {"http", "https"} and
                isinstance(endpoint.get("host"), str) and endpoint["host"]):
            # 現行orchestrationはURLをscheme/host/port/pathへ正規化する。
            # provenanceのfield名からC2等の役割は推測しない。
            url_identity = {key: endpoint.get(key) for key in ("scheme", "host", "port", "path")}
        else:
            continue
        raw_role = endpoint.get("role")
        role = URL_ROLES.get(raw_role, "unknown") if isinstance(raw_role, str) else "unknown"
        identity = _hash((url_identity, role))
        if identity not in seen:
            counts[role] += 1
            seen.add(identity)
    return dict(sorted(counts.items()))


def _project(digest: str, family: str, docs: dict[str, tuple[dict[str, Any] | None, str | None]]) -> dict[str, Any]:
    report, _ = docs["report.json"]
    orch, orch_hash = docs["orchestration.json"]
    c2, c2_hash = docs["c2-analysis.json"]
    route, route_hash = docs["route-config-candidates.json"]
    findings = set()
    report_valid = False
    if report is not None:
        try:
            if type(report.get("schema_version")) is not int or report.get("schema_version") != 1:
                findings.add("report_schema_unknown")
                raise ValueError()
            corpus._validate_report(report, digest)
            report_valid = True
        except corpus.CorpusSummaryError as exc:
            findings.add("report_unknown_or_invalid")
            findings.add("validation:" + exc.code)
        except (TypeError, ValueError, KeyError):
            findings.add("report_unknown_or_invalid")
    else:
        findings.add("report_missing")
    manifest = report.get("artifact_sha256", {}) if report_valid else {}
    valid_orch = None
    if orch is not None and report_valid and manifest.get("orchestration.json") == orch_hash:
        try:
            if type(orch.get("schema_version")) is not int or orch.get("schema_version") not in {1, 2}:
                findings.add("orchestration_schema_unknown")
                raise ValueError()
            corpus._validate_orchestration(orch, digest)
            gate = orch["quality_gates"]["config"]
            if gate["required"] is not None and type(gate["required"]) is not bool:
                raise ValueError()
            valid_orch = orch
        except corpus.CorpusSummaryError as exc:
            findings.add("orchestration_unknown_or_invalid")
            findings.add("validation:" + exc.code)
        except (TypeError, ValueError, KeyError):
            findings.add("orchestration_unknown_or_invalid")
    else:
        findings.add("orchestration_missing_or_unbound")
    valid_route = False
    if route is not None and report_valid and manifest.get("route-config-candidates.json") == route_hash:
        try:
            corpus._validate_route(route, digest)
            valid_route = (type(route.get("schema_version")) is int and
                type(route.get("route_config_candidate_recovered")) is bool)
        except (corpus.CorpusSummaryError, TypeError, ValueError, KeyError):
            pass
    if route is not None and not valid_route:
        findings.add("route_candidates_unknown_or_unbound")
    c2_validation = None
    if (c2 is not None and report_valid and manifest.get("c2-analysis.json") == c2_hash
            and type(c2.get("schema_version")) is int and c2.get("schema_version") == 1
            and isinstance(c2.get("phase_evidence"), list) and len(c2["phase_evidence"]) <= 64):
        try:
            c2_validation = c2_analysis_contract.validate_contract(c2, digest)
        except (TypeError, ValueError, KeyError):
            pass
    if c2_validation is None:
        findings.add("c2_unknown_or_unbound")
    blockers = set()
    if report_valid:
        blockers.update(report["case_state"]["blockers"])
    if valid_orch is not None:
        blockers.update(valid_orch["blockers"])
    safe_blockers = set()
    actions = set()
    for blocker in blockers:
        policy = remediation_registry.planner_policy_for_blocker(blocker)
        if blocker in corpus.PUBLIC_BLOCKER_CODES or policy is not None:
            # family suffixは分類に必要だが出力には不要なので、登録prefixでも値を保持しない。
            public_code = blocker.split(":", 1)[0] if blocker.startswith((
                "selected_family_has_no_automatic_handler:", "selected_family_has_no_valid_handler_evidence:"
            )) else blocker
            safe_blockers.add(public_code)
            if policy is not None:
                actions.add(policy.action_id)
        else:
            safe_blockers.add("unknown_blocker_redacted")
    config = {"status": "unknown", "required": None, "recorded_confirmed": False, "candidate_recorded": False}
    if valid_orch is not None:
        required = valid_orch["quality_gates"]["config"]["required"]
        confirmed = valid_orch["outputs"]["config_recovered"]
        candidate = valid_orch["candidate_outputs"]["config_candidate_recovered"] or (
            valid_route and route["route_config_candidate_recovered"])
        config = {"status": "recorded_confirmed" if confirmed else "candidate_only" if candidate else
            "required_missing" if required is True else "not_required" if required is False else "unknown",
            "required": required, "recorded_confirmed": confirmed, "candidate_recorded": bool(candidate)}
    status = report["case_state"]["status"] if report_valid else "unknown"
    fingerprint = {"implementation_contract": None, "input": None, "evidence": None}
    if report_valid:
        fingerprint["implementation_contract"] = report["analysis_contract"]["sha256"]
        sample = report["sample"]
        fingerprint["input"] = _hash({key: sample.get(key) for key in
            ("sha256", "size", "outer_sha256", "outer_size", "input_kind")})
        fingerprint["evidence"] = _hash({name: document for name, (document, _digest) in docs.items()
            if name != "report.json"})
    return {"sha256": digest, "catalog_family": family, "record_valid": report_valid and valid_orch is not None,
        "recorded_case_state": status, "metadata_findings": sorted(findings), "blockers": sorted(safe_blockers),
        "improvement_actions": sorted(actions), "config": config, "url_role_counts": _url_counts(valid_orch),
        "c2_recorded_outcome": c2_validation["outcome"] if c2_validation else "unknown",
        "c2_metadata_contract_complete": c2_validation["complete"] if c2_validation else False,
        "fingerprints": fingerprint, "automatic_retry_allowed": False}


def _compare(record: dict[str, Any], previous: dict[str, Any] | None) -> None:
    current = record["fingerprints"]
    old = previous.get("fingerprints") if isinstance(previous, dict) else None
    if not isinstance(old, dict) or any(not isinstance(current[k], str) or
            not isinstance(old.get(k), str) or not SHA.fullmatch(old[k]) for k in current):
        record["change_decision"] = "comparison_unknown"
        record["changed_dimensions"] = []
        return
    changed = sorted(key for key in current if current[key] != old[key])
    record["changed_dimensions"] = changed
    record["change_decision"] = "successor_review_required" if changed else "unchanged_no_retry"


def _rates(records: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [record for record in records if record["record_valid"]]
    required = [record for record in valid if record["config"]["required"] is True]
    candidates = [record for record in valid if record["config"]["candidate_recorded"]]
    def rate(numerator: int, denominator: int) -> dict[str, Any]:
        return {"numerator": numerator, "denominator": denominator,
            "percentage": round(100 * numerator / denominator, 2) if denominator else None}
    return {"all_cases": len(records), "record_valid_cases": len(valid), "config_required_cases": len(required),
        "config_candidate_cases": len(candidates), "recorded_config_on_required": rate(
            sum(record["config"]["recorded_confirmed"] for record in required), len(required)),
        "recorded_config_on_valid": rate(sum(record["config"]["recorded_confirmed"] for record in valid), len(valid)),
        "candidate_only_cases": sum(record["config"]["status"] == "candidate_only" for record in valid)}


def _inventory(root: Path, *, baseline: Path | None = None, max_cases: int = MAX_CASES,
               max_files: int = MAX_FILES, max_bytes: int = MAX_TOTAL_BYTES,
               seconds: float = MAX_SECONDS) -> dict[str, Any]:
    _validate_limits(max_cases=max_cases, max_files=max_files, max_bytes=max_bytes, seconds=seconds)
    reader = _Reader(root, max_files=max_files, max_bytes=max_bytes, seconds=seconds)
    catalog, catalog_hash = reader.read(reader.root / "analysis-results/catalog/cases.json")
    if type(catalog.get("schema_version")) is not int or catalog.get("schema_version") != 1:
        raise InventoryError("catalog_schema_unknown")
    cases = catalog.get("cases")
    if not isinstance(cases, dict) or len(cases) > max_cases:
        raise InventoryError("catalog_case_limit_or_structure")
    previous = {}
    if baseline is not None:
        if baseline.suffix.casefold() != ".json" or baseline.name.casefold() in {"creds.json", "credentials.json"}:
            raise InventoryError("baseline_json_metadata_required")
        old, _ = reader.read(baseline)
        if (type(old.get("schema_version")) is not int or old.get("schema_version") != 1
                or old.get("inventory_type") != INVENTORY_TYPE):
            raise InventoryError("baseline_schema_unknown")
        if old.get("inventory_sha256") != _hash({key: value for key, value in old.items() if key != "inventory_sha256"}):
            raise InventoryError("baseline_commitment_invalid")
        values = old.get("cases")
        if not isinstance(values, list) or len(values) > max_cases:
            raise InventoryError("baseline_cases_invalid")
        for item in values:
            if not isinstance(item, dict) or not isinstance(item.get("sha256"), str) or not SHA.fullmatch(item["sha256"]):
                raise InventoryError("baseline_identity_invalid")
            if item["sha256"] in previous:
                raise InventoryError("baseline_duplicate_case")
            previous[item["sha256"]] = item
    records = []
    for digest, item in sorted(cases.items()):
        reader._check()
        if not isinstance(item, dict):
            raise InventoryError("catalog_identity_invalid")
        if not isinstance(item.get("case_kind"), str):
            raise InventoryError("catalog_case_kind_invalid")
        if item.get("case_kind") not in {"malware", "unclassified"}:
            # 非malwareも全catalog分母には残し、無理に固定pathを適用しない。
            if not SHA.fullmatch(digest):
                raise InventoryError("catalog_identity_invalid")
            records.append({"sha256": digest, "catalog_family": "out_of_scope", "record_valid": False,
                "recorded_case_state": "unknown", "metadata_findings": ["case_kind_out_of_scope"],
                "blockers": [], "improvement_actions": [], "config": {"status": "unknown", "required": None,
                "recorded_confirmed": False, "candidate_recorded": False}, "url_role_counts": {},
                "c2_recorded_outcome": "unknown", "c2_metadata_contract_complete": False,
                "fingerprints": {"implementation_contract": None, "input": None, "evidence": None},
                "automatic_retry_allowed": False})
        else:
            path, family = _case_path(reader.root, digest, item)
            docs = {name: reader.read(path / name, optional=True) for name in FILES}
            records.append(_project(digest, family, docs))
        _compare(records[-1], previous.get(digest))
    reader.verify()
    families = defaultdict(list)
    for record in records:
        families[record["catalog_family"]].append(record)
    failures = Counter(code for record in records for code in record["blockers"])
    findings = Counter(code for record in records for code in record["metadata_findings"])
    actions = Counter(action for record in records for action in record["improvement_actions"])
    reader._check()
    result = {"schema_version": SCHEMA_VERSION, "inventory_type": INVENTORY_TYPE,
        "catalog_sha256": catalog_hash, "scope": "public_metadata_recorded_status_only",
        "full_artifact_seals_verified": False, "sample_bytes_read": False, "network_contacted": False,
        "automatic_dispatch_allowed": False, "coverage": _rates(records),
        "recorded_case_state_counts": dict(sorted(Counter(r["recorded_case_state"] for r in records).items())),
        "metadata_finding_case_counts": dict(sorted(findings.items())),
        "blocker_case_counts": dict(sorted(failures.items())),
        "improvement_priorities": [{"action_id": action, "affected_cases": count} for action, count in
            sorted(actions.items(), key=lambda pair: (-pair[1], pair[0]))],
        "family_coverage": {family: _rates(values) for family, values in sorted(families.items())},
        "change_decision_counts": dict(sorted(Counter(r["change_decision"] for r in records).items())),
        "url_role_counts": dict(sorted(sum((Counter(r["url_role_counts"]) for r in records), Counter()).items())),
        "limits": {"max_cases": max_cases, "max_files_including_reverification": max_files,
            "max_bytes_including_reverification": max_bytes, "wall_seconds": seconds}, "cases": records}
    result["inventory_sha256"] = _hash(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="公開metadata記録の未完了理由を読取専用で監査します。実検体の成功率ではありません。")
    parser.add_argument("--repository", type=Path, default=Path.cwd(), help="公開catalogを持つリポジトリ")
    parser.add_argument("--baseline", type=Path, help="同じリポジトリ内の前回inventory JSON（省略時は比較不明）")
    parser.add_argument("--max-cases", type=int, default=MAX_CASES, help="case数の上限（上限到達は停止）")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, help="再検証も含むfile読取回数上限")
    parser.add_argument("--max-bytes", type=int, default=MAX_TOTAL_BYTES, help="再検証も含む合計読取byte上限")
    parser.add_argument("--wall-seconds", type=float, default=MAX_SECONDS, help="読取りと集計の時間上限")
    args = parser.parse_args(argv)
    if not (1 <= args.max_cases <= MAX_CASES and 1 <= args.max_files <= MAX_FILES and
            1 <= args.max_bytes <= MAX_TOTAL_BYTES and 0 < args.wall_seconds <= MAX_SECONDS):
        parser.error("上限は正値かつ既定のhard limit以下にしてください")
    try:
        result = _inventory(args.repository, baseline=args.baseline, max_cases=args.max_cases,
            max_files=args.max_files, max_bytes=args.max_bytes, seconds=args.wall_seconds)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (InventoryError, OSError) as exc:
        code = str(exc) if isinstance(exc, InventoryError) else "metadata_io_error"
        print(json.dumps({"error": code, "complete": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
