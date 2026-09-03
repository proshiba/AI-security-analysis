#!/usr/bin/env python3
"""collection公開成果物の挙動・帰属・通信品質をfail-closedで検証する。

検体や非公開解析物は開かず、manifestが指す公開caseだけを対象にする。reportの
seal／artifact hashを検証した後、提供元ラベルの帰属境界、ScreenConnectの双用途
管理通信、関数role、process creationの説明、call edge／constant coverageを横断して
検証する。外部通信と検体実行は行わない。
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any


COMMON = Path(__file__).resolve().parent
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import (  # noqa: E402
    case_integrity_errors,
    ensure_no_reparse_components,
    ensure_tree_without_reparse,
    load_json_object_strict,
    normalize_sha256_digest,
    resolve_case_artifact,
)


SCHEMA_VERSION = 1
MAX_MARKDOWN_BYTES = 16 * 1024 * 1024
MAX_CASES = 10_000
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_SEGMENT_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
COMPLETE_FUNCTION_STATUSES = frozenset(
    {
        "characteristic_function_static_analysis_complete",
        "characteristic_function_static_analysis_complete_with_documented_limits",
    }
)
NEGATIVE_SYMBOLS = (
    "nullableattribute",
    "compilerservices",
    "msifile.getbytes",
    "cabfile.save",
    "getstartupinfo",
    "sendmessagew",
    "requestpositionifneeded",
)
FORBIDDEN_NEGATIVE_ROLES = frozenset(
    {
        "persistence",
        "network",
        "networking",
        "communication",
        "c2",
        "command",
        "command_dispatch",
        "command_execution",
        "remote_command",
    }
)
PROCESS_CREATION_MARKERS = frozenset(
    {
        "createprocessa",
        "createprocessw",
        "shellexecutea",
        "shellexecutew",
        "system.diagnostics.process.start",
        "microsoft.visualbasic.interaction.shell",
    }
)
SCREENCONNECT_REQUIRED_GATES = frozenset(
    {
        "generic_triage",
        "static_layers",
        "family_resolution",
        "handler_evidence",
        "config",
        "network",
        "function_analysis",
        "requirements_policy",
    }
)


@dataclass(frozen=True)
class Finding:
    """機械判定用codeと人間向け説明を保持する。"""

    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        """JSONへ保存できる形式へ変換する。"""

        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass
class CaseValidation:
    """1caseの意味品質検証結果。"""

    sha256: str
    case_path: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, code: str, path: str, message: str) -> None:
        """重複しないfindingを追加する。"""

        finding = Finding(code=code, path=path, message=message)
        if finding not in self.findings:
            self.findings.append(finding)

    @property
    def valid(self) -> bool:
        """違反がなければtrueを返す。"""

        return not self.findings

    def as_dict(self) -> dict[str, Any]:
        """JSONへ保存できる形式へ変換する。"""

        return {
            "sha256": self.sha256,
            "case_path": self.case_path,
            "valid": self.valid,
            "findings": [item.as_dict() for item in self.findings],
        }


def _relative(repository: Path, path: Path) -> str:
    """finding用にrepository相対POSIX pathを返す。"""

    try:
        return path.relative_to(repository).as_posix()
    except ValueError:
        return str(path)


def _inside(path: Path, root: Path) -> bool:
    """pathがroot自身または配下かを文字列prefixに依存せず判定する。"""

    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _load_json(path: Path) -> dict[str, Any]:
    """既存の単一handle・厳密JSON loaderを使用する。"""

    return load_json_object_strict(path)


def _load_case_json(
    repository: Path,
    case_dir: Path,
    name: str,
    validation: CaseValidation,
) -> dict[str, Any] | None:
    """case直下のJSONを境界検証付きで読み、失敗をfindingへ変換する。"""

    try:
        path = resolve_case_artifact(case_dir, name)
        return _load_json(path)
    except (OSError, TypeError, ValueError) as exc:
        validation.add(
            "required_json_invalid",
            _relative(repository, case_dir / name),
            f"必須JSONを安全に読み取れません: {exc}",
        )
        return None


def _read_markdown(path: Path) -> str:
    """reparse／hardlink／容量超過を拒否してMarkdownを読む。"""

    ensure_no_reparse_components(path)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > MAX_MARKDOWN_BYTES
    ):
        raise ValueError("Markdownが単一linkの通常fileではないか容量上限を超えています")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != before.st_size
            or opened.st_ino == 0
            or not os.path.samestat(before, opened)
        ):
            raise ValueError("Markdownが読取開始前に差し替えられました")
        chunks: list[bytes] = []
        remaining = MAX_MARKDOWN_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    after_path = path.lstat()
    if (
        len(data) > MAX_MARKDOWN_BYTES
        or len(data) != opened.st_size
        or not os.path.samestat(opened, after_handle)
        or not os.path.samestat(opened, after_path)
        or opened.st_mtime_ns != after_handle.st_mtime_ns
        or opened.st_mtime_ns != after_path.st_mtime_ns
        or opened.st_size != after_handle.st_size
        or opened.st_size != after_path.st_size
    ):
        raise ValueError("Markdownが読取中に変更されました")
    return data.decode("utf-8-sig", errors="strict")


def _load_markdown(
    repository: Path,
    case_dir: Path,
    name: str,
    validation: CaseValidation,
) -> str | None:
    """case Markdownを安全に読み、失敗をfindingへ変換する。"""

    path = case_dir / name
    try:
        return _read_markdown(path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        validation.add(
            "required_markdown_invalid",
            _relative(repository, path),
            f"必須Markdownを安全に読み取れません: {exc}",
        )
        return None


def _manifest_digests(manifest: Mapping[str, Any]) -> list[str]:
    """manifestのcase_idを曖昧な代替fieldなしで厳格に解決する。"""

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > MAX_CASES:
        raise ValueError("manifest.casesは1件以上、上限以内の配列である必要があります")
    digests: list[str] = []
    for index, item in enumerate(cases):
        if not isinstance(item, Mapping):
            raise ValueError(f"manifest.cases[{index}]がobjectではありません")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("sha256:"):
            raise ValueError(f"manifest.cases[{index}].case_idが正規形ではありません")
        digest = case_id.removeprefix("sha256:")
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"manifest.cases[{index}].case_idが小文字SHA-256ではありません")
        normalize_sha256_digest(digest)
        digests.append(digest)
    if len(digests) != len(set(digests)):
        raise ValueError("manifest.casesに重複SHA-256があります")
    if digests != sorted(digests):
        raise ValueError("manifest.casesがSHA-256順の正規形ではありません")
    return digests


def _summary_case_records(
    summary: Mapping[str, Any],
    expected: list[str],
) -> dict[str, dict[str, Any]]:
    """publication-summaryのcase集合をmanifestへ一対一で結合する。"""

    cases = summary.get("cases")
    if not isinstance(cases, list) or len(cases) != len(expected):
        raise ValueError("publication-summary.cases件数がmanifestと一致しません")
    records: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(cases):
        if not isinstance(item, dict):
            raise ValueError(f"publication-summary.cases[{index}]がobjectではありません")
        digest = item.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"publication-summary.cases[{index}].sha256が正規形ではありません")
        if digest in records:
            raise ValueError("publication-summary.casesに重複SHA-256があります")
        records[digest] = item
    if set(records) != set(expected):
        raise ValueError("publication-summaryとmanifestのcase集合が一致しません")
    return records


def _canonical_case_candidates(repository: Path, digest: str) -> list[Path]:
    """正規malware catalogから同じSHA-256のcase pathを列挙する。"""

    malware_root = repository / "analysis-results" / "malware"
    return sorted(
        (
            path
            for path in malware_root.glob(f"*/versions/*/cases/{digest}")
            if path.is_dir()
        ),
        key=lambda value: value.as_posix(),
    )


def _resolve_case_dir(
    repository: Path,
    digest: str,
    record: Mapping[str, Any],
) -> Path:
    """summary path、catalog唯一性、SHA-256末尾を同時に検証する。"""

    relative = record.get("case_path")
    if not isinstance(relative, str) or "\\" in relative or "\x00" in relative:
        raise ValueError("case_pathが安全なPOSIX相対pathではありません")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("case_pathが安全なPOSIX相対pathではありません")
    expected_prefix = ("analysis-results", "malware")
    if pure.parts[:2] != expected_prefix or len(pure.parts) != 7:
        raise ValueError("case_pathが正規malware case layoutではありません")
    if (
        pure.parts[3] != "versions"
        or pure.parts[5] != "cases"
        or pure.parts[6] != digest
        or any(SAFE_SEGMENT_RE.fullmatch(part) is None for part in (pure.parts[2], pure.parts[4]))
    ):
        raise ValueError("case_pathのfamily/version/SHA-256境界が不正です")
    unresolved = repository.joinpath(*pure.parts)
    ensure_no_reparse_components(unresolved)
    case_dir = unresolved.resolve(strict=True)
    malware_root = (repository / "analysis-results" / "malware").resolve(strict=True)
    if not _inside(case_dir, malware_root) or case_dir.name != digest:
        raise ValueError("case_pathがmalware catalog境界外です")
    candidates = [path.resolve(strict=True) for path in _canonical_case_candidates(repository, digest)]
    if candidates != [case_dir]:
        raise ValueError("SHA-256に対応する正規case directoryが一意ではありません")
    ensure_tree_without_reparse(case_dir)
    return case_dir


def _walk_boolean(value: Any, key: str) -> list[bool]:
    """JSON treeから厳密boolの指定keyだけを収集する。"""

    found: list[bool] = []
    if isinstance(value, Mapping):
        for name, child in value.items():
            if name == key and type(child) is bool:
                found.append(child)
            found.extend(_walk_boolean(child, key))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_boolean(child, key))
    return found


def _family_attribution(document: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """成果物ごとの既知位置から公開帰属境界を取得する。"""

    for key in ("family_attribution", "publication_attribution", "attribution"):
        candidate = document.get(key)
        if isinstance(candidate, Mapping) and "supports_attribution" in candidate:
            return candidate
    return None


def _validate_provider_boundary(
    repository: Path,
    case_dir: Path,
    record: Mapping[str, Any],
    report: Mapping[str, Any],
    routing: Mapping[str, Any],
    documents: Mapping[str, Mapping[str, Any]],
    readme: str,
    features_markdown: str,
    validation: CaseValidation,
) -> bool:
    """提供元ラベルを内部静的確認済みfamilyへ昇格していないことを検証する。"""

    classification = report.get("classification")
    selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
    support_flags = _walk_boolean(routing, "supports_attribution")
    provider_only = selected == [] and (False in support_flags or record.get("attribution_basis") in {
        "malwarebazaar_reported_signature",
        "unsupported_reported_signature",
        "provider_reported_signature",
    })
    if not provider_only:
        return False

    expected_statuses = {"provider_reported_not_statically_confirmed", "unresolved"}
    attribution_documents = ("analysis.json", "features.json")
    for name in attribution_documents:
        document = documents.get(name, {})
        attribution = _family_attribution(document)
        if attribution is None:
            validation.add(
                "provider_attribution_boundary_missing",
                _relative(repository, case_dir / name),
                "provider-only caseに機械可読な帰属境界がありません。",
            )
            continue
        if (
            attribution.get("status") not in expected_statuses
            or attribution.get("supports_attribution") is not False
            or attribution.get("statically_confirmed_family") is not None
        ):
            validation.add(
                "provider_family_promoted",
                _relative(repository, case_dir / name),
                "提供元ラベルが内部静的確認済みfamilyとして表現されています。",
            )

    analysis = documents.get("analysis.json", {})
    analysis_case = analysis.get("case") if isinstance(analysis, Mapping) else None
    if not isinstance(analysis_case, Mapping) or (
        analysis_case.get("statically_confirmed_family") is not None
        or analysis_case.get("family_attribution_status") not in expected_statuses
        or analysis_case.get("family_role") not in {
            "provider_reported_grouping",
            "unclassified",
            "unresolved",
        }
    ):
        validation.add(
            "provider_analysis_definite_family",
            _relative(repository, case_dir / "analysis.json"),
            "analysis.jsonが整理先ラベルと静的確認済みfamilyを分離していません。",
        )

    features = documents.get("features.json", {})
    feature_attribution = _family_attribution(features)
    if feature_attribution is None or feature_attribution.get("supports_attribution") is not False:
        validation.add(
            "provider_features_definite_family",
            _relative(repository, case_dir / "features.json"),
            "features.jsonにprovider-only帰属境界がありません。",
        )

    for name, text in (("README.md", readme), ("FEATURES.md", features_markdown)):
        if re.search(r"(?m)^- (?:正規分類|ファミリー):\s*`(?!unknown`|unclassified`|なし`)[^`]+`", text):
            validation.add(
                "provider_markdown_definite_family",
                _relative(repository, case_dir / name),
                "provider-only caseを無修飾の確定familyとして表示しています。",
            )
        required = (
            "提供元報告" in text
            and re.search(r"内部静的確認済みファミリー:\s*`なし`", text) is not None
        )
        if not required:
            validation.add(
                "provider_markdown_boundary_missing",
                _relative(repository, case_dir / name),
                "提供元報告と内部静的確認未成立の境界説明がありません。",
            )

    if (
        record.get("family_attribution_status") not in expected_statuses
        or record.get("statically_confirmed_family") is not None
        or record.get("family_role") not in {
            "provider_reported_grouping",
            "unclassified",
            "unresolved",
        }
    ):
        validation.add(
            "provider_collection_summary_definite_family",
            "publication-summary.json",
            "collection case summaryがprovider-onlyラベルを確定familyから分離していません。",
        )
    return True


def _endpoint_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    """通信観測をroleを含む比較用tupleへ変換する。"""

    return (
        str(value.get("host") or "").casefold().rstrip("."),
        value.get("port"),
        str(value.get("transport") or value.get("protocol") or "").casefold(),
        str(value.get("role") or "").casefold(),
        str(value.get("path") or ""),
    )


def _endpoint_locator(value: Mapping[str, Any]) -> tuple[Any, ...]:
    """role名の付け替えでは隠せない通信先identityを返す。"""

    key = _endpoint_key(value)
    return (*key[:3], key[4])


def _valid_management_endpoint(value: Any) -> bool:
    """ScreenConnect双用途管理endpointの証拠境界を検証する。"""

    if not isinstance(value, Mapping):
        return False
    evidence = value.get("evidence")
    return (
        value.get("role")
        in {"remote_management_relay", "screenconnect_clickonce_bootstrap"}
        and isinstance(evidence, Mapping)
        and evidence.get("kind") == "screenconnect_embedded_management_endpoint"
        and evidence.get("malicious_use_confirmed") is False
        and evidence.get("c2_classification")
        in {"dual_use_not_c2_by_itself", "dual_use_management_endpoint_not_c2_by_itself"}
    )


def _validate_screenconnect_complete(
    repository: Path,
    case_dir: Path,
    report: Mapping[str, Any],
    documents: Mapping[str, Mapping[str, Any]],
    readme: str,
    features_markdown: str,
    validation: CaseValidation,
) -> None:
    """完了ScreenConnect caseの全公開成果物を同じ意味状態へ結合する。"""

    state = report.get("case_state")
    classification = report.get("classification")
    selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
    if selected != ["screenconnect_rmm"] or not isinstance(state, Mapping):
        return
    if state.get("status") != "complete":
        return
    if state.get("complete") is not True or state.get("resumable") is not True or state.get("blockers") != []:
        validation.add(
            "screenconnect_report_state_inconsistent",
            _relative(repository, case_dir / "report.json"),
            "完了ScreenConnectのreport state flagsまたはblockerが矛盾しています。",
        )

    analysis = documents.get("analysis.json", {})
    analysis_case = analysis.get("case") if isinstance(analysis, Mapping) else None
    logic = documents.get("static-logic.json", {})
    if not isinstance(analysis_case, Mapping) or (
        analysis_case.get("sha256") != validation.sha256
        or analysis_case.get("statically_confirmed_family") not in {
            "screenconnect-rmm",
            "screenconnect_rmm",
        }
        or analysis_case.get("declarative_status") not in COMPLETE_FUNCTION_STATUSES
        or analysis_case.get("declarative_status") != logic.get("status")
    ):
        validation.add(
            "screenconnect_analysis_state_inconsistent",
            _relative(repository, case_dir / "analysis.json"),
            "analysis.jsonが完了report／静的ロジックと一致しません。",
        )

    features = documents.get("features.json", {})
    assessment = features.get("analysis_assessment") if isinstance(features, Mapping) else None
    management_assessment = (
        features.get("screenconnect_management_assessment")
        if isinstance(features, Mapping)
        else None
    )
    if not isinstance(assessment, Mapping) or (
        assessment.get("status") != "complete"
        or assessment.get("missing") != []
        or assessment.get("unresolved") != []
    ):
        validation.add(
            "screenconnect_features_not_complete",
            _relative(repository, case_dir / "features.json"),
            "完了ScreenConnectのfeatures assessmentがcompleteではありません。",
        )

    communication = documents.get("communication-patterns.json", {})
    communication_body = communication.get("communication") if isinstance(communication, Mapping) else None
    config = communication.get("config") if isinstance(communication, Mapping) else None
    boundary = communication.get("evidence_boundary") if isinstance(communication, Mapping) else None
    management = (
        communication_body.get("confirmed_static_management_endpoints")
        if isinstance(communication_body, Mapping)
        else None
    )
    c2_endpoints = (
        communication_body.get("confirmed_static_c2_endpoints")
        if isinstance(communication_body, Mapping)
        else None
    )
    all_endpoints = (
        communication_body.get("confirmed_static_endpoints")
        if isinstance(communication_body, Mapping)
        else None
    )
    if not isinstance(management, list) or not management or any(
        not _valid_management_endpoint(item) for item in management
    ):
        validation.add(
            "screenconnect_management_endpoint_invalid",
            _relative(repository, case_dir / "communication-patterns.json"),
            "双用途管理endpointが証拠種別・role・悪性利用境界付きで記録されていません。",
        )
        management = []
    if not isinstance(c2_endpoints, list):
        validation.add(
            "screenconnect_c2_endpoint_list_invalid",
            _relative(repository, case_dir / "communication-patterns.json"),
            "malware C2専用endpoint配列がありません。",
        )
        c2_endpoints = []
    management_keys = {_endpoint_key(item) for item in management if isinstance(item, Mapping)}
    c2_keys = {_endpoint_key(item) for item in c2_endpoints if isinstance(item, Mapping)}
    management_locators = {
        _endpoint_locator(item) for item in management if isinstance(item, Mapping)
    }
    c2_locators = {
        _endpoint_locator(item) for item in c2_endpoints if isinstance(item, Mapping)
    }
    if management_locators & c2_locators:
        validation.add(
            "screenconnect_management_endpoint_promoted_to_c2",
            _relative(repository, case_dir / "communication-patterns.json"),
            "同じrole付き管理endpointがmalware C2配列にも含まれています。",
        )
    if not isinstance(all_endpoints, list) or {
        _endpoint_key(item) for item in all_endpoints if isinstance(item, Mapping)
    } != management_keys | c2_keys:
        validation.add(
            "screenconnect_endpoint_projection_mismatch",
            _relative(repository, case_dir / "communication-patterns.json"),
            "全通信先projectionが管理endpointとC2 endpointの和集合に一致しません。",
        )
    if not isinstance(config, Mapping) or config.get("terminal_managed_client") is not True:
        validation.add(
            "screenconnect_terminal_client_unverified",
            _relative(repository, case_dir / "communication-patterns.json"),
            "終端managed clientの静的確認がありません。",
        )
    if not isinstance(boundary, Mapping) or boundary.get(
        "dual_use_management_endpoint_is_c2_confirmation"
    ) is not False:
        validation.add(
            "screenconnect_evidence_boundary_invalid",
            _relative(repository, case_dir / "communication-patterns.json"),
            "双用途管理endpointをC2確認とみなさない境界がありません。",
        )

    c2 = documents.get("c2-analysis.json", {})
    c2_body = c2.get("c2") if isinstance(c2, Mapping) else None
    deep = c2.get("deep_analysis") if isinstance(c2, Mapping) else None
    terminal = c2.get("terminal_payload") if isinstance(c2, Mapping) else None
    protocol = c2_body.get("protocol") if isinstance(c2_body, Mapping) else None
    if not c2_keys and (
        not isinstance(c2_body, Mapping)
        or c2_body.get("outcome") != "no_c2_capability_verified"
        or c2_body.get("endpoints") != []
        or not isinstance(protocol, Mapping)
        or protocol.get("status") != "not_applicable"
    ):
        validation.add(
            "screenconnect_no_c2_contract_inconsistent",
            _relative(repository, case_dir / "c2-analysis.json"),
            "別個C2なしの判定とC2契約が一致しません。",
        )
    c2_contract_endpoints = c2_body.get("endpoints") if isinstance(c2_body, Mapping) else None
    if c2_keys and (
        not isinstance(c2_body, Mapping)
        or c2_body.get("outcome") == "no_c2_capability_verified"
        or not isinstance(c2_contract_endpoints, list)
        or any(not isinstance(item, Mapping) for item in c2_contract_endpoints)
        or {
            _endpoint_locator(item)
            for item in c2_contract_endpoints
            if isinstance(item, Mapping)
        }
        != c2_locators
    ):
        validation.add(
            "screenconnect_c2_contract_inconsistent",
            _relative(repository, case_dir / "c2-analysis.json"),
            "別個C2観測件数とC2契約が一致しません。",
        )
    if not isinstance(deep, Mapping) or deep.get("status") != "complete" or deep.get("blockers") != []:
        validation.add(
            "screenconnect_c2_analysis_not_complete",
            _relative(repository, case_dir / "c2-analysis.json"),
            "ScreenConnect C2分析の完了状態またはblockerが不正です。",
        )
    if not isinstance(terminal, Mapping) or (
        terminal.get("reached") is not True
        or terminal.get("status") != "recovered"
        or terminal.get("blockers") != []
    ):
        validation.add(
            "screenconnect_terminal_state_inconsistent",
            _relative(repository, case_dir / "c2-analysis.json"),
            "終端managed clientの到達状態がreport完了と一致しません。",
        )

    orchestration = documents.get("orchestration.json", {})
    resolution = orchestration.get("family_resolution") if isinstance(orchestration, Mapping) else None
    gates = orchestration.get("quality_gates") if isinstance(orchestration, Mapping) else None
    if (
        orchestration.get("schema_version") != 2
        or orchestration.get("sample_sha256") != validation.sha256
        or orchestration.get("status") != "complete"
        or orchestration.get("blockers") != []
        or orchestration.get("next_actions_ja") != []
        or not isinstance(resolution, Mapping)
        or resolution.get("status") != "resolved"
        or resolution.get("family") != "screenconnect_rmm"
    ):
        validation.add(
            "screenconnect_orchestration_state_inconsistent",
            _relative(repository, case_dir / "orchestration.json"),
            "orchestrationのfamily・terminal status・blockerがreport完了と一致しません。",
        )
    if not isinstance(gates, Mapping):
        validation.add(
            "screenconnect_orchestration_gates_missing",
            _relative(repository, case_dir / "orchestration.json"),
            "orchestration quality gateがありません。",
        )
    else:
        for name in SCREENCONNECT_REQUIRED_GATES:
            gate = gates.get(name)
            if not isinstance(gate, Mapping) or (
                gate.get("required") is not True
                or gate.get("satisfied") is not True
                or gate.get("status") != "satisfied"
            ):
                validation.add(
                    "screenconnect_required_gate_incomplete",
                    _relative(repository, case_dir / "orchestration.json"),
                    f"必須quality gate {name} が完了していません。",
                )
        terminal_gate = gates.get("terminal_payload")
        if not isinstance(terminal_gate, Mapping) or (
            terminal_gate.get("required") is not False
            or terminal_gate.get("satisfied") is not False
            or terminal_gate.get("status") != "not_applicable"
        ):
            validation.add(
                "screenconnect_terminal_gate_inconsistent",
                _relative(repository, case_dir / "orchestration.json"),
                "終端managed client自身に別payload必須gateを課しています。",
            )

    if isinstance(analysis_case, Mapping) and (
        analysis_case.get("confirmed_static_management_observations") != len(management_keys)
        or analysis_case.get("confirmed_static_c2_observations") != len(c2_keys)
        or analysis_case.get("confirmed_static_network_observations")
        != len(management_keys | c2_keys)
    ):
        validation.add(
            "screenconnect_analysis_endpoint_count_mismatch",
            _relative(repository, case_dir / "analysis.json"),
            "analysis.jsonの管理／C2／全通信先件数が通信成果物と一致しません。",
        )
    if not isinstance(management_assessment, Mapping) or (
        management_assessment.get("dual_use_management_client") is not True
        or management_assessment.get("management_endpoint_observations") != len(management_keys)
        or management_assessment.get("separate_malware_c2_observations") != len(c2_keys)
        or management_assessment.get("malicious_use_confirmed") is not False
        or type(management_assessment.get("remote_command_capability_statically_confirmed"))
        is not bool
    ):
        validation.add(
            "screenconnect_feature_assessment_inconsistent",
            _relative(repository, case_dir / "features.json"),
            "featuresの双用途管理・remote command・悪性利用・別個C2評価が不整合です。",
        )

    for name, text in (("README.md", readme), ("FEATURES.md", features_markdown)):
        human = text.casefold()
        human_requirements = {
            "screenconnect_human_dual_use_missing": "双用途" in human,
            "screenconnect_human_remote_command_missing": (
                "remote command" in human or "リモートコマンド" in human
            ),
            "screenconnect_human_malicious_use_boundary_missing": (
                "悪性利用" in human
                and any(
                    marker in human
                    for marker in ("未確認", "確認していません", "確定していない")
                )
            ),
            "screenconnect_human_separate_c2_boundary_missing": (
                "別個" in human
                and "c2" in human
                and (
                    bool(c2_keys)
                    or any(marker in human for marker in ("未確認", "確認していません", "0件"))
                )
            ),
        }
        for code, satisfied in human_requirements.items():
            if not satisfied:
                validation.add(
                    code,
                    _relative(repository, case_dir / name),
                    "ScreenConnectの双用途性、remote command、悪性利用、別個C2の境界説明が不足しています。",
                )


def _normalized_role(value: Any) -> str:
    """role表記を比較用snake caseへ変換する。"""

    return re.sub(r"[^a-z0-9]+", "_", str(value or "").casefold()).strip("_")


def _validate_static_logic_quality(
    repository: Path,
    case_dir: Path,
    logic: Mapping[str, Any],
    validation: CaseValidation,
) -> None:
    """negative symbolのroleとcall／constant coverageのcount整合を検証する。"""

    path = _relative(repository, case_dir / "static-logic.json")
    if logic.get("sha256") != validation.sha256 or logic.get("case_id") not in {
        None,
        f"sha256:{validation.sha256}",
    }:
        validation.add("static_logic_identity_mismatch", path, "静的ロジックのcase identityが一致しません。")
    functions = logic.get("functions")
    coverage = logic.get("coverage")
    call_edges = logic.get("call_edges")
    overall = logic.get("overall_logic")
    if not isinstance(functions, list) or not isinstance(coverage, Mapping):
        validation.add("static_logic_structure_invalid", path, "functionsまたはcoverageがobject契約を満たしません。")
        return
    if not isinstance(call_edges, list):
        validation.add("call_edges_invalid", path, "call_edgesが配列ではありません。")
        call_edges = []
    edge_count = coverage.get("call_edge_count")
    graph_recorded = coverage.get("call_graph_recorded")
    if type(edge_count) is not int or edge_count < 0 or edge_count != len(call_edges):
        validation.add("call_edge_count_mismatch", path, "call_edge_countが公開call_edges件数と一致しません。")
    if type(graph_recorded) is not bool or graph_recorded is not bool(call_edges):
        validation.add("call_graph_completion_mismatch", path, "call graph完了claimがcall edge件数と矛盾します。")
    observed = overall.get("observed_call_edges") if isinstance(overall, Mapping) else None
    if not isinstance(observed, list):
        validation.add("observed_call_edges_invalid", path, "overall_logic.observed_call_edgesがありません。")
        observed = []
    source_pairs = Counter(
        (str(item.get("caller") or ""), str(item.get("callee") or ""))
        for item in call_edges
        if isinstance(item, Mapping)
    )
    observed_pairs = Counter(
        (str(item.get("caller") or ""), str(item.get("callee") or ""))
        for item in observed
        if isinstance(item, Mapping)
    )
    if (
        sum(source_pairs.values()) != len(call_edges)
        or sum(observed_pairs.values()) != len(observed)
        or source_pairs != observed_pairs
    ):
        validation.add("observed_call_edge_projection_mismatch", path, "call_edgesと全体ロジックの観測edgeが一致しません。")

    complete_claim = (
        logic.get("status") in COMPLETE_FUNCTION_STATUSES
        or coverage.get("all_static_analysis_content_retained") is True
    )
    published_constant_count = 0
    declared_constant_count = 0
    for index, function in enumerate(functions):
        if not isinstance(function, Mapping):
            validation.add("function_record_invalid", path, f"functions[{index}]がobjectではありません。")
            continue
        name = str(function.get("name") or "")
        role = _normalized_role(function.get("role"))
        evidence = function.get("evidence")
        confirmed_role = isinstance(evidence, Mapping) and str(
            evidence.get("confidence") or ""
        ).casefold().startswith("confirmed")
        if (
            confirmed_role
            and any(marker in name.casefold() for marker in NEGATIVE_SYMBOLS)
            and (
                role in FORBIDDEN_NEGATIVE_ROLES
                or any(token in role for token in ("persistence", "network", "command"))
            )
        ):
            validation.add(
                "negative_symbol_promoted_to_behavior",
                path,
                f"既知negative symbol {name!r} をconfirmed {role!r} roleへ昇格しています。",
            )
        constants = function.get("constants")
        analysis = function.get("function_analysis")
        source_counts = analysis.get("source_field_counts") if isinstance(analysis, Mapping) else None
        declared = source_counts.get("constants") if isinstance(source_counts, Mapping) else None
        if not isinstance(constants, list) or type(declared) is not int or declared < 0:
            validation.add(
                "constant_coverage_invalid",
                path,
                f"functions[{index}]のconstant配列または元件数が不正です。",
            )
            continue
        published_constant_count += len(constants)
        declared_constant_count += declared
        if complete_claim and declared != len(constants):
            validation.add(
                "constant_coverage_count_mismatch",
                path,
                f"functions[{index}]のconstant完了claimと公開件数が一致しません。",
            )
    if complete_claim and published_constant_count != declared_constant_count:
        validation.add(
            "constant_coverage_total_mismatch",
            path,
            "constant coverageの合計が各関数の取得元件数と一致しません。",
        )
    for key in ("constant_count", "constant_reference_count", "published_constant_count"):
        if key in coverage and coverage.get(key) != published_constant_count:
            validation.add(
                "constant_coverage_summary_mismatch",
                path,
                f"coverage.{key}が公開constant件数と一致しません。",
            )


def _has_process_creation_evidence(
    analysis: Mapping[str, Any],
    features: Mapping[str, Any],
    logic: Mapping[str, Any],
) -> bool:
    """import・特徴・レビュー済み関数のいずれかにprocess creation証拠があるか返す。"""

    for hint in analysis.get("capability_hints") or []:
        if isinstance(hint, Mapping) and hint.get("capability") == "process_creation":
            return True
    for behavior in features.get("behaviors") or []:
        if isinstance(behavior, Mapping) and behavior.get("id") == "execution:process_creation":
            return True
    for function in logic.get("functions") or []:
        if not isinstance(function, Mapping):
            continue
        if _normalized_role(function.get("role")) == "process_creation":
            return True
        values = [function.get("name"), *(function.get("api_calls") or []), *(function.get("callees") or [])]
        lowered = {str(value).casefold() for value in values}
        if any(any(marker in value for marker in PROCESS_CREATION_MARKERS) for value in lowered):
            return True
    return False


def _execution_route_documented(text: str) -> bool:
    """実行経路について確認済み／未確定のどちらかを明示しているか返す。"""

    lowered = text.casefold()
    return "実行経路" in lowered and any(
        marker in lowered
        for marker in ("確認", "確定", "復元", "未完了", "不明", "追跡")
    )


def _fixed_command_recovery_documented(text: str) -> bool:
    """固定commandの復元可否を結論付きで記録しているか返す。"""

    lowered = text.casefold()
    fixed = re.search(r"固定(?:済み|された)?\s*(?:command|コマンド(?:ライン)?)", lowered)
    status = re.search(r"(?:復元|確認|特定).{0,40}(?:可能|でき|済み|未|不可|不能|なし|不明)", lowered)
    reverse = re.search(r"(?:可能|でき|済み|未|不可|不能|なし|不明).{0,40}(?:復元|確認|特定)", lowered)
    return fixed is not None and (status is not None or reverse is not None)


def _validate_process_creation_docs(
    repository: Path,
    case_dir: Path,
    analysis: Mapping[str, Any],
    features: Mapping[str, Any],
    logic: Mapping[str, Any],
    readme: str,
    features_markdown: str,
    validation: CaseValidation,
) -> None:
    """process creation証拠があるcaseだけ実行経路・固定command復元可否を要求する。"""

    if not _has_process_creation_evidence(analysis, features, logic):
        return
    for name, text in (("README.md", readme), ("FEATURES.md", features_markdown)):
        if not _execution_route_documented(text):
            validation.add(
                "process_creation_execution_route_missing",
                _relative(repository, case_dir / name),
                "process creation証拠に対する実行経路の確認状態がありません。",
            )
        if not _fixed_command_recovery_documented(text):
            validation.add(
                "process_creation_fixed_command_status_missing",
                _relative(repository, case_dir / name),
                "process creation証拠に対する固定command復元可否がありません。",
            )


def _validate_case_identity(
    repository: Path,
    case_dir: Path,
    record: Mapping[str, Any],
    documents: Mapping[str, Mapping[str, Any]],
    readme: str,
    features_markdown: str,
    validation: CaseValidation,
) -> None:
    """report外の公開成果物も同じcase SHA-256へ結合する。"""

    digest = validation.sha256
    identities: list[tuple[str, Any]] = []
    analysis = documents.get("analysis.json", {})
    analysis_case = analysis.get("case") if isinstance(analysis, Mapping) else None
    identities.append(("analysis.json", analysis_case.get("sha256") if isinstance(analysis_case, Mapping) else None))
    features = documents.get("features.json", {})
    identities.append(("features.json", features.get("sha256")))
    logic = documents.get("static-logic.json", {})
    identities.append(("static-logic.json", logic.get("sha256")))
    c2 = documents.get("c2-analysis.json", {})
    identities.append(("c2-analysis.json", c2.get("sha256")))
    communication = documents.get("communication-patterns.json", {})
    identities.append(("communication-patterns.json", communication.get("sha256")))
    orchestration = documents.get("orchestration.json", {})
    identities.append(("orchestration.json", orchestration.get("sample_sha256")))
    metadata = documents.get("metadata.json", {})
    identities.append(("metadata.json", metadata.get("sha256")))
    for name, observed in identities:
        if observed != digest:
            validation.add(
                "artifact_case_identity_mismatch",
                _relative(repository, case_dir / name),
                f"{name}のcase SHA-256がmanifestと一致しません。",
            )
    if features.get("case_id") != f"sha256:{digest}" or metadata.get("case_id") != f"sha256:{digest}":
        validation.add(
            "artifact_case_id_mismatch",
            _relative(repository, case_dir),
            "case_idがmanifestの正規SHA-256 IDと一致しません。",
        )
    expected_path = record.get("case_path")
    if metadata.get("canonical_path") != expected_path:
        validation.add(
            "metadata_canonical_path_mismatch",
            _relative(repository, case_dir / "metadata.json"),
            "metadata canonical_pathがcollection summaryと一致しません。",
        )
    for name, text in (("README.md", readme), ("FEATURES.md", features_markdown)):
        if digest not in text:
            validation.add(
                "markdown_case_identity_missing",
                _relative(repository, case_dir / name),
                "人間向け文書にcase SHA-256がありません。",
            )


def _validate_case(
    repository: Path,
    case_dir: Path,
    digest: str,
    record: Mapping[str, Any],
) -> tuple[CaseValidation, bool]:
    """1件の公開caseを暗号学的・意味的に検証する。"""

    relative_case = _relative(repository, case_dir)
    validation = CaseValidation(sha256=digest, case_path=relative_case)
    report = _load_case_json(repository, case_dir, "report.json", validation)
    if report is None:
        return validation, False
    integrity = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        require_resumable=False,
    )
    for code in integrity:
        validation.add(
            "report_integrity_error",
            _relative(repository, case_dir / "report.json"),
            f"report seal／artifact hash／case契約違反: {code}",
        )

    required_json = (
        "analysis.json",
        "features.json",
        "static-logic.json",
        "family-routing.json",
        "classification.json",
        "metadata.json",
        "communication-patterns.json",
        "c2-analysis.json",
        "orchestration.json",
    )
    documents: dict[str, Mapping[str, Any]] = {}
    for name in required_json:
        document = _load_case_json(repository, case_dir, name, validation)
        if document is not None:
            documents[name] = document
    readme = _load_markdown(repository, case_dir, "README.md", validation)
    features_markdown = _load_markdown(repository, case_dir, "FEATURES.md", validation)
    if readme is None or features_markdown is None:
        return validation, False
    if len(documents) != len(required_json):
        return validation, False

    _validate_case_identity(
        repository,
        case_dir,
        record,
        documents,
        readme,
        features_markdown,
        validation,
    )
    provider_only = _validate_provider_boundary(
        repository,
        case_dir,
        record,
        report,
        documents["family-routing.json"],
        documents,
        readme,
        features_markdown,
        validation,
    )
    _validate_screenconnect_complete(
        repository,
        case_dir,
        report,
        documents,
        readme,
        features_markdown,
        validation,
    )
    _validate_static_logic_quality(
        repository,
        case_dir,
        documents["static-logic.json"],
        validation,
    )
    _validate_process_creation_docs(
        repository,
        case_dir,
        documents["analysis.json"],
        documents["features.json"],
        documents["static-logic.json"],
        readme,
        features_markdown,
        validation,
    )
    return validation, provider_only


def _validate_collection_summary(
    repository: Path,
    collection_dir: Path,
    summary: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    validations: list[CaseValidation],
    provider_digests: set[str],
) -> list[Finding]:
    """collection集計の帰属表現と関数countをcase結果へ照合する。"""

    findings: list[Finding] = []
    summary_path = _relative(repository, collection_dir / "publication-summary.json")
    collection_readme_path = collection_dir / "README.md"
    try:
        readme = _read_markdown(collection_readme_path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [
            Finding(
                "collection_readme_invalid",
                _relative(repository, collection_readme_path),
                f"collection READMEを安全に読めません: {exc}",
            )
        ]
    if provider_digests:
        boundary = re.search(
            r"(?:内部|本解析).{0,40}静的確認.{0,40}(?:なし|未|ではありません|していません)",
            readme,
            flags=re.DOTALL,
        )
        if "提供元報告" not in readme or boundary is None:
            findings.append(
                Finding(
                    "collection_provider_boundary_missing",
                    _relative(repository, collection_readme_path),
                    "provider-only groupを内部静的確認済みfamilyと区別する説明がありません。",
                )
            )
        provider_families = {
            str(records[digest].get("family") or "")
            for digest in provider_digests
            if digest in records
        }
        for family in sorted(provider_families - {"", "unclassified", "unknown"}):
            definite_row = re.search(
                rf"(?m)^\|\s*\[{re.escape(family)}\][^|]*\|\s*\d+\s*\|",
                readme,
                flags=re.IGNORECASE,
            )
            if definite_row and re.search(r"(?mi)^\|\s*正規分類\s*\|", readme):
                findings.append(
                    Finding(
                        "collection_provider_group_as_canonical_family",
                        _relative(repository, collection_readme_path),
                        f"provider-only group {family!r} を正規分類として表示しています。",
                    )
                )

    function_summary = summary.get("function_analysis")
    if isinstance(function_summary, Mapping):
        case_logic: list[Mapping[str, Any]] = []
        for validation in validations:
            if not validation.case_path:
                continue
            try:
                case_logic.append(
                    _load_json(repository / validation.case_path / "static-logic.json")
                )
            except (OSError, TypeError, ValueError):
                continue
        mappings = {
            "discovered_function_inventory_count": "discovered_function_inventory_count",
            "characteristic_function_selected_count": "characteristic_function_selected_count",
            "characteristic_function_attempted_count": "decompilation_attempted_count",
            "decompilation_succeeded_count": "decompilation_succeeded_count",
            "decompilation_limited_or_failed_count": "decompilation_limited_or_failed_count",
            "decompilation_excluded_count": "decompilation_excluded_count",
            "unselected_function_count": "unselected_function_count",
            "ghidra_function_inventory_count": "ghidra_function_inventory_count",
            "managed_method_inventory_count": "managed_method_inventory_count",
            "ghidra_programs_with_valid_mcp_responses": "ghidra_programs_with_valid_mcp_responses",
        }
        for summary_key, case_key in mappings.items():
            expected = sum(
                int(logic.get("coverage", {}).get(case_key) or 0)
                for logic in case_logic
                if isinstance(logic.get("coverage"), Mapping)
                and type(logic["coverage"].get(case_key)) is int
            )
            if function_summary.get(summary_key) != expected:
                findings.append(
                    Finding(
                        "collection_function_count_mismatch",
                        summary_path,
                        f"function_analysis.{summary_key}がcase合計{expected}と一致しません。",
                    )
                )
        if function_summary.get("root_cases") != len(records):
            findings.append(
                Finding(
                    "collection_function_root_count_mismatch",
                    summary_path,
                    "function_analysis.root_casesがmanifest件数と一致しません。",
                )
            )
        if function_summary.get("all_static_analysis_content_retained") is True and any(
            any(item.code.startswith(("call_", "constant_", "observed_call_")) for item in result.findings)
            for result in validations
        ):
            findings.append(
                Finding(
                    "collection_function_completion_claim_inconsistent",
                    summary_path,
                    "全静的解析内容保持claimがcaseのcall／constant coverage違反と矛盾します。",
                )
            )
    return findings


def validate_collection(repository: Path, collection: Path) -> dict[str, Any]:
    """指定collectionの全caseと集計を検証し、機械可読結果を返す。"""

    repository = repository.resolve(strict=True)
    collection_dir = collection.resolve(strict=True)
    collection_root = (repository / "analysis-results" / "collections").resolve(strict=True)
    top_findings: list[Finding] = []
    validations: list[CaseValidation] = []
    try:
        if not _inside(collection_dir, collection_root) or collection_dir == collection_root:
            raise ValueError("--collectionはrepository内の個別collection directoryに限定されます")
        ensure_no_reparse_components(collection_dir)
        manifest = _load_json(collection_dir / "manifest.json")
        summary = _load_json(collection_dir / "publication-summary.json")
        digests = _manifest_digests(manifest)
        records = _summary_case_records(summary, digests)
    except (OSError, TypeError, ValueError) as exc:
        top_findings.append(
            Finding(
                "collection_contract_invalid",
                _relative(repository, collection_dir),
                str(exc),
            )
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "collection": _relative(repository, collection_dir),
            "case_count": 0,
            "valid_cases": 0,
            "invalid_cases": 0,
            "complete": False,
            "finding_count": len(top_findings),
            "findings": [item.as_dict() for item in top_findings],
            "results": [],
            "safety": {
                "network_contacted": False,
                "samples_opened": False,
                "samples_executed": False,
            },
        }

    provider_digests: set[str] = set()
    for digest in digests:
        record = records[digest]
        try:
            case_dir = _resolve_case_dir(repository, digest, record)
        except (OSError, TypeError, ValueError) as exc:
            missing = CaseValidation(sha256=digest, case_path=str(record.get("case_path") or ""))
            missing.add(
                "case_resolution_failed",
                str(record.get("case_path") or "publication-summary.json"),
                str(exc),
            )
            validations.append(missing)
            continue
        result, provider_only = _validate_case(repository, case_dir, digest, record)
        validations.append(result)
        if provider_only:
            provider_digests.add(digest)
    top_findings.extend(
        _validate_collection_summary(
            repository,
            collection_dir,
            summary,
            records,
            validations,
            provider_digests,
        )
    )
    finding_count = len(top_findings) + sum(len(item.findings) for item in validations)
    complete = not top_findings and all(item.valid for item in validations)
    return {
        "schema_version": SCHEMA_VERSION,
        "collection": _relative(repository, collection_dir),
        "case_count": len(validations),
        "valid_cases": sum(item.valid for item in validations),
        "invalid_cases": sum(not item.valid for item in validations),
        "provider_only_cases": len(provider_digests),
        "complete": complete,
        "finding_count": finding_count,
        "findings": [item.as_dict() for item in top_findings],
        "results": [item.as_dict() for item in validations],
        "safety": {
            "network_contacted": False,
            "samples_opened": False,
            "samples_executed": False,
        },
    }


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語にする。"""

    def format_help(self) -> str:
        """標準見出しを日本語化する。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    """公開CLI parserを作る。"""

    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True, help="リポジトリroot")
    parser.add_argument("--collection", type=Path, required=True, help="検証するcollection directory")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """CLI entrypoint。違反が1件でもあればexit 1を返す。"""

    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        result = validate_collection(args.repository, args.collection)
    except (OSError, TypeError, ValueError) as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "collection": str(args.collection),
            "case_count": 0,
            "valid_cases": 0,
            "invalid_cases": 0,
            "complete": False,
            "finding_count": 1,
            "findings": [
                {
                    "code": "validator_input_invalid",
                    "path": str(args.collection),
                    "message": str(exc),
                }
            ],
            "results": [],
            "safety": {
                "network_contacted": False,
                "samples_opened": False,
                "samples_executed": False,
            },
        }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
