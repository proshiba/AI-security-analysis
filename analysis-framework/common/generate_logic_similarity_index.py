#!/usr/bin/env python3
"""感染チェーンと全体ロジックの比較プロファイルを横断生成する。

関数単位のコード類似性とは分離し、実行段階、復元層、モジュール、
機能、代表関数の役割、コードfingerprintを独立した比較軸として扱う。
単一軸の一致だけでは類似候補に昇格しない。
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from itertools import combinations
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
MAX_MATCHES_PER_CASE = 10
MAX_SHARED_ITEMS = 8
SHA256_LENGTH = 64

DIMENSION_WEIGHTS = {
    "execution_stages": 2.0,
    "layer_chain": 2.0,
    "module_stack": 1.5,
    "capabilities": 1.0,
    "function_roles": 1.5,
    "code_fingerprints": 3.0,
}

DIMENSION_LABELS = {
    "execution_stages": "実行段階",
    "layer_chain": "感染・復元層",
    "module_stack": "モジュール構成",
    "capabilities": "機能・挙動",
    "function_roles": "代表関数の役割",
    "code_fingerprints": "コードfingerprint",
}

CANONICAL_STAGE_ALIASES = {
    "delivery": ("delivery", "initial_access", "attachment", "distribution"),
    "script_execution": ("script", "javascript", "jscript", "powershell", "wscript"),
    "payload_decoding": (
        "configuration",
        "decode",
        "decrypt",
        "deobfusc",
        "payload",
        "resource",
        "unpack",
    ),
    "loader_execution": ("startup", "entry", "init", "loader", "execution"),
    "defense_evasion": ("anti", "evasion", "environment", "sandbox", "vm"),
    "persistence": ("persistence", "autorun", "scheduled_task", "service"),
    "process_memory": ("inject", "memory", "process", "thread"),
    "credential_collection": ("browser", "credential", "mail", "password"),
    "input_capture": ("clipboard", "input", "keylog", "screenshot"),
    "host_discovery": ("fingerprint", "host", "recon", "system"),
    "staging": ("archive", "report", "stage", "staging"),
    "command_control": ("c2", "command", "communication", "network"),
    "exfiltration": ("exfil", "ftp", "smtp", "upload"),
    "file_operations": ("file", "filesystem"),
    "cleanup": ("cleanup", "delete", "self_delete"),
}


def _load_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _string_set(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {
        str(value).strip().casefold()
        for value in values
        if isinstance(value, (str, int, float)) and str(value).strip()
    }


def _canonical_stage(*values: Any) -> str:
    rendered_values = [str(value or "").casefold() for value in values]
    for value in rendered_values:
        if value in CANONICAL_STAGE_ALIASES:
            return value
    rendered = " ".join(rendered_values)
    for stage, aliases in CANONICAL_STAGE_ALIASES.items():
        if any(alias in rendered for alias in aliases):
            return stage
    return ""


def _function_records(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        function
        for function in report.get("functions", [])
        if isinstance(function, Mapping)
    ]


def _execution_stages(report: Mapping[str, Any]) -> set[str]:
    overall = report.get("overall_logic")
    if not isinstance(overall, Mapping):
        return set()
    output: set[str] = set()
    for phase in overall.get("phases", []):
        if not isinstance(phase, Mapping):
            continue
        roles = phase.get("roles", [])
        role_text = " ".join(str(value) for value in roles) if isinstance(roles, list) else ""
        stage = _canonical_stage(
            phase.get("phase_id"),
            phase.get("phase"),
            phase.get("title_ja"),
            role_text,
        )
        if stage:
            output.add(stage)
    return output


def _layer_chain(static_layers: Mapping[str, Any]) -> set[str]:
    layers = [
        layer
        for layer in static_layers.get("layers", [])
        if isinstance(layer, Mapping)
    ]
    by_sha = {
        str(layer.get("sha256") or "").casefold(): layer
        for layer in layers
        if layer.get("sha256")
    }
    output: set[str] = set()
    for layer in layers:
        current_format = str(layer.get("format") or "unknown").casefold()
        transform = str(layer.get("transform") or "unknown").casefold()
        parent = by_sha.get(str(layer.get("parent_sha256") or "").casefold())
        if parent is None:
            output.add(f"root:{current_format}")
            continue
        parent_format = str(parent.get("format") or "unknown").casefold()
        output.add(f"{parent_format}--{transform}-->{current_format}")
    return output


def _module_stack(report: Mapping[str, Any]) -> set[str]:
    output: set[str] = set()
    for program in report.get("program_evidence", []):
        if not isinstance(program, Mapping):
            continue
        file_format = str(
            program.get("format")
            or program.get("language")
            or program.get("architecture")
            or "unknown"
        ).casefold()
        relationship = str(
            program.get("relationship") or "relationship_unknown"
        ).casefold()
        output.add(f"{relationship}:{file_format}")
    return output


def _capabilities(features: Mapping[str, Any]) -> set[str]:
    output: set[str] = set()
    for field in ("sample_characteristics", "behaviors"):
        for record in features.get(field, []):
            if not isinstance(record, Mapping):
                continue
            identifier = str(record.get("id") or "").casefold()
            if not identifier or identifier.startswith(("version:", "format:")):
                continue
            output.add(identifier)
    return output


def _function_roles(report: Mapping[str, Any]) -> set[str]:
    return {
        str(function.get("role")).casefold()
        for function in _function_records(report)
        if function.get("role")
        and str(function.get("role")).casefold()
        not in {"general_internal_logic", "unclassified", "unknown"}
    }


def _code_fingerprints(report: Mapping[str, Any]) -> set[str]:
    output: set[str] = set()
    for function in _function_records(report):
        fingerprints = function.get("fingerprints")
        if not isinstance(fingerprints, Mapping):
            continue
        semantic = str(fingerprints.get("semantic_sequence_sha256") or "").casefold()
        normalized = str(fingerprints.get("normalized_logic_sha256") or "").casefold()
        token_count = int(fingerprints.get("semantic_token_count") or 0)
        if len(semantic) == SHA256_LENGTH and token_count >= 4:
            output.add(f"semantic:{semantic}")
        elif len(normalized) == SHA256_LENGTH and token_count >= 4:
            output.add(f"normalized:{normalized}")
    return output


def build_profile(
    *,
    sha256: str,
    case_record: Mapping[str, Any],
    report: Mapping[str, Any],
    static_layers: Mapping[str, Any],
    features: Mapping[str, Any],
) -> dict[str, Any]:
    """1 caseの比較プロファイルを決定的な順序で返す。"""

    dimensions = {
        "execution_stages": _execution_stages(report),
        "layer_chain": _layer_chain(static_layers),
        "module_stack": _module_stack(report),
        "capabilities": _capabilities(features),
        "function_roles": _function_roles(report),
        "code_fingerprints": _code_fingerprints(report),
    }
    return {
        "case_id": f"sha256:{sha256}",
        "sha256": sha256,
        "family": str(case_record.get("family") or report.get("family") or "unknown"),
        "version_key": str(case_record.get("version_key") or "unknown"),
        "canonical_path": str(case_record.get("canonical_path") or ""),
        "dimensions": {
            name: sorted(values)
            for name, values in dimensions.items()
        },
        "available_dimensions": [
            name for name, values in dimensions.items() if values
        ],
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def compare_profiles(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> dict[str, Any] | None:
    """2 caseを比較し、最低2独立軸を満たす候補だけを返す。"""

    left_dimensions = left.get("dimensions")
    right_dimensions = right.get("dimensions")
    if not isinstance(left_dimensions, Mapping) or not isinstance(
        right_dimensions, Mapping
    ):
        return None

    evidence: list[dict[str, Any]] = []
    weighted_score = 0.0
    available_weight = 0.0
    for name, weight in DIMENSION_WEIGHTS.items():
        left_values = _string_set(left_dimensions.get(name))
        right_values = _string_set(right_dimensions.get(name))
        if not left_values or not right_values:
            continue
        similarity = _jaccard(left_values, right_values)
        available_weight += weight
        weighted_score += similarity * weight
        shared = sorted(left_values & right_values)
        if shared:
            evidence.append(
                {
                    "dimension": name,
                    "label_ja": DIMENSION_LABELS[name],
                    "similarity": round(similarity, 4),
                    "shared": shared[:MAX_SHARED_ITEMS],
                    "shared_total": len(shared),
                }
            )

    if len(evidence) < 2 or available_weight == 0:
        return None
    score = round(weighted_score / available_weight, 4)
    same_family = str(left.get("family")) == str(right.get("family"))
    evidence_names = {item["dimension"] for item in evidence}
    layer_similarity = next(
        (
            float(item["similarity"])
            for item in evidence
            if item["dimension"] == "layer_chain"
        ),
        0.0,
    )
    if not same_family and not (
        "code_fingerprints" in evidence_names
        or (layer_similarity >= 0.75 and len(evidence) >= 3)
    ):
        return None
    if score < 0.34:
        return None

    if score >= 0.72 and len(evidence) >= 3 and (
        "code_fingerprints" in evidence_names or layer_similarity >= 0.75
    ):
        level = "高"
    elif score >= 0.50:
        level = "中"
    else:
        level = "参考候補"
    return {
        "left_sha256": str(left.get("sha256") or ""),
        "right_sha256": str(right.get("sha256") or ""),
        "same_family": same_family,
        "score": score,
        "level": level,
        "independent_evidence_axes": len(evidence),
        "evidence": evidence,
        "assessment": "類似候補。campaignまたはactorの同一性を意味しません。",
    }


def _retain_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority = {"高": 0, "中": 1, "参考候補": 2}
    ordered = sorted(
        matches,
        key=lambda item: (
            priority[item["level"]],
            -float(item["score"]),
            -int(item["independent_evidence_axes"]),
            item["left_sha256"],
            item["right_sha256"],
        ),
    )
    retained: list[dict[str, Any]] = []
    per_case: dict[str, int] = {}
    for match in ordered:
        left = match["left_sha256"]
        right = match["right_sha256"]
        if (
            per_case.get(left, 0) >= MAX_MATCHES_PER_CASE
            or per_case.get(right, 0) >= MAX_MATCHES_PER_CASE
        ):
            continue
        retained.append(match)
        per_case[left] = per_case.get(left, 0) + 1
        per_case[right] = per_case.get(right, 0) + 1
    return retained


def build_index(repository: Path) -> dict[str, Any]:
    """catalog上の全caseから比較プロファイルと候補を生成する。"""

    root = repository.resolve()
    catalog = _load_object(root / "analysis-results" / "catalog" / "cases.json")
    cases = catalog.get("cases")
    if not isinstance(cases, Mapping):
        raise ValueError("analysis-results/catalog/cases.jsonのcasesがobjectではありません")

    profiles: dict[str, dict[str, Any]] = {}
    for sha256, case_record in sorted(cases.items()):
        if not isinstance(case_record, Mapping):
            continue
        case_dir = root / str(case_record.get("canonical_path") or "")
        report = _load_object(case_dir / "static-logic.json")
        features = _load_object(case_dir / "features.json")
        static_layers = _load_object(case_dir / "static-layers.json")
        if not report and not features and not static_layers:
            continue
        profile = build_profile(
            sha256=str(sha256),
            case_record=case_record,
            report=report,
            static_layers=static_layers,
            features=features,
        )
        for document_name in ("OVERALL-LOGIC.md", "README.md"):
            if (case_dir / document_name).is_file():
                profile["document_path"] = (
                    str(case_record.get("canonical_path") or "").rstrip("/")
                    + "/"
                    + document_name
                )
                break
        if len(profile["available_dimensions"]) >= 2:
            profiles[str(sha256)] = profile

    matches = []
    for left_sha, right_sha in combinations(sorted(profiles), 2):
        match = compare_profiles(profiles[left_sha], profiles[right_sha])
        if match is not None:
            matches.append(match)
    retained = _retain_matches(matches)
    level_counts = {
        level: sum(1 for match in retained if match["level"] == level)
        for level in ("高", "中", "参考候補")
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "comparison_contract": {
            "minimum_independent_evidence_axes": 2,
            "same_family_is_evidence": False,
            "single_ioc_is_evidence": False,
            "actor_or_campaign_attribution_automatic": False,
            "max_matches_per_case": MAX_MATCHES_PER_CASE,
        },
        "counts": {
            "catalog_cases": len(cases),
            "profiled_cases": len(profiles),
            "candidate_pairs_before_limit": len(matches),
            "retained_pairs": len(retained),
            "levels": level_counts,
        },
        "profiles": profiles,
        "matches": retained,
        "limitations": [
            "比較対象に構造化成果物がない場合はprofileを作成できません。",
            "同じpacker、builder、runtime、共通libraryでも一致し得ます。",
            "類似候補はcampaign、actor、ファミリーの同一性を自動確定しません。",
        ],
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }


def _profile_link(profiles: Mapping[str, Any], sha256: str) -> str:
    profile = profiles.get(sha256)
    profile = profile if isinstance(profile, Mapping) else {}
    family = str(profile.get("family") or "unknown").replace("|", "/")
    document = str(profile.get("document_path") or "")
    label = f"{family} / {sha256[:12]}\N{HORIZONTAL ELLIPSIS}"
    prefix = "analysis-results/"
    if document.startswith(prefix):
        target = "../" + document[len(prefix) :]
        return f"[{label}]({target})"
    return f"`{label}`"


def render_markdown(index: Mapping[str, Any]) -> str:
    """比較索引をレビューしやすい日本語Markdownへ描画する。"""

    counts = index.get("counts")
    counts = counts if isinstance(counts, Mapping) else {}
    profiles = index.get("profiles")
    profiles = profiles if isinstance(profiles, Mapping) else {}
    lines = [
        "# 感染チェーン・全体ロジック類似性",
        "",
        "この索引は、感染・復元層、実行段階、モジュール構成、機能、代表関数の役割、"
        "コードfingerprintを検体横断で比較したレビュー候補です。",
        "同一ファミリー名や単一IOCは類似性の証拠に数えず、最低2つの独立軸を要求します。",
        "",
        "## 集計",
        "",
        f"- カタログcase: {int(counts.get('catalog_cases') or 0):,}件",
        f"- 比較プロファイル作成済み: {int(counts.get('profiled_cases') or 0):,}件",
        f"- 保持した候補pair: {int(counts.get('retained_pairs') or 0):,}件",
        "",
        "## 類似候補",
        "",
        "| 評価 | score | case A | case B | 独立軸 | 主な一致 |",
        "|---|---:|---|---|---:|---|",
    ]
    matches = [
        match
        for match in index.get("matches", [])
        if isinstance(match, Mapping)
    ]
    if not matches:
        lines.append("| なし | 0.0000 | - | - | 0 | 比較可能な候補なし |")
    for match in matches:
        evidence = [
            item
            for item in match.get("evidence", [])
            if isinstance(item, Mapping)
        ]
        labels = "、".join(str(item.get("label_ja")) for item in evidence[:4])
        lines.append(
            f"| {match.get('level')} | {float(match.get('score') or 0):.4f} | "
            f"{_profile_link(profiles, str(match.get('left_sha256') or ''))} | "
            f"{_profile_link(profiles, str(match.get('right_sha256') or ''))} | "
            f"{int(match.get('independent_evidence_axes') or 0)} | {labels} |"
        )
    lines.extend(
        [
            "",
            "## 解釈上の注意",
            "",
            "- 「高」「中」「参考候補」は解析レビューの優先度であり、帰属の確定ではありません。",
            "- builder、packer、runtime、共通libraryの共有でも一致します。",
            "- 最終判断では配布文脈、時系列、設定形式、通信、署名、IOC、コード詳細を追加相関します。",
            "",
        ]
    )
    return "\n".join(lines)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def generate(
    repository: Path,
    *,
    output_json: Path,
    output_markdown: Path,
    write: bool = False,
    check: bool = False,
) -> dict[str, Any]:
    """比較索引を生成し、writeまたはcheck結果を返す。"""

    if write and check:
        raise ValueError("--writeと--checkは同時指定できません")
    index = build_index(repository)
    expected = {
        output_json: json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        output_markdown: render_markdown(index),
    }
    mismatches = [
        path.relative_to(repository.resolve()).as_posix()
        for path, content in expected.items()
        if not path.is_file()
        or path.read_text(encoding="utf-8-sig") != content
    ]
    if write:
        for path, content in expected.items():
            _atomic_write(path, content)
    return {
        "profiled_cases": index["counts"]["profiled_cases"],
        "retained_pairs": index["counts"]["retained_pairs"],
        "mismatches": mismatches,
        "write_performed": bool(write and mismatches),
        "check_failed": bool(check and mismatches),
    }


def build_parser() -> argparse.ArgumentParser:
    """CLI引数parserを返す。"""

    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument("--write", action="store_true", help="比較索引を更新する")
    parser.add_argument("--check", action="store_true", help="差分があれば終了コード1を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLIを実行する。"""

    args = build_parser().parse_args(argv)
    root = args.repository.resolve()
    result = generate(
        root,
        output_json=root / "analysis-results" / "catalog" / "logic-similarity.json",
        output_markdown=root / "analysis-results" / "catalog" / "LOGIC-SIMILARITY.md",
        write=args.write,
        check=args.check,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
