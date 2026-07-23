#!/usr/bin/env python3
"""static-logic.jsonから関数コード類似性の横断索引を生成する。"""

from __future__ import annotations

import argparse
from collections import defaultdict
from itertools import combinations
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from static_logic import simhash_similarity


SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
SIMHASH64_RE = re.compile(r"^[0-9a-f]{16}$", re.IGNORECASE)


def _function_records(results_root: Path) -> list[dict[str, Any]]:
    output = []
    for path in sorted(results_root.rglob("static-logic.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, Mapping):
            continue
        sha256 = str(value.get("sha256") or path.parent.name).casefold()
        family = str(value.get("family") or "unknown")
        for function in value.get("functions", []):
            if not isinstance(function, Mapping):
                continue
            fingerprints = function.get("fingerprints")
            if not isinstance(fingerprints, Mapping):
                continue
            simhash = str(fingerprints.get("semantic_simhash64") or "")
            semantic_sha256 = str(fingerprints.get("semantic_sequence_sha256") or "")
            token_count = int(fingerprints.get("semantic_token_count") or 0)
            if (
                not SIMHASH64_RE.fullmatch(simhash)
                or not SHA256_RE.fullmatch(semantic_sha256)
                or token_count < 4
            ):
                continue
            output.append(
                {
                    "sha256": sha256,
                    "family": family,
                    "function_id": str(function.get("function_id") or "unknown"),
                    "role": str(function.get("role") or "unclassified"),
                    "semantic_simhash64": simhash,
                    "semantic_sequence_sha256": semantic_sha256,
                    "semantic_token_count": token_count,
                    "api_calls": sorted({str(item) for item in function.get("api_calls", [])}),
                    "source": path.relative_to(results_root.parent).as_posix(),
                }
            )
    return output


def _bands(simhash: str) -> Iterable[str]:
    for index in range(0, 16, 4):
        yield f"{index // 4}:{simhash[index:index + 4]}"


def build_index(results_root: Path) -> dict[str, Any]:
    """exact semantic列とLSH候補から保守的な関数類似pairを作る。"""

    records = _function_records(results_root)
    exact: dict[str, list[int]] = defaultdict(list)
    buckets: dict[str, set[int]] = defaultdict(set)
    for index, record in enumerate(records):
        exact[record["semantic_sequence_sha256"]].append(index)
        for band in _bands(record["semantic_simhash64"]):
            buckets[band].add(index)
    exact_groups = []
    for fingerprint, members in sorted(exact.items()):
        case_hashes = {records[index]["sha256"] for index in members}
        if len(case_hashes) < 2:
            continue
        exact_groups.append(
            {
                "semantic_sequence_sha256": fingerprint,
                "members": [records[index] for index in members],
            }
        )
    candidates = set()
    for members in buckets.values():
        for left, right in combinations(sorted(members), 2):
            candidates.add((left, right))
    pairs = []
    for left_index, right_index in sorted(candidates):
        left, right = records[left_index], records[right_index]
        if left["sha256"] == right["sha256"]:
            continue
        similarity = simhash_similarity(
            left["semantic_simhash64"], right["semantic_simhash64"]
        )
        same_family = left["family"] == right["family"]
        exact_match = (
            left["semantic_sequence_sha256"] == right["semantic_sequence_sha256"]
        )
        shared_api = sorted(set(left["api_calls"]) & set(right["api_calls"]))
        threshold = 0.86 if same_family else 0.94
        if not exact_match and (similarity < threshold or (not same_family and len(shared_api) < 2)):
            continue
        pairs.append(
            {
                "left": left,
                "right": right,
                "similarity": similarity,
                "exact_semantic_sequence": exact_match,
                "same_family": same_family,
                "shared_api_calls": shared_api,
                "assessment": "code_similarity_candidate",
            }
        )
    return {
        "schema_version": 1,
        "analysis_mode": "static_function_fingerprint_correlation",
        "counts": {
            "logic_files": len(list(results_root.rglob("static-logic.json"))),
            "functions": len(records),
            "exact_groups": len(exact_groups),
            "similarity_pairs": len(pairs),
        },
        "exact_groups": exact_groups,
        "similarity_pairs": pairs,
        "limitations": [
            "類似性はコード共有、共通library、compiler生成処理でも生じます。",
            "類似性だけでファミリー、actor、campaignを確定しません。",
            "異なるdecompiler設定や難読化によりfingerprintが変化する可能性があります。",
        ],
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    """コード類似性索引を日本語Markdownへ描画する。"""

    lines = [
        "# 関数コード類似性索引",
        "",
        "各caseの `static-logic.json` にある正規化fingerprintを相関した索引です。",
        "一致はコード共有の手掛かりであり、ファミリー、actor、campaignの確定ではありません。",
        "",
        "## 集計",
        "",
        "| 項目 | 件数 |",
        "|---|---:|",
        f"| static-logic.json | {report['counts']['logic_files']} |",
        f"| 関数・処理単位 | {report['counts']['functions']} |",
        f"| 完全一致group | {report['counts']['exact_groups']} |",
        f"| 類似候補pair | {report['counts']['similarity_pairs']} |",
        "",
        "## 類似候補",
        "",
        "| 左case／関数 | 右case／関数 | 類似度 | 同一ファミリー |",
        "|---|---|---:|---|",
    ]
    for pair in report.get("similarity_pairs", []):
        left, right = pair["left"], pair["right"]
        lines.append(
            f"| `{left['sha256'][:12]}:{left['function_id']}` | "
            f"`{right['sha256'][:12]}:{right['function_id']}` | "
            f"{pair['similarity']:.4f} | {'はい' if pair['same_family'] else 'いいえ'} |"
        )
    if not report.get("similarity_pairs"):
        lines.append("| - | - | - | - |")
    lines.extend(["", "## 制約", ""])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    lines.append("")
    return "\n".join(lines)


def generate(
    repository: Path,
    *,
    output_json: Path,
    output_markdown: Path,
    write: bool = False,
    check: bool = False,
) -> dict[str, Any]:
    """横断索引を生成し、必要に応じて書込みまたは同期検証を行う。"""

    repository = repository.resolve()
    output_json = output_json.resolve()
    output_markdown = output_markdown.resolve()
    for path in (output_json, output_markdown):
        try:
            path.relative_to(repository)
        except ValueError as exc:
            raise ValueError("similarity outputs must stay within the repository") from exc
    report = build_index(repository / "analysis-results")
    expected = {
        output_json: json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        output_markdown: render_markdown(report),
    }
    mismatches = []
    for path, content in expected.items():
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current != content:
            mismatches.append(path.relative_to(repository).as_posix())
            if write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
    return {
        **report["counts"],
        "mismatches": mismatches,
        "write_performed": bool(write and mismatches),
        "check_failed": bool(check and mismatches),
    }


def build_parser() -> argparse.ArgumentParser:
    """日本語helpを持つコード類似性索引CLIを構築する。"""

    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument(
        "--output-json",
        type=Path,
        default=repository / "analysis-results" / "catalog" / "code-similarity.json",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=repository / "analysis-results" / "catalog" / "CODE-SIMILARITY.md",
    )
    parser.add_argument("--write", action="store_true", help="類似性索引を更新する")
    parser.add_argument("--check", action="store_true", help="生成差分があれば非0を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、書込みまたは同期検証の終了codeを返す。"""

    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    result = generate(
        args.repository,
        output_json=args.output_json,
        output_markdown=args.output_markdown,
        write=args.write,
        check=args.check,
    )
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "mismatches"},
            ensure_ascii=False,
            indent=2,
        )
    )
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
