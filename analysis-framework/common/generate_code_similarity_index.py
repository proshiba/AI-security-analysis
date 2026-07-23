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


SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
SIMHASH64_RE = re.compile(r"^[0-9a-f]{16}$", re.IGNORECASE)
MARKDOWN_PAIR_LIMIT = 1000


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
            if not SIMHASH64_RE.fullmatch(simhash) or not SHA256_RE.fullmatch(semantic_sha256) or token_count < 4:
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


def _ghidra_hash_records(results_root: Path) -> list[dict[str, Any]]:
    """Ghidra opcode hashをcase横断の完全一致比較用に収集する。"""

    output = []
    for path in sorted(results_root.rglob("static-logic.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, Mapping):
            continue
        sha256 = str(value.get("sha256") or path.parent.name).casefold()
        if not SHA256_RE.fullmatch(sha256):
            continue
        family = str(value.get("family") or "unknown")
        seen: set[tuple[str, str, str]] = set()
        for program in value.get("program_evidence", []):
            if not isinstance(program, Mapping):
                continue
            selector = str(program.get("program_selector") or "not_recorded")
            relationship = str(program.get("relationship") or "unknown")
            for function in program.get("function_hashes", []):
                if not isinstance(function, Mapping):
                    continue
                digest = str(function.get("hash") or "").casefold()
                instruction_count = int(function.get("instruction_count") or 0)
                address = str(function.get("address") or "unknown")
                identity = (digest, selector, address)
                if not SHA256_RE.fullmatch(digest) or instruction_count < 4 or identity in seen:
                    continue
                seen.add(identity)
                output.append(
                    {
                        "sha256": sha256,
                        "family": family,
                        "program_selector": selector,
                        "relationship": relationship,
                        "function_name": str(function.get("name") or "unknown"),
                        "address": address,
                        "opcode_sha256": digest,
                        "instruction_count": instruction_count,
                        "source": path.relative_to(results_root.parent).as_posix(),
                    }
                )
    return output


def _bands(simhash: str) -> Iterable[str]:
    for index in range(0, 16, 4):
        yield f"{index // 4}:{simhash[index : index + 4]}"


def build_index(results_root: Path) -> dict[str, Any]:
    """exact semantic列とLSH候補から保守的な関数類似pairを作る。"""

    records = _function_records(results_root)
    ghidra_records = _ghidra_hash_records(results_root)
    record_ids = {index: f"fn-{index + 1:06d}" for index in range(len(records))}
    function_records = [{"record_id": record_ids[index], **record} for index, record in enumerate(records)]
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
                "members": [record_ids[index] for index in members],
            }
        )
    ghidra_exact: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(ghidra_records):
        ghidra_exact[record["opcode_sha256"]].append(index)
    ghidra_exact_groups = []
    for fingerprint, members in sorted(ghidra_exact.items()):
        case_hashes = {ghidra_records[index]["sha256"] for index in members}
        if len(case_hashes) < 2:
            continue
        ghidra_exact_groups.append(
            {
                "opcode_sha256": fingerprint,
                "members": [ghidra_records[index] for index in members],
            }
        )
    simhash_exact: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        simhash_exact[record["semantic_simhash64"]].append(index)
    simhash_groups = []
    for fingerprint, members in sorted(simhash_exact.items()):
        case_hashes = {records[index]["sha256"] for index in members}
        if len(case_hashes) < 2:
            continue
        simhash_groups.append(
            {
                "semantic_simhash64": fingerprint,
                "members": [record_ids[index] for index in members],
            }
        )
    pairs = []
    evaluated = 0
    for bucket_name, members in sorted(buckets.items()):
        by_simhash: dict[str, list[int]] = defaultdict(list)
        for index in sorted(members):
            by_simhash[records[index]["semantic_simhash64"]].append(index)
        for left_hash, right_hash in combinations(sorted(by_simhash), 2):
            common_bands = sorted(set(_bands(left_hash)) & set(_bands(right_hash)))
            if not common_bands or bucket_name != common_bands[0]:
                continue
            distance = (int(left_hash, 16) ^ int(right_hash, 16)).bit_count()
            if distance > 8:
                continue
            for left_index in by_simhash[left_hash]:
                for right_index in by_simhash[right_hash]:
                    left, right = records[left_index], records[right_index]
                    if left["sha256"] == right["sha256"]:
                        continue
                    same_family = left["family"] == right["family"]
                    shared_api = sorted(set(left["api_calls"]) & set(right["api_calls"]))
                    if not same_family and len(shared_api) < 2:
                        continue
                    evaluated += 1
                    maximum_distance = 8 if same_family else 3
                    if distance > maximum_distance:
                        continue
                    pairs.append(
                        {
                            "left_id": record_ids[left_index],
                            "right_id": record_ids[right_index],
                            "similarity": 1.0 - (distance / 64.0),
                            "exact_semantic_sequence": False,
                            "same_family": same_family,
                            "shared_api_calls": shared_api,
                            "assessment": "code_similarity_candidate",
                        }
                    )
    return {
        "schema_version": 2,
        "analysis_mode": "static_function_fingerprint_correlation",
        "counts": {
            "logic_files": len(list(results_root.rglob("static-logic.json"))),
            "functions": len(records),
            "exact_groups": len(exact_groups),
            "simhash_groups": len(simhash_groups),
            "similarity_pairs": len(pairs),
            "candidate_pairs_evaluated": evaluated,
            "ghidra_function_hashes": len(ghidra_records),
            "ghidra_exact_groups": len(ghidra_exact_groups),
        },
        "exact_groups": exact_groups,
        "function_records": function_records,
        "simhash_groups": simhash_groups,
        "similarity_pairs": pairs,
        "ghidra_exact_groups": ghidra_exact_groups,
        "limitations": [
            "類似性はコード共有、共通library、compiler生成処理でも生じます。",
            "類似性だけでファミリー、actor、campaignを確定しません。",
            "異なるdecompiler設定や難読化によりfingerprintが変化する可能性があります。",
            "Ghidra opcode hash完全一致も、共通libraryやcompiler生成処理を除外するものではありません。",
            "完全一致とSimHash完全一致はgroupへ全memberを保持し、重複する二者pairへ展開しません。",
            "JSONでは関数recordを一度だけ保持し、groupとpairからrecord IDで参照します。",
        ],
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    """コード類似性索引を日本語Markdownへ描画する。"""

    records_by_id = {
        str(item["record_id"]): item
        for item in report.get("function_records", [])
        if isinstance(item, Mapping) and item.get("record_id")
    }
    all_pairs = list(report.get("similarity_pairs", []))
    displayed_pairs = sorted(
        all_pairs,
        key=lambda item: (
            -float(item.get("similarity", 0.0)),
            bool(item.get("same_family")),
            str(item.get("left_id", "")),
            str(item.get("right_id", "")),
        ),
    )[:MARKDOWN_PAIR_LIMIT]
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
        f"| fingerprint対象関数 | {report['counts']['functions']} |",
        f"| 完全一致group | {report['counts']['exact_groups']} |",
        f"| SimHash完全一致group | {report['counts']['simhash_groups']} |",
        f"| 評価した非一致候補pair | {report['counts']['candidate_pairs_evaluated']} |",
        f"| 類似候補pair | {report['counts']['similarity_pairs']} |",
        f"| Ghidra関数hash | {report['counts']['ghidra_function_hashes']} |",
        f"| Ghidra完全一致group | {report['counts']['ghidra_exact_groups']} |",
        "",
        "## Ghidra opcode hash完全一致",
        "",
        "異なるcase間で同じopcode hashを持つ関数です。役割や帰属は別途レビューが必要です。",
        "",
        "| opcode hash | case／program／関数 |",
        "|---|---|",
    ]
    for group in report.get("ghidra_exact_groups", []):
        members = ", ".join(
            f"`{item['sha256'][:12]}:{item['program_selector']}:{item['function_name']}`" for item in group["members"]
        )
        lines.append(f"| `{group['opcode_sha256']}` | {members} |")
    if not report.get("ghidra_exact_groups"):
        lines.append("| - | - |")
    lines.extend(
        [
            "",
            "## 類似候補",
            "",
            (
                f"人間向け一覧には類似度の高い順に最大{MARKDOWN_PAIR_LIMIT:,}件を表示します。"
                "全候補はJSON索引を参照してください。"
            ),
            "",
            "| 左case／関数 | 右case／関数 | 類似度 | 同一ファミリー |",
            "|---|---|---:|---|",
        ]
    )
    for pair in displayed_pairs:
        left = records_by_id.get(str(pair.get("left_id")), {})
        right = records_by_id.get(str(pair.get("right_id")), {})
        lines.append(
            f"| `{str(left.get('sha256', 'unknown'))[:12]}:{left.get('function_id', 'unknown')}` | "
            f"`{str(right.get('sha256', 'unknown'))[:12]}:{right.get('function_id', 'unknown')}` | "
            f"{pair['similarity']:.4f} | {'はい' if pair['same_family'] else 'いいえ'} |"
        )
    if not displayed_pairs:
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
