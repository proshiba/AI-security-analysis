#!/usr/bin/env python3
"""全caseの正本索引、派生成果物、UIを決定順で一括更新する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

from generate_code_similarity_index import generate as generate_code_similarity
from generate_ioc_lists import generate as generate_ioc_lists
from generate_logic_similarity_index import generate as generate_logic_similarity
from result_layout import build_layout_plan
from sync_result_catalog import sync_case_identity_metadata, sync_catalog


_ROOT_COUNT_RE = re.compile(r"含む[0-9,]+件のSHA-256 caseを扱い")
_RESULTS_TABLE_RE = re.compile(
    r"(?s)(## 現在の収録状況\s+)(?:<!-- case-inventory:start -->\s*)?"
    r"\| 区分 \| 件数 \|\s+\|---\|---:\|.*?"
    r"(?:<!-- case-inventory:end -->\s*)?(?=版名は)"
)
_UNCLASSIFIED_COUNT_RE = re.compile(r"未分類[0-9,]+件は")
_HASH_CHUNK_BYTES = 1024 * 1024
_FORBIDDEN_PUBLICATION_FILENAMES = frozenset({"datastore-upload.json"})


def _validate_publication_safety(repository: Path) -> dict[str, Any]:
    """公開成果物へdatastore upload receiptが混入していないことを検証する。"""

    root = repository.resolve()
    results_root = root / "analysis-results"
    violations = []
    if results_root.is_dir():
        violations = sorted(
            candidate.relative_to(root).as_posix()
            for candidate in results_root.rglob("*")
            if candidate.is_file()
            and candidate.name.casefold() in _FORBIDDEN_PUBLICATION_FILENAMES
        )
    return {
        "forbidden_filenames": sorted(_FORBIDDEN_PUBLICATION_FILENAMES),
        "violations": violations,
    }


def _atomic_text_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except (OSError, UnicodeError):
        Path(temporary).unlink(missing_ok=True)
        raise


def _render_results_inventory_table(counts: dict[str, Any]) -> str:
    rows = [
        ("SHA-256で一意な全case", counts["unique_case_hashes"]),
        ("ファミリ帰属済みcase", counts["malware_cases"]),
        ("未分類case", counts["unclassified_cases"]),
        ("サプライチェーンpayload", counts["supply_chain_payload_cases"]),
        ("版を静的根拠で確認済み", counts["confirmed_malware_versions"]),
        ("exact sampleの外部報告で版を特定", counts["reported_malware_versions"]),
        ("版不明または判定資料不足（ファミリ帰属済み）", counts["unknown_malware_versions"]),
    ]
    lines = [
        "<!-- case-inventory:start -->",
        "| 区分 | 件数 |",
        "|---|---:|",
        *(f"| {label} | {int(value):,} |" for label, value in rows),
        "<!-- case-inventory:end -->",
        "",
    ]
    return "\n".join(lines)


def sync_documented_case_counts(
    repository: Path, counts: dict[str, Any], *, write: bool = False
) -> dict[str, Any]:
    """READMEの全case件数ブロックをレイアウト監査値へ同期する。"""

    root = repository.resolve()
    expected_total = int(counts["unique_case_hashes"])
    updates: dict[Path, str] = {}

    root_readme = root / "README.md"
    root_text = root_readme.read_text(encoding="utf-8-sig")
    replaced_root, root_matches = _ROOT_COUNT_RE.subn(
        f"含む{expected_total:,}件のSHA-256 caseを扱い", root_text, count=1
    )
    if root_matches != 1:
        raise ValueError("README.mdのcase件数記述を一意に特定できません")
    if replaced_root != root_text:
        updates[root_readme] = replaced_root

    results_readme = root / "analysis-results" / "README.md"
    results_text = results_readme.read_text(encoding="utf-8-sig")
    table = _render_results_inventory_table(counts)
    replaced_results, table_matches = _RESULTS_TABLE_RE.subn(
        lambda match: match.group(1) + table,
        results_text,
        count=1,
    )
    if table_matches != 1:
        raise ValueError("analysis-results/README.mdの収録状況表を一意に特定できません")
    replaced_results, count_matches = _UNCLASSIFIED_COUNT_RE.subn(
        f"未分類{int(counts['unclassified_cases']):,}件は",
        replaced_results,
        count=1,
    )
    if count_matches != 1:
        raise ValueError("analysis-results/README.mdの未分類件数を一意に特定できません")
    if replaced_results != results_text:
        updates[results_readme] = replaced_results

    if write:
        for path, content in sorted(updates.items()):
            _atomic_text_write(path, content)
    return {
        "expected_case_count": expected_total,
        "mismatches": [path.relative_to(root).as_posix() for path in sorted(updates)],
        "write_performed": bool(write and updates),
    }


def _checksum_manifest_content(path: Path) -> str:
    portable_text_suffixes = {
        ".asm",
        ".csv",
        ".html",
        ".json",
        ".md",
        ".rules",
        ".txt",
        ".yaml",
        ".yar",
        ".yara",
        ".yml",
    }
    rows = []
    for item in sorted(
        (
            candidate
            for candidate in path.parent.rglob("*")
            if candidate.is_file() and candidate != path
        ),
        key=lambda candidate: candidate.relative_to(path.parent).as_posix().casefold(),
    ):
        rows.append(
            f"{_streaming_sha256(item, normalize_crlf=item.suffix.casefold() in portable_text_suffixes)}  "
            f"{item.relative_to(path.parent).as_posix()}"
        )
    return "\n".join(rows) + ("\n" if rows else "")


def _streaming_sha256(
    path: Path,
    *,
    normalize_crlf: bool,
    chunk_bytes: int = _HASH_CHUNK_BYTES,
) -> str:
    """ファイル全体を保持せず、必要ならCRLFをLFへ正規化してSHA-256を返す。"""

    if chunk_bytes < 1:
        raise ValueError("chunk_bytes must be positive")
    digest = hashlib.sha256()
    trailing_cr = b""
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_bytes):
            content = trailing_cr + chunk
            trailing_cr = b""
            if normalize_crlf and content.endswith(b"\r"):
                content, trailing_cr = content[:-1], b"\r"
            digest.update(content.replace(b"\r\n", b"\n") if normalize_crlf else content)
    if trailing_cr:
        digest.update(trailing_cr)
    return digest.hexdigest()


def sync_checksum_manifests(
    repository: Path, *, write: bool = False
) -> dict[str, Any]:
    """公開成果物内のmanifest.sha256を現在のファイル内容へ同期する。"""

    root = repository.resolve()
    mismatches: list[str] = []
    for path in sorted((root / "analysis-results").glob("**/manifest.sha256")):
        expected = _checksum_manifest_content(path)
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current == expected:
            continue
        mismatches.append(path.relative_to(root).as_posix())
        if write:
            _atomic_text_write(path, expected)
    return {
        "manifests": len(list((root / "analysis-results").glob("**/manifest.sha256"))),
        "mismatches": mismatches,
        "write_performed": bool(write and mismatches),
    }


def _run_ui_command(repository: Path, script: str, *, check: bool) -> dict[str, Any]:
    command = [sys.executable, str(repository / script)]
    if check:
        command.append("--check")
    completed = subprocess.run(
        command,
        cwd=repository,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return {
        "script": script,
        "mode": "check" if check else "write",
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip()[-2000:],
        "stderr": completed.stderr.strip()[-2000:],
        "check_failed": completed.returncode != 0,
    }


def refresh(
    repository: Path, *, write: bool = False, check: bool = False
) -> dict[str, Any]:
    """case identityからUIまでを依存順に更新し、書込み後は同じ範囲を再検証する。"""

    if write and check:
        raise ValueError("--write and --check are mutually exclusive")
    root = repository.resolve()
    mode = "write" if write else "check" if check else "dry_run"
    publication_safety = _validate_publication_safety(root)
    if publication_safety["violations"]:
        raise ValueError(
            "公開成果物に禁止されたdatastore upload receiptがあります: "
            + publication_safety["violations"][0]
        )

    # レイアウト計画の構築は全成果物の走査を伴い、1パスの実行時間のうち最大の
    # 割合を占める。以前は metadata同期・catalog同期・ここ の3箇所がそれぞれ
    # 独自に構築していたため、同じツリーを3回走査していた。
    #
    # 計画は metadata.json の内容も読むので、無条件には使い回せない。
    # metadata同期が実際に書き込んだ場合だけ作り直し、それ以外は共有する。
    plan = build_layout_plan(root)
    if plan.get("errors"):
        raise ValueError(f"layout preflight failed: {plan['errors'][0]}")
    metadata = sync_case_identity_metadata(root, write=write, plan=plan)
    if metadata["write_performed"]:
        plan = build_layout_plan(root)
        if plan.get("errors"):
            raise ValueError(f"layout preflight failed: {plan['errors'][0]}")
    catalog = sync_catalog(root, write=write, plan=plan)
    counts = plan["counts"]
    documents = sync_documented_case_counts(root, counts, write=write)
    iocs = generate_ioc_lists(root, write=write, check=check)
    similarity = generate_code_similarity(
        root,
        output_json=root / "analysis-results" / "catalog" / "code-similarity.json",
        output_markdown=root / "analysis-results" / "catalog" / "CODE-SIMILARITY.md",
        write=write,
        check=check,
    )
    logic_similarity = generate_logic_similarity(
        root,
        output_json=root / "analysis-results" / "catalog" / "logic-similarity.json",
        output_markdown=root / "analysis-results" / "catalog" / "LOGIC-SIMILARITY.md",
        write=write,
        check=check,
    )
    checksums = sync_checksum_manifests(root, write=write)
    ui_data = _run_ui_command(root, "ui/generate_ui_data.py", check=not write)
    portal = _run_ui_command(root, "ui/build_portal_index.py", check=not write)
    if write and (ui_data["returncode"] or portal["returncode"]):
        failed = ui_data if ui_data["returncode"] else portal
        raise RuntimeError(f"UI生成に失敗しました: {failed['script']}: {failed['stderr']}")

    stale = {
        "metadata": bool(metadata["updated_cases"]),
        "catalog": bool(catalog["added_cases"] or catalog["updated_cases"]),
        "documents": bool(documents["mismatches"]),
        "iocs": bool(iocs["mismatches"]),
        "code_similarity": bool(similarity["mismatches"]),
        "logic_similarity": bool(logic_similarity["mismatches"]),
        "checksums": bool(checksums["mismatches"]),
        "ui_data": bool(ui_data["check_failed"]),
        "portal": bool(portal["check_failed"]),
    }
    verification = refresh(root, check=True) if write else None
    check_failed = bool(
        verification["check_failed"] if verification is not None else check and any(stale.values())
    )
    return {
        "schema_version": 1,
        "mode": mode,
        "case_count": counts["unique_case_hashes"],
        "stages": {
            "metadata": metadata,
            "catalog": catalog,
            "documents": documents,
            "iocs": iocs,
            "code_similarity": similarity,
            "logic_similarity": logic_similarity,
            "checksums": checksums,
            "ui_data": ui_data,
            "portal": portal,
        },
        "stale": stale,
        "verification": verification,
        "write_performed": bool(
            write
            and (
                metadata["write_performed"]
                or catalog["write_performed"]
                or documents["write_performed"]
                or iocs["write_performed"]
                or similarity["write_performed"]
                or logic_similarity["write_performed"]
                or checksums["write_performed"]
            )
        ),
        "check_failed": check_failed,
        "safety": {
            "publication": publication_safety,
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """全体反映CLIの引数parserを返す。"""

    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument("--write", action="store_true", help="全派生成物を更新して再検証する")
    parser.add_argument("--check", action="store_true", help="差分があれば終了コード1を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、機械可読な実行結果を出力する。"""

    args = build_parser().parse_args(argv)
    result = refresh(args.repository, write=args.write, check=args.check)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
