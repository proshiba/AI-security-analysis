"""Triageのfamily検索から、完全SHA-256取得用の非公開manifestを生成する。

このCLIは検体を取得しない。providerのfamily labelを確認済み帰属として
扱わず、後続の :mod:`triage_artifact_retrieval` へ渡す候補だけを、有界な
ページングと重複排除で固定する。検索候補の公開性は未確認であり、出力先は
repository外に限定する。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any

import triage_artifact_retrieval as retrieval

SCHEMA_VERSION = 1
MAX_FAMILIES = 16
MAX_PAGES = 20
MAX_RESULTS = 1_000
PAGE_LIMIT = 200
MAX_CURSOR_LENGTH = 512
FAMILY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def normalize_family(value: object) -> str:
    """API検索に許可する単一family識別子を返す。"""

    family = str(value or "").strip()
    if not FAMILY_RE.fullmatch(family):
        raise ValueError("familyは英数字、'.'、'_'、'-'の1〜64文字が必要です")
    return family.lower()


def _manifest_hashes(path: Path) -> set[str]:
    """本CLIと既存取得manifestのSHA-256を重複排除用に読む。"""

    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, Mapping):
        raise TypeError("除外manifestはJSON objectである必要があります")
    selected_hashes = document.get("selected_hashes") or []
    if not isinstance(selected_hashes, list):
        raise TypeError("除外manifestのselected_hashesは配列である必要があります")
    values: list[object] = list(selected_hashes)
    for key in (
        "candidates",
        "downloads",
        "root_sample_candidates",
        "root_sample_downloads",
    ):
        rows = document.get(key) or []
        if not isinstance(rows, list):
            raise TypeError(f"除外manifestの{key}は配列である必要があります")
        for row in rows:
            if not isinstance(row, Mapping):
                raise TypeError(f"除外manifestの{key}要素はobjectである必要があります")
            row_values = [
                row.get(field)
                for field in ("sha256", "parent_sha256", "expected_sha256")
                if row.get(field)
            ]
            if not row_values:
                raise ValueError(f"除外manifestの{key}要素にSHA-256がありません")
            normalized = {retrieval.normalize_sha256(value) for value in row_values}
            if len(normalized) != 1:
                raise ValueError(f"除外manifestの{key}に矛盾するSHA-256があります")
            values.append(next(iter(normalized)))
    return {retrieval.normalize_sha256(value) for value in values}


def load_excluded_hashes(paths: Iterable[Path]) -> set[str]:
    """複数manifestから既取得SHA-256を読み、集合として返す。"""

    excluded: set[str] = set()
    for path in paths:
        excluded.update(_manifest_hashes(path.resolve(strict=True)))
    return excluded


def _reject_nonlocal_path(path: Path, label: str) -> None:
    """UNC、device、ADS、mapped remote driveを解決前に拒否する。"""

    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError(f"{label}のpath表現が不正です")
    windows = PureWindowsPath(raw)
    normalized = raw.replace("/", "\\")
    if normalized.startswith("\\\\") or windows.drive.startswith("\\\\"):
        raise ValueError(f"{label}にUNC／device pathは使用できません")
    if windows.drive and windows.drive.endswith(":") and not windows.root:
        raise ValueError(f"{label}にdrive相対pathは使用できません")
    colon_positions = [index for index, character in enumerate(raw) if character == ":"]
    drive_colon = (
        len(raw) >= 2
        and raw[0].isalpha()
        and raw[1] == ":"
        and colon_positions == [1]
    )
    if colon_positions and not drive_colon:
        raise ValueError(f"{label}にADS／device指定は使用できません")
    if os.name == "nt" and re.fullmatch(r"[A-Za-z]:\\", windows.anchor):
        import ctypes

        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        if int(get_drive_type(windows.anchor)) == 4:
            raise ValueError(f"{label}にmapped remote driveは使用できません")


def _reject_reparse_components(path: Path, label: str) -> None:
    """解決前の既存path chainにsymlink／junctionがないことを確認する。"""

    absolute = Path(os.path.abspath(path))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    for component in reversed((absolute, *absolute.parents)):
        if not component.exists():
            continue
        try:
            information = component.lstat()
        except OSError as error:
            raise ValueError(f"{label}のpathを検査できません") from error
        attributes = int(getattr(information, "st_file_attributes", 0))
        if component.is_symlink() or attributes & reparse_flag:
            raise ValueError(f"{label}にsymlink／junctionは使用できません")


def validate_private_output_path(path: Path) -> Path:
    """候補manifestが誤ってrepositoryへ保存されないようにする。"""

    _reject_nonlocal_path(path, "output manifest")
    _reject_reparse_components(path, "output manifest")
    target = path.resolve()
    _reject_nonlocal_path(target, "output manifest")
    try:
        target.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return target
    raise ValueError("検索候補manifestはrepository外へ保存してください")


def validate_local_input_path(path: Path) -> Path:
    """除外manifestをlocalの通常fileへ限定して解決する。"""

    _reject_nonlocal_path(path, "exclude manifest")
    _reject_reparse_components(path, "exclude manifest")
    target = path.resolve(strict=True)
    _reject_nonlocal_path(target, "exclude manifest")
    if not target.is_file():
        raise ValueError("exclude manifestは通常fileである必要があります")
    return target


def _validated_page(value: object) -> tuple[list[Mapping[str, Any]], str | None]:
    """Triage collection responseをfail-closedで検証する。"""

    if not isinstance(value, Mapping):
        raise TypeError("Triage検索responseはJSON objectが必要です")
    raw_rows = value.get("data")
    if not isinstance(raw_rows, list):
        raise TypeError("Triage検索response.dataは配列が必要です")
    if len(raw_rows) > PAGE_LIMIT:
        raise ValueError("Triage検索responseが1ページ上限を超えました")
    rows: list[Mapping[str, Any]] = []
    for row in raw_rows:
        if not isinstance(row, Mapping):
            raise TypeError("Triage検索結果の各要素はobjectが必要です")
        rows.append(row)
    raw_cursor = value.get("next")
    if raw_cursor in (None, ""):
        return rows, None
    if not isinstance(raw_cursor, str) or len(raw_cursor) > MAX_CURSOR_LENGTH:
        raise ValueError("Triage検索のnext cursorが不正です")
    if any(character in raw_cursor for character in "\r\n\x00"):
        raise ValueError("Triage検索のnext cursorに制御文字があります")
    if not rows:
        raise ValueError("Triage検索の空ページにnext cursorがあります")
    return rows, raw_cursor


def _require_no_redirect_opener(opener: Any) -> None:
    """Bearer付きrequestへredirect拒否handlerがあることを確認する。"""

    handlers = getattr(opener, "handlers", ())
    if not any(isinstance(handler, retrieval.NoRedirect) for handler in handlers):
        raise ValueError("Triage API openerにはNoRedirect handlerが必要です")


def search_public_families(
    families: Iterable[str],
    *,
    api_key: str,
    opener: Any,
    excluded_hashes: set[str] | None = None,
    maximum_results: int = 100,
    maximum_pages: int = 10,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """family候補を取得し、未確認のprovider labelと帰属を分離して固定する。"""

    normalized_families = tuple(dict.fromkeys(normalize_family(item) for item in families))
    if not normalized_families or len(normalized_families) > MAX_FAMILIES:
        raise ValueError(f"familyは1件から{MAX_FAMILIES}件まで指定できます")
    if not 1 <= maximum_results <= MAX_RESULTS:
        raise ValueError(f"maximum_resultsは1から{MAX_RESULTS}の範囲が必要です")
    if not 1 <= maximum_pages <= MAX_PAGES:
        raise ValueError(f"maximum_pagesは1から{MAX_PAGES}の範囲が必要です")
    if not api_key:
        raise ValueError("Triage API keyが必要です")
    _require_no_redirect_opener(opener)

    excluded = set(excluded_hashes or ())
    selected: list[dict[str, Any]] = []
    selected_hashes: set[str] = set()
    observed_hashes: set[str] = set()
    pages: list[dict[str, Any]] = []
    family_coverage: list[dict[str, Any]] = []
    unqueried_families: list[str] = []
    exclusion_counts = {
        "existing_sha256": 0,
        "duplicate_sha256": 0,
        "non_reported": 0,
        "non_file": 0,
    }

    for family in normalized_families:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        family_complete = False
        family_stop_reason = "maximum_pages_reached"
        for page_index in range(maximum_pages):
            parameters = {
                "query": f"family:{family}",
                "limit": str(PAGE_LIMIT),
            }
            if cursor is not None:
                parameters["offset"] = cursor
            path = f"/search?{urllib.parse.urlencode(parameters)}"
            document = retrieval.api_json(
                path,
                api_key,
                opener=opener,
                timeout=timeout,
            )
            rows, next_cursor = _validated_page(document)
            pages.append(
                {
                    "family": family,
                    "page": page_index + 1,
                    "observed_count": len(rows),
                    "cursor_used": cursor is not None,
                    "next_present": next_cursor is not None,
                }
            )
            for row in rows:
                if row.get("status") != "reported":
                    exclusion_counts["non_reported"] += 1
                    continue
                if row.get("kind") != "file":
                    exclusion_counts["non_file"] += 1
                    continue
                digest = retrieval.normalize_sha256(row.get("sha256"))
                if digest in observed_hashes:
                    exclusion_counts["duplicate_sha256"] += 1
                    continue
                observed_hashes.add(digest)
                if digest in excluded:
                    exclusion_counts["existing_sha256"] += 1
                    continue
                sample_id = str(row.get("id") or "")
                if not retrieval.SAMPLE_ID_RE.fullmatch(sample_id):
                    raise ValueError("Triage検索結果のsample IDが不正です")
                selected.append(
                    {
                        "sha256": digest,
                        "sample_id": sample_id,
                        "triage_family_search": family,
                        "provider_family_hint_is_confirmation": False,
                        "public_page_verified": False,
                    }
                )
                selected_hashes.add(digest)
                if len(selected) >= maximum_results:
                    family_stop_reason = "maximum_results_reached"
                    break
            if len(selected) >= maximum_results:
                break
            if next_cursor is None or not rows:
                family_complete = True
                family_stop_reason = "query_exhausted"
                break
            if next_cursor == cursor or next_cursor in seen_cursors:
                raise ValueError("Triage検索cursorが循環しました")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        family_coverage.append(
            {
                "family": family,
                "complete": family_complete,
                "stop_reason": family_stop_reason,
            }
        )
        if len(selected) >= maximum_results:
            unqueried_families = list(
                normalized_families[normalized_families.index(family) + 1 :]
            )
            break

    candidate_set_complete = (
        not unqueried_families
        and all(item["complete"] for item in family_coverage)
    )
    if len(selected) >= maximum_results:
        stop_reason = "maximum_results_reached"
    elif candidate_set_complete:
        stop_reason = "queries_exhausted"
    else:
        stop_reason = "one_or_more_queries_truncated"

    return {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "source": "Hatching Triage family search",
        "selection_queries": [f"family:{family}" for family in normalized_families],
        "requested": maximum_results,
        "selected": len(selected),
        "selected_hashes": [item["sha256"] for item in selected],
        "excluded_sha256_count": len(excluded),
        "exclusion_counts": exclusion_counts,
        "pages": pages,
        "family_coverage": family_coverage,
        "unqueried_families": unqueried_families,
        "candidate_set_complete": candidate_set_complete,
        "candidate_set_truncated": not candidate_set_complete,
        "stop_reason": stop_reason,
        "candidates": selected,
        "selection_family_label_is_confirmation": False,
        "safety": {
            "sample_executed": False,
            "sample_downloaded": False,
            "external_c2_contacted": False,
            "network_scope": "Triage API family search only",
            "provider_family_label_used_as_confirmation": False,
            "candidate_public_page_verified": False,
        },
    }


def _atomic_write_json(path: Path, document: Mapping[str, Any]) -> None:
    """UTF-8 JSONを同一directoryの一時file経由で置き換える。"""

    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, target)
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    """公開性未確認のfamily候補manifest生成CLIを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", action="append", required=True)
    parser.add_argument("--exclude-manifest", action="append", default=[], type=Path)
    parser.add_argument("--output-manifest", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--allow-network", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """明示network gate後にfamily検索manifestを生成する。"""

    args = build_parser().parse_args(argv)
    if not args.allow_network:
        raise SystemExit("--allow-networkなしではTriage APIへ接続しません")
    api_key = os.environ.get("TRIAGE_API_KEY", "")
    if not api_key:
        raise SystemExit("TRIAGE_API_KEYが必要です")
    output_manifest = validate_private_output_path(args.output_manifest)
    resolved_excludes = [validate_local_input_path(path) for path in args.exclude_manifest]
    if output_manifest in resolved_excludes:
        raise SystemExit("output manifestとexclude manifestは同じpathにできません")
    excluded = load_excluded_hashes(resolved_excludes)
    document = search_public_families(
        args.family,
        api_key=api_key,
        opener=urllib.request.build_opener(retrieval.NoRedirect()),
        excluded_hashes=excluded,
        maximum_results=args.limit,
        maximum_pages=args.max_pages,
        timeout=args.timeout,
    )
    _atomic_write_json(output_manifest, document)
    print(
        json.dumps(
            {
                "selected": document["selected"],
                "output_manifest": str(output_manifest),
                "sample_downloaded": False,
                "provider_family_label_used_as_confirmation": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
