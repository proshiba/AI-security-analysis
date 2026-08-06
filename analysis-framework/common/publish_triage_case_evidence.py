#!/usr/bin/env python3
"""完全ハッシュ一致の公開Triage証跡と後段取得結果を正規ケースへ公開する。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any
import urllib.parse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAMPLE_ID_RE = re.compile(r"^\d{6}-[a-z0-9]{10}$")
SAFE_NAME_RE = re.compile(r"^[^\\/\x00-\x1f]{1,240}$")
START_MARKER = "<!-- triage-public-evidence:start -->"
END_MARKER = "<!-- triage-public-evidence:end -->"


def utc_now() -> str:
    """現在時刻をUTCのISO 8601形式で返す。"""

    return datetime.now(timezone.utc).isoformat()


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _io_path(path: Path) -> Path:
    """Windowsの従来のパス長上限を回避できる絶対パスへ変換する。"""

    if os.name != "nt":
        return path
    absolute = str(path.resolve(strict=False))
    if absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)


def _write_json(path: Path, value: object) -> None:
    destination = _io_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = _io_path(path.with_suffix(path.suffix + ".tmp"))
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(destination)


def _write_text(path: Path, value: str) -> None:
    destination = _io_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = _io_path(path.with_suffix(path.suffix + ".tmp"))
    temporary.write_text(value.rstrip() + "\n", encoding="utf-8", newline="\n")
    temporary.replace(destination)


def _sha256(value: Any) -> str:
    digest = str(value or "").strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("有効なSHA-256が必要です")
    return digest


def _sample_id(value: Any) -> str:
    sample_id = str(value or "")
    if not SAMPLE_ID_RE.fullmatch(sample_id):
        raise ValueError("Triage sample IDが不正です")
    return sample_id


def _safe_name(value: Any) -> str | None:
    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1]
    return name if SAFE_NAME_RE.fullmatch(name) else None


def _safe_endpoint(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) > 2_048 or any(ord(char) < 32 for char in text):
        return None
    match = re.fullmatch(r"(?P<host>[A-Za-z0-9.-]+)(?::(?P<port>\d{1,5}))?", text)
    if match:
        port = match.group("port")
        if port is None or 1 <= int(port) <= 65_535:
            return text.lower()
        return None
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https", "ftp"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        host = parsed.hostname.lower()
        netloc = f"{host}:{port}" if port is not None else host
        return urllib.parse.urlunsplit(
            (parsed.scheme.lower(), netloc, parsed.path or "/", "", "")
        )
    return None


def _collection_cases(repository: Path, collection_id: str) -> dict[str, Path]:
    root = repository / "analysis-results" / "collections" / collection_id
    manifest = _json(root / "manifest.json")
    expected = {
        _sha256(str(item.get("case_id") or "").removeprefix("sha256:"))
        for item in manifest.get("cases") or []
    }
    indexed: dict[str, Path] = {}
    for summary_path in (root / "sources").glob("*/summary.json"):
        summary = _json(summary_path)
        for case in summary.get("cases") or []:
            digest = _sha256(case.get("sha256"))
            relative = Path(str(case.get("case_path") or ""))
            absolute = (repository / relative).resolve()
            absolute.relative_to(repository.resolve())
            if digest in indexed and indexed[digest] != absolute:
                raise ValueError(f"case pathが重複しています: {digest}")
            indexed[digest] = absolute
    if set(indexed) != expected:
        raise ValueError("collection membershipとcase pathの対応が一致しません")
    return indexed


def _normalize_match(parent_sha256: str, match: dict[str, Any]) -> dict[str, Any]:
    if _sha256(match.get("sha256")) != parent_sha256:
        raise ValueError("Triage一致結果のSHA-256が親検体と一致しません")
    if match.get("visibility") != "public_searchable_api":
        raise ValueError("公開確認済みではないTriage結果です")
    sample_id = _sample_id(match.get("sample_id"))
    if match.get("triage_url") != f"https://tria.ge/{sample_id}":
        raise ValueError("Triage参照URLが解析IDと一致しません")
    config = sorted(
        {
            endpoint
            for value in match.get("config_endpoints") or []
            if (endpoint := _safe_endpoint(value))
        }
    )[:100]
    reports = []
    for report in (match.get("reports") or [])[:4]:
        processes = []
        for process in (report.get("processes") or [])[:100]:
            command_sha256 = process.get("command_sha256")
            if command_sha256 is not None:
                command_sha256 = _sha256(command_sha256)
            processes.append(
                {
                    "image": _safe_name(process.get("image")),
                    "command_sha256": command_sha256,
                    "command_pattern": str(process.get("command_pattern") or "unknown")[:120],
                    "processes_in_command": sorted(
                        {_safe_name(value) for value in process.get("processes_in_command") or []}
                        - {None}
                    )[:30],
                }
            )
        network = sorted(
            {
                endpoint
                for value in report.get("network_context") or []
                if (endpoint := _safe_endpoint(value))
            }
        )[:200]
        dumped = []
        for item in (report.get("dumped_files") or [])[:100]:
            digest = item.get("sha256")
            dumped.append(
                {
                    "name": _safe_name(item.get("name")),
                    "sha256": _sha256(digest) if digest else None,
                    "downloaded": False,
                }
            )
        reports.append(
            {
                "task_id": str(report.get("task_id") or "")[:120] or None,
                "processes": processes,
                "network_context": network,
                "network_classification": "context_only",
                "dumped_files": dumped,
            }
        )
    return {
        "sample_id": sample_id,
        "triage_url": match["triage_url"],
        "target": _safe_name(match.get("target")),
        "size": int(match.get("size") or 0),
        "score": match.get("score"),
        "families": sorted({str(value)[:120] for value in match.get("families") or []}),
        "config_endpoints": config,
        "config_endpoint_assessment": "sandbox_config_candidate",
        "reports": reports,
    }


def _artifact_index(path: Path | None, membership: set[str]) -> dict[str, list[dict[str, Any]]]:
    indexed = {digest: [] for digest in membership}
    if path is None:
        return indexed
    manifest = _json(path)
    for item in manifest.get("downloads") or []:
        parent = _sha256(item.get("parent_sha256"))
        if parent not in membership:
            raise ValueError("artifact manifestにcollection外の親検体があります")
        indexed[parent].append(
            {
                "sample_id": _sample_id(item.get("sample_id")),
                "kind": str(item.get("kind") or "unknown")[:80],
                "name": _safe_name(item.get("name")),
                "sha256": _sha256(item.get("artifact_sha256")),
                "size": int(item.get("size") or 0),
                "duplicate_of_parent": bool(item.get("duplicate_of_parent")),
                "executed": False,
                "stored_in_repository": False,
            }
        )
    return indexed


def _artifact_analysis_index(path: Path | None) -> dict[str, dict[str, Any]]:
    """後段成果物へ適用したローカル静的解析の公開可能な状態だけを抽出する。"""

    indexed: dict[str, dict[str, Any]] = {}
    if path is None:
        return indexed
    summary = _json(path)
    for item in summary.get("cases") or []:
        digest = _sha256(item.get("sha256"))
        indexed[digest] = {
            "family": str(item.get("family") or "unknown")[:120],
            "selected_family": (
                str(item["selected_family"])[:120]
                if item.get("selected_family") is not None
                else None
            ),
            "case_state": str(item.get("case_state") or "unknown")[:40],
            "handler_succeeded": int(item.get("handler_succeeded") or 0),
            "analysis_stage_failed": bool(item.get("analysis_stage_failed")),
            "sample_executed": False,
            "network_contacted": False,
        }
    return indexed

def _render_case(evidence: dict[str, Any]) -> str:
    matches = evidence["public_matches"]
    endpoints = sorted({value for match in matches for value in match["config_endpoints"]})
    processes = sorted(
        {
            process["image"]
            for match in matches
            for report in match["reports"]
            for process in report["processes"]
            if process["image"]
        }
    )
    recovered = evidence["recovered_artifacts"]
    match_rows = [
        f"- [{item['sample_id']}]({item['triage_url']}): ファミリー候補 `{', '.join(item['families']) or '未確定'}`、評価score `{item['score']}`"
        for item in matches
    ] or ["- 完全ハッシュ一致の公開解析は確認できませんでした。"]
    endpoint_rows = [f"- `{value}`（sandbox config候補）" for value in endpoints] or ["- 取得できませんでした。"]
    artifact_rows = [
        f"- `{item['sha256']}` / `{item['kind']}` / {item['size']} bytes / "
        f"親と同一: `{str(item['duplicate_of_parent']).lower()}` / "
        f"静的解析: `{(item.get('static_analysis') or {}).get('case_state', '未実施')}`"
        for item in recovered
    ] or ["- 取得できませんでした。"]
    return f"""# Triage公開解析・後段取得証跡

## 完全ハッシュ一致

{chr(10).join(match_rows)}

## プロセス・通信

- 観測process: `{', '.join(processes) or '取得できず'}`
- raw commandは保存せず、command SHA-256と処理patternだけをJSONへ保持しています。
- sandbox background trafficは`context_only`であり、C2へ自動昇格しません。

{chr(10).join(endpoint_rows)}

## 二段目成果物

{chr(10).join(artifact_rows)}

```mermaid
flowchart LR
    A["親検体 SHA-256固定"] --> B["公開Triage解析との完全一致"]
    B --> C["process・config・通信contextを正規化"]
    C --> D["dump／memory候補を限定取得"]
    D --> E["暗号化保存・ハッシュ検証"]
    E --> F["ローカル静的解析（実行なし）"]
```

## 判定境界

Triage由来のfamily、process、config、通信は外部sandbox証跡です。config extractorが返したendpointはC2候補として扱えますが、
静的設定復元またはprocess帰属とprotocol応答が揃うまでは確認済みC2とはしません。取得成果物と検体は実行していません。
"""


def _readme_section(case_root: Path, evidence: dict[str, Any]) -> None:
    readme_path = case_root / "README.md"
    text = readme_path.read_text(encoding="utf-8-sig")
    section = (
        f"{START_MARKER}\n## 公開sandbox・二段目解析\n\n"
        f"完全ハッシュ一致の公開Triage解析は`{len(evidence['public_matches'])}`件、"
        f"取得して静的解析へ渡した後段成果物は`{len(evidence['recovered_artifacts'])}`件です。"
        "詳細は[TRIAGE.md](TRIAGE.md)を参照してください。\n"
        f"{END_MARKER}"
    )
    pattern = re.compile(re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER), re.DOTALL)
    text = pattern.sub(section, text) if pattern.search(text) else text.rstrip() + "\n\n" + section + "\n"
    _write_text(readme_path, text)


def _merge_iocs(case_root: Path, evidence: dict[str, Any]) -> None:
    """sandbox config endpointだけを候補IOCへ追加し、通信contextは除外する。"""

    path = case_root / "iocs.json"
    document = _json(path) if path.is_file() else {"schema_version": 1}
    network = document.get("network")
    if not isinstance(network, list):
        network = []
    source = "hatching_triage_public_exact_sha256_config"
    retained = [
        item
        for item in network
        if not isinstance(item, dict) or item.get("source") != source
    ]
    endpoints = sorted(
        {
            endpoint
            for match in evidence["public_matches"]
            for endpoint in match["config_endpoints"]
        }
    )
    retained.extend(
        {
            "value": endpoint,
            "role": "c2_candidate_external_sandbox_config",
            "confidence": "medium_external_sandbox_exact_hash",
            "classification": "candidate_not_static_confirmed",
            "source": source,
        }
        for endpoint in endpoints
    )
    document["network"] = retained
    document.setdefault("network_contacted", False)
    document.setdefault("sample_executed", False)
    _write_json(path, document)

def publish(
    repository: Path,
    collection_id: str,
    triage_result: Path,
    artifact_manifest: Path | None,
    artifact_analysis_summary: Path | None,
    *,
    write: bool,
) -> dict[str, Any]:
    """公開Triage証拠と後段解析状態を正規caseへ反映する。"""

    repository = repository.resolve()
    cases = _collection_cases(repository, collection_id)
    source = _json(triage_result)
    artifacts = _artifact_index(artifact_manifest, set(cases))
    artifact_analysis = _artifact_analysis_index(artifact_analysis_summary)
    for rows in artifacts.values():
        for item in rows:
            item["static_analysis"] = artifact_analysis.get(item["sha256"])
    results = []
    source_by_hash = {_sha256(item.get("sha256")): item for item in source.get("results") or []}
    for digest, case_root in sorted(cases.items()):
        row = source_by_hash.get(digest, {"matches": [], "errors": [{"error": "not_queried"}]})
        matches = []
        omitted = 0
        for match in row.get("matches") or []:
            try:
                matches.append(_normalize_match(digest, match))
            except ValueError:
                omitted += 1
        evidence = {
            "schema_version": 1,
            "sha256": digest,
            "generated_at_utc": utc_now(),
            "source": "Hatching Triage public exact-SHA-256 analysis",
            "public_matches": matches,
            "omitted_matches": omitted,
            "query_errors": [
                {"error": str(item.get("error") or "unknown")[:80]}
                for item in (row.get("errors") or [])[:20]
            ],
            "recovered_artifacts": artifacts[digest],
            "safety": {
                "sample_submitted": False,
                "sample_executed_locally": False,
                "artifact_executed": False,
                "raw_commands_published": False,
                "private_analysis_published": False,
                "artifact_binaries_stored_in_repository": False,
            },
        }
        if write:
            _write_json(case_root / "triage-evidence.json", evidence)
            _write_text(case_root / "TRIAGE.md", _render_case(evidence))
            _readme_section(case_root, evidence)
            _merge_iocs(case_root, evidence)
        results.append(
            {
                "sha256": digest,
                "case_path": case_root.relative_to(repository).as_posix(),
                "public_matches": len(matches),
                "config_endpoints": len({v for match in matches for v in match["config_endpoints"]}),
                "recovered_artifacts": len(artifacts[digest]),
            }
        )
    summary = {
        "schema_version": 1,
        "collection_id": collection_id,
        "generated_at_utc": utc_now(),
        "cases": len(results),
        "cases_with_public_matches": sum(item["public_matches"] > 0 for item in results),
        "public_matches": sum(item["public_matches"] for item in results),
        "config_endpoints": sum(item["config_endpoints"] for item in results),
        "recovered_artifacts": sum(item["recovered_artifacts"] for item in results),
        "results": results,
        "samples_executed_locally": False,
    }
    if write:
        root = repository / "analysis-results" / "collections" / collection_id
        _write_json(root / "triage-summary.json", summary)
        rows = [
            f"| `{item['sha256']}` | {item['public_matches']} | {item['config_endpoints']} | {item['recovered_artifacts']} |"
            for item in results
            if item["public_matches"] or item["recovered_artifacts"]
        ]
        _write_text(
            root / "TRIAGE-SUMMARY.md",
            f"""# Triage公開解析・後段取得サマリー

- 対象case: `{summary['cases']}`件
- 公開完全ハッシュ一致あり: `{summary['cases_with_public_matches']}`件
- 公開解析一致: `{summary['public_matches']}`件
- sandbox config endpoint候補: `{summary['config_endpoints']}`件
- 取得済み後段成果物: `{summary['recovered_artifacts']}`件
- ローカル実行: `0`件

| SHA-256 | 公開解析 | config候補 | 後段成果物 |
|---|---:|---:|---:|
{chr(10).join(rows) or '| なし | 0 | 0 | 0 |'}

通信contextは正規OSのbackground trafficを含み得るため、config endpointと分離し、C2へ自動昇格していません。
""",
        )
    return summary


def build_parser() -> argparse.ArgumentParser:
    """公開証拠反映CLIの引数parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--triage-result", type=Path, required=True)
    parser.add_argument("--artifact-manifest", type=Path)
    parser.add_argument("--artifact-analysis-summary", type=Path)
    parser.add_argument("--write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Triage証拠の検証・公開処理を実行する。"""

    args = build_parser().parse_args(argv)
    summary = publish(
        args.repository,
        args.collection_id,
        args.triage_result.resolve(),
        args.artifact_manifest.resolve() if args.artifact_manifest else None,
        args.artifact_analysis_summary.resolve() if args.artifact_analysis_summary else None,
        write=args.write,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
