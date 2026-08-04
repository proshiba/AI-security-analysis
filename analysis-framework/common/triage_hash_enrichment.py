#!/usr/bin/env python3
"""SHA-256をHatching Triageの既存解析へ照合し、公開可能な要約だけを保存する。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CLICKFIX_ROOT = REPOSITORY_ROOT / "analysis-framework" / "clickfix"
if str(CLICKFIX_ROOT) not in sys.path:
    sys.path.insert(0, str(CLICKFIX_ROOT))

import clickfix_triage_enrichment as triage  # noqa: E402


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def collection_partial_hashes(collection: Path) -> list[str]:
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    return [
        str(case["sha256"]).lower()
        for case in summary.get("cases") or []
        if case.get("case_state") == "partial" and SHA256_RE.fullmatch(str(case.get("sha256") or "").lower())
    ]


def collection_hashes(collection: Path) -> list[str]:
    """collectionに属する全SHA-256を、公開段階に依存せず返す。"""

    summary_path = collection / "publication-summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        hashes = [
            str(case.get("sha256") or "").lower()
            for case in summary.get("cases") or []
        ]
        valid = sorted({value for value in hashes if SHA256_RE.fullmatch(value)})
        if valid:
            return valid

    manifest = json.loads((collection / "manifest.json").read_text(encoding="utf-8"))
    hashes = []
    for case in manifest.get("cases") or []:
        value = str(case.get("sha256") or "").lower()
        if not value:
            value = str(case.get("case_id") or "").lower().removeprefix("sha256:")
        if SHA256_RE.fullmatch(value):
            hashes.append(value)
    return sorted(set(hashes))


def enrich_hash(sha256: str, api_key: str, timeout: float) -> dict[str, object]:
    response = triage._api_json(
        "/search?" + urllib.parse.urlencode({"query": f"sha256:{sha256}"}),
        api_key,
        timeout,
    )
    rows = response.get("data") or []
    matches = []
    errors = []
    for row in rows[:3]:
        sample_id = str(row.get("id") or "")
        if not triage.SAMPLE_ID_RE.fullmatch(sample_id):
            continue
        try:
            metadata = triage._api_json(f"/samples/{sample_id}", api_key, timeout)
            metadata_hash = str(metadata.get("sha256") or "").lower()
            if metadata_hash != sha256:
                errors.append({"sample_id": sample_id, "error": "sha256_mismatch"})
                continue
            if metadata.get("private") is True or metadata.get("owner"):
                errors.append({"sample_id": sample_id, "error": "private_result_omitted"})
                continue
            overview = triage._api_json(f"/samples/{sample_id}/overview.json", api_key, timeout)
            summarized = triage.summarize_overview(overview)
            reports = []
            for task in summarized["behavioral_tasks"][:2]:
                task_name = str(task["task_id"])
                if task_name.startswith(sample_id + "-"):
                    task_name = task_name[len(sample_id) + 1 :]
                report = triage._api_json(
                    f"/samples/{sample_id}/{task_name}/report_triage.json",
                    api_key,
                    timeout,
                )
                reports.append(triage.summarize_report(report))
            matches.append(
                {
                    **summarized,
                    "sample_id": sample_id,
                    "triage_url": f"https://tria.ge/{sample_id}",
                    "visibility": "public_searchable_api",
                    "reports": reports,
                }
            )
        except Exception as error:  # APIはheterogeneousなnetwork/parser例外を返す
            errors.append({"sample_id": sample_id, "error": type(error).__name__})
    return {
        "sha256": sha256,
        "search_result_count": len(rows),
        "matches": matches,
        "errors": errors,
        "safety": {
            "sample_submitted": False,
            "sample_downloaded": False,
            "artifact_downloaded": False,
            "memory_dump_downloaded": False,
            "pcap_downloaded": False,
            "sample_executed_locally": False,
            "raw_commands_published": False,
            "api_key_published": False,
        },
    }


def run(hashes: list[str], api_key: str, timeout: float) -> dict[str, object]:
    normalized = sorted({value.lower() for value in hashes})
    if not normalized or any(not SHA256_RE.fullmatch(value) for value in normalized):
        raise ValueError("SHA-256は1件以上の有効な値が必要です")
    results = [enrich_hash(value, api_key, timeout) for value in normalized]
    return {
        "schema_version": 1,
        "query_type": "sha256_existing_analysis_only",
        "results": results,
        "counts": {
            "hashes": len(results),
            "search_results": sum(int(item["search_result_count"]) for item in results),
            "summarized_matches": sum(len(item["matches"]) for item in results),
            "errors": sum(len(item["errors"]) for item in results),
        },
        "safety": {
            "sample_submitted": False,
            "sample_downloaded": False,
            "artifact_downloaded": False,
            "sample_executed_locally": False,
            "network_contacted": True,
            "network_scope": "tria.ge API only",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hash", action="append", default=[])
    parser.add_argument("--collection", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    hashes = list(arguments.hash)
    if arguments.collection:
        hashes.extend(collection_hashes(arguments.collection.resolve()))
    api_key = os.environ.get("TRIAGE_API_KEY")
    if not api_key:
        raise SystemExit("TRIAGE_API_KEYが必要です")
    result = run(hashes, api_key, arguments.timeout)
    _atomic_json(arguments.output.resolve(), result)
    print(json.dumps(result["counts"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
