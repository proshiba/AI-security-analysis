#!/usr/bin/env python3
"""ClickFix caseをTriageの既存解析と照合し、公開可能な要約を生成する。"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

from clickfix_daily_intake import (
    DOMAIN_RE,
    atomic_json,
    command_profile,
    sanitize_domain,
    sanitize_url,
    utc_now,
)

TRIAGE_API = "https://tria.ge/api/v0"
USER_AGENT = "AI-security-analysis ClickFix Triage enrichment/1.0"
MAX_CASES = 50
MAX_MATCHES = 3
MAX_REPORTS = 2
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
SAMPLE_ID_RE = re.compile(r"^\d{6}-[a-z0-9]{10}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8", newline="\n")


def _api_json(path: str, api_key: str, timeout: float) -> Any:
    request = urllib.request.Request(
        TRIAGE_API + path,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("Triage応答が上限を超えました")
        return json.loads(data.decode("utf-8"))


def _safe_basename(value: Any) -> str | None:
    text = str(value or "").replace("\\", "/").rstrip("/")
    if not text:
        return None
    return text.rsplit("/", 1)[-1][:260]


def _safe_endpoint(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) > 2_048:
        return None
    if text.lower().startswith(("http://", "https://")):
        return sanitize_url(text)["sanitized"]
    domain = sanitize_domain(text)
    if DOMAIN_RE.fullmatch(domain):
        return domain
    if IP_RE.fullmatch(text):
        return text
    if re.fullmatch(r"[a-z0-9.-]+:\d{1,5}", text, re.IGNORECASE):
        host, port = text.rsplit(":", 1)
        if DOMAIN_RE.fullmatch(host) or IP_RE.fullmatch(host):
            return f"{host.lower()}:{port}"
    return None


def _iter_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _iter_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_values(child)


def _families(overview: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for target in overview.get("targets") or []:
        for family in target.get("family") or []:
            if isinstance(family, str):
                values.add(family)
        for tag in target.get("tags") or []:
            if isinstance(tag, str) and tag.startswith("family:"):
                values.add(tag.split(":", 1)[1])
    for extracted in overview.get("extracted") or []:
        family = (extracted.get("config") or {}).get("family")
        if isinstance(family, str):
            values.add(family)
    return sorted(values)


def _artifact_candidates(overview: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for extracted in overview.get("extracted") or []:
        for key, category in (("resource", "memory"), ("dumped_file", "dumped_file")):
            value = extracted.get(key)
            if not isinstance(value, str) or not value:
                continue
            actual_category = "memory" if "/memory/" in value else category
            marker = (actual_category, value)
            if marker in seen:
                continue
            seen.add(marker)
            artifacts.append(
                {
                    "category": actual_category,
                    "name": _safe_basename(value),
                    "reference_sha256": hashlib.sha256(value.encode()).hexdigest(),
                    "downloaded": False,
                }
            )
    return artifacts[:50]


def _config_endpoints(overview: dict[str, Any]) -> list[str]:
    endpoints: set[str] = set()
    keys = {"c2", "cnc", "domain", "domains", "url", "urls", "ip", "ips", "host", "hosts"}
    for extracted in overview.get("extracted") or []:
        config = extracted.get("config") or {}
        for key, value in _iter_values(config):
            if key.lower() not in keys:
                continue
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                endpoint = _safe_endpoint(candidate)
                if endpoint:
                    endpoints.add(endpoint)
    return sorted(endpoints)[:100]


def summarize_overview(overview: dict[str, Any]) -> dict[str, Any]:
    sample = overview.get("sample") or {}
    analysis = overview.get("analysis") or {}
    tasks = overview.get("tasks") or {}
    behavioral = []
    for task_id, task in tasks.items():
        if task.get("kind") != "behavioral" or task.get("status") != "reported":
            continue
        behavioral.append(
            {
                "task_id": task_id,
                "name": task.get("name") or task_id.rsplit("-", 1)[-1],
                "os": task.get("os") or task.get("platform"),
                "target": _safe_basename(task.get("target")),
                "score": task.get("score"),
                "tags": sorted(str(tag) for tag in task.get("tags") or []),
                "pcap_downloaded": False,
            }
        )
    sha256 = str(sample.get("sha256") or "").lower()
    return {
        "sample_id": sample.get("id"),
        "sha256": sha256 if SHA256_RE.fullmatch(sha256) else None,
        "target": _safe_basename(sample.get("target")),
        "size": sample.get("size"),
        "score": sample.get("score", analysis.get("score")),
        "families": _families(overview),
        "behavioral_tasks": behavioral,
        "artifact_candidates": _artifact_candidates(overview),
        "config_endpoints": _config_endpoints(overview),
    }


def summarize_report(report: dict[str, Any]) -> dict[str, Any]:
    processes = []
    seen_processes: set[tuple[str | None, str]] = set()
    for process in report.get("processes") or []:
        image = _safe_basename(process.get("image") or process.get("orig"))
        command = str(process.get("cmd") or "")
        digest = hashlib.sha256(command.encode()).hexdigest() if command else None
        marker = (image, digest or "")
        if marker in seen_processes:
            continue
        seen_processes.add(marker)
        profile = command_profile(command) if command else None
        processes.append(
            {
                "image": image,
                "command_sha256": digest,
                "command_pattern": profile.get("pattern") if profile else None,
                "processes_in_command": profile.get("processes") if profile else [],
            }
        )
    endpoints: set[str] = set()
    network = report.get("network") or {}
    network_keys = {"url", "host", "hostname", "domain", "ip", "dst", "destination"}
    for key, value in _iter_values(network):
        if key.lower() not in network_keys:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            endpoint = _safe_endpoint(candidate)
            if endpoint:
                endpoints.add(endpoint)
    dumped = []
    for entry in report.get("dumped") or []:
        if not isinstance(entry, dict):
            continue
        sha256 = str(entry.get("sha256") or "").lower()
        dumped.append(
            {
                "name": _safe_basename(entry.get("path") or entry.get("name")),
                "sha256": sha256 if SHA256_RE.fullmatch(sha256) else None,
                "downloaded": False,
            }
        )
    task = report.get("task") or {}
    return {
        "task_id": task.get("id") or task.get("name"),
        "processes": processes[:50],
        "network_context": sorted(endpoints)[:100],
        "dumped_files": dumped[:50],
    }


def _query_case(case: dict[str, Any], api_key: str, timeout: float, private_root: Path) -> dict[str, Any]:
    case_id = str(case["case_id"])
    domain = sanitize_domain(str(case["domain"]))
    case_private = private_root / case_id
    searches = []
    errors = []
    matches: dict[str, dict[str, Any]] = {}
    query_specs = [("domain", domain)]
    for full_url in case.get("candidate_urls") or []:
        sanitized = sanitize_url(str(full_url))["sanitized"]
        if sanitized:
            query_specs.append(("url", sanitized))
    for sha256 in case.get("sha256_candidates") or []:
        normalized = str(sha256).lower()
        if SHA256_RE.fullmatch(normalized):
            query_specs.append(("sha256", normalized))
    for operator, value in query_specs:
        query = f"{operator}:{value}"
        try:
            response = _api_json(
                "/search?" + urllib.parse.urlencode({"query": query}),
                api_key,
                timeout,
            )
            atomic_json(case_private / f"search-{operator}.json", response)
            rows = response.get("data") or []
            searches.append({"operator": operator, "result_count": len(rows)})
            for row in rows:
                sample_id = str(row.get("id") or "")
                if SAMPLE_ID_RE.fullmatch(sample_id):
                    matches.setdefault(sample_id, row)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append({"operator": operator, "error": type(error).__name__})
    public_matches = []
    private_matches_omitted = 0
    for sample_id, row in list(matches.items())[:MAX_MATCHES]:
        try:
            metadata = _api_json(f"/samples/{sample_id}", api_key, timeout)
            atomic_json(case_private / sample_id / "metadata.json", metadata)
            if metadata.get("private") is not False:
                private_matches_omitted += 1
                continue
            overview = _api_json(f"/samples/{sample_id}/overview.json", api_key, timeout)
            atomic_json(case_private / sample_id / "overview.json", overview)
            summarized = summarize_overview(overview)
            reports = []
            for task in summarized["behavioral_tasks"][:MAX_REPORTS]:
                task_name = str(task["task_id"])
                if task_name.startswith(sample_id + "-"):
                    task_name = task_name[len(sample_id) + 1 :]
                try:
                    report = _api_json(
                        f"/samples/{sample_id}/{task_name}/report_triage.json",
                        api_key,
                        timeout,
                    )
                    atomic_json(case_private / sample_id / f"report-{task_name}.json", report)
                    reports.append(summarize_report(report))
                except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
                    errors.append({"sample_id": sample_id, "task": task_name, "error": type(error).__name__})
            summarized["reports"] = reports
            summarized["triage_url"] = f"https://tria.ge/{sample_id}"
            summarized["submitted"] = row.get("submitted")
            public_matches.append(summarized)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append({"sample_id": sample_id, "error": type(error).__name__})
    return {
        "schema_version": 1,
        "case_id": case_id,
        "domain": domain,
        "queried_at_utc": utc_now(),
        "queries": searches,
        "public_match_count": len(public_matches),
        "private_matches_omitted": private_matches_omitted,
        "matches": public_matches,
        "errors": errors,
        "safety": {
            "sample_submitted": False,
            "sample_downloaded": False,
            "artifact_downloaded": False,
            "pcap_downloaded": False,
            "sample_executed_locally": False,
        },
    }


def render_case(result: dict[str, Any]) -> str:
    matches = result["matches"]
    if not matches:
        match_text = "公開済み解析との一致は確認できませんでした。"
    else:
        blocks = []
        for match in matches:
            tasks = match["behavioral_tasks"]
            process_names = sorted(
                {
                    process["image"]
                    for report in match.get("reports") or []
                    for process in report.get("processes") or []
                    if process.get("image")
                }
            )
            command_hashes = sorted(
                {
                    process["command_sha256"]
                    for report in match.get("reports") or []
                    for process in report.get("processes") or []
                    if process.get("command_sha256")
                }
            )
            network = sorted(
                set(match.get("config_endpoints") or [])
                | {
                    endpoint
                    for report in match.get("reports") or []
                    for endpoint in report.get("network_context") or []
                }
            )
            artifact_counts = {}
            for artifact in match.get("artifact_candidates") or []:
                category = artifact["category"]
                artifact_counts[category] = artifact_counts.get(category, 0) + 1
            blocks.append(
                f"""### [{match["sample_id"]}]({match["triage_url"]})

- SHA-256: `{match.get("sha256") or "未提示"}`
- 対象名: `{match.get("target") or "未提示"}`
- score: `{match.get("score")}`
- family: `{", ".join(match.get("families") or []) or "未確定"}`
- behavioral task: `{len(tasks)}`件
- process: `{", ".join(process_names[:30]) or "取得できず"}`
- command証跡: raw commandは公開せずSHA-256 `{len(command_hashes)}`件
- 通信候補: `{", ".join(network[:30]) or "取得できず"}`
- artifact候補: `{json.dumps(artifact_counts, ensure_ascii=False)}`

通信先にはサンドボックスOSや正規ソフトウェアのbackground trafficが混在し得ます。
config extractor、process帰属、複数taskでの再現を確認するまではC2へ昇格しません。"""
            )
        match_text = "\n\n".join(blocks)
    query_text = (
        ", ".join(f"`{row['operator']}:` {row['result_count']}件" for row in result["queries"]) or "API応答なし"
    )
    return f"""# Hatching Triage照合

## 結果

- domain: `{result["domain"]}`
- 照合日時: `{result["queried_at_utc"]}`
- 検索結果: {query_text}
- 公開一致: `{result["public_match_count"]}`件
- 非公開一致の公開成果物への転記: `{result["private_matches_omitted"]}`件を除外
- API error: `{len(result["errors"])}`件

{match_text}

## 調査方針

Triageの既存解析を`domain:`、取得済み完全URLの`url:`、取得済みhashの`sha256:`で照合し、
公開sampleだけについてoverviewと最大2件のbehavioral reportを要約しました。プロセス名、command SHA-256、通信候補、抽出ファイル、
memory由来resourceの有無を残します。raw command、private sample情報、API keyは公開しません。

## 未実施操作

- 新規sample提出: 実施していません。
- 元sample、dumped file、memory dump、PCAPのdownload: 実施していません。
- ローカル実行: 実施していません。

artifactを取得する場合は対象taskと保存先を明示し、`.work`配下でhash検証してから別工程で扱います。

## 参照

- [Triage Search API](https://tria.ge/docs/cloud-api/search/)
- [Triage Samples API](https://tria.ge/docs/cloud-api/samples/)
- [Triage解析種別](https://tria.ge/docs/analysis/)
"""


def render_collection(results: list[dict[str, Any]], analysis_date: str) -> str:
    matches = sum(item["public_match_count"] for item in results)
    errors = sum(len(item["errors"]) for item in results)
    rows = []
    for item in results:
        rows.append(
            f"| `{item['domain']}` | {item['public_match_count']} | "
            f"{item['private_matches_omitted']} | {len(item['errors'])} |"
        )
    return f"""# ClickFix Triage照合サマリー: {analysis_date}

- case数: `{len(results)}`
- 公開解析一致: `{matches}`件
- API error: `{errors}`件
- 新規提出／検体・memory・PCAP download: `0`件

| domain | 公開一致 | private除外 | error |
|---|---:|---:|---:|
{chr(10).join(rows)}

一致なしは「未解析」を意味しません。domainがTriage extractorへ残らない、別stageで停止する、
時限配信である、または別IOCで登録されている可能性があります。hashを取得した場合は`sha256:`で
再照合します。
"""


def enrich(
    repository: Path,
    analysis_date: str,
    private_root: Path,
    api_key: str,
    workers: int,
    timeout: float,
    write: bool,
) -> list[dict[str, Any]]:
    collection_id = f"clickfix-daily-{analysis_date.replace('-', '')}"
    manifest_path = repository / "analysis-results" / "clickfix" / "collections" / collection_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = list(manifest.get("cases") or [])
    if not cases or len(cases) > MAX_CASES:
        raise ValueError(f"case件数が範囲外です: {len(cases)}")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 4))) as executor:
        futures = {executor.submit(_query_case, case, api_key, timeout, private_root): case for case in cases}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    order = {case["case_id"]: index for index, case in enumerate(cases)}
    results.sort(key=lambda item: order[item["case_id"]])
    if write:
        for case, result in zip(cases, results, strict=True):
            case_root = repository / "analysis-results" / "clickfix" / case["relative_path"]
            atomic_json(case_root / "triage-evidence.json", result)
            _write_text(case_root / "TRIAGE.md", render_case(result))
        collection_root = manifest_path.parent
        _write_text(collection_root / "TRIAGE-SUMMARY.md", render_collection(results, analysis_date))
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--analysis-date", required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    api_key = os.environ.get("TRIAGE_API_KEY")
    if not api_key:
        raise SystemExit("TRIAGE_API_KEYが必要です")
    results = enrich(
        args.repository.resolve(),
        args.analysis_date,
        args.private_output.resolve() / args.analysis_date,
        api_key,
        args.workers,
        args.timeout,
        args.write,
    )
    print(
        json.dumps(
            {
                "cases": len(results),
                "public_matches": sum(item["public_match_count"] for item in results),
                "errors": sum(len(item["errors"]) for item in results),
                "write_performed": bool(args.write),
                "sample_submitted": False,
                "artifact_downloaded": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
