#!/usr/bin/env python3
"""NanoCoreの認証済み追加静的設定を、初回snapshotを保ったまま公開する。"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from handler_evidence import confirmed_static_handler_iocs, trusted_handler_result
from ioc_markdown import render_canonical_ioc_document


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HANDLER_PATH = re.compile(r"handlers/[a-z0-9-]+\.json\Z")
_START = "<!-- nanocore-c2-followup:start -->"
_END = "<!-- nanocore-c2-followup:end -->"


def _object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON objectが必要です: {path}")
    return value


def _render_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _case_document(source: Path, digest: str) -> tuple[dict, list[dict]]:
    report = _object(source / "report.json")
    if report.get("sample", {}).get("sha256") != digest or report.get("executed_sample") is not False:
        raise ValueError("追加解析の親検体SHA-256または安全境界が不一致です")
    pairs = []
    for execution in report.get("handler_executions") or []:
        relative = execution.get("result")
        if not isinstance(relative, str) or _HANDLER_PATH.fullmatch(relative) is None:
            continue
        artifact = _object(source / relative)
        if trusted_handler_result(execution, artifact):
            pairs.append((execution, artifact))
    if len(pairs) != 1:
        raise ValueError(f"NanoCore認証済みhandlerは1件必要です: {digest}")
    execution, artifact = pairs[0]
    result = artifact["result"]
    config = result.get("config")
    resource = result.get("resource")
    if (
        result.get("family") != "nanocore"
        or result.get("sample_sha256") != digest
        or result.get("static_config_recovered") is not True
        or result.get("decoded_config_recovered") is not True
        or result.get("classification_confidence") not in {"confirmed_config_format", "confirmed_reviewed_sample"}
        or not isinstance(config, dict)
        or not isinstance(resource, dict)
        or not isinstance(resource.get("encrypted_length"), int)
        or resource["encrypted_length"] <= 0
        or resource["encrypted_length"] % 8
        or result.get("safety") != {"network_contacted": False, "sample_executed": False}
    ):
        raise ValueError(f"復号設定の証拠が不足しています: {digest}")
    endpoints = confirmed_static_handler_iocs(pairs, family="nanocore")
    if len(endpoints) != 2 or len({(item.get("host"), item.get("port")) for item in endpoints}) != 2:
        raise ValueError(f"主・副C2設定の2件を確認できません: {digest}")
    expected_hosts = {config.get("PrimaryConnectionHost"), config.get("BackupConnectionHost")}
    if expected_hosts != {item["host"] for item in endpoints} or {item["port"] for item in endpoints} != {config.get("ConnectionPort")}:
        raise ValueError("公開endpointと復号設定の値が一致しません")
    c2 = _object(source / "c2-analysis.json")
    if c2.get("sha256") != digest or c2.get("c2", {}).get("outcome") != "unresolved":
        raise ValueError("追加解析のC2契約が不正です")
    expected_values = {f"{item['host']}:{item['port']}" for item in endpoints}
    if {item.get("value") for item in c2["c2"].get("endpoints") or []} != expected_values:
        raise ValueError("C2契約とhandlerのendpointが一致しません")
    document = {
        "schema_version": 1,
        "sha256": digest,
        "family": "nanocore",
        "status": "static_config_endpoints_confirmed_protocol_unresolved",
        "version": result.get("version"),
        "group": result.get("campaign"),
        "handler_id": execution["handler_id"],
        "source_layer_sha256": execution["selected_layer_sha256"],
        "encrypted_resource_length": resource["encrypted_length"],
        "configured_endpoints": endpoints,
        "connect_delay_ms": config.get("ConnectDelay"),
        "keep_alive_timeout_ms": config.get("KeepAliveTimeout"),
        "terminal_payload_reached": False,
        "protocol_confirmed": False,
        "liveness_confirmed": False,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_published": False,
            "raw_payload_published": False,
        },
    }
    return document, endpoints


def _readme_with_note(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    note = (
        f"{_START}\n"
        "追加静的解析でNanoCoreの暗号化設定から主・副の接続先を確認しました。"
        "[根拠と制約](STATIC-C2-FOLLOWUP.md)を参照してください。"
        "以下のC2件数などは初回解析時点のsnapshotです。\n"
        f"{_END}"
    )
    if _START in text:
        start = text.index(_START)
        end = text.index(_END, start) + len(_END)
        return text[:start] + note + text[end:]
    lines = text.splitlines(keepends=True)
    if not lines or not lines[0].startswith("# "):
        raise ValueError(f"case READMEの先頭見出しがありません: {path}")
    return lines[0] + "\n" + note + "\n\n" + "".join(lines[1:])


def _updated_iocs(path: Path, digest: str, endpoints: list[dict]) -> dict:
    existing = _object(path)
    if existing.get("sha256") != [digest] or existing.get("sample_executed") is not False or existing.get("network_contacted") is not False:
        raise ValueError("既存IOCの親SHA-256または安全境界が不一致です")
    values = {f"{item['host']}:{item['port']}" for item in endpoints}
    retained = []
    for item in existing.get("network") or []:
        if not isinstance(item, dict):
            continue
        if item.get("source", "").startswith("handler:nanocore:"):
            continue
        if item.get("source") == "hatching_triage_public_exact_sha256_config" and item.get("value") in values:
            continue
        retained.append(item)
    return {**existing, "network": [*retained, *endpoints]}


def _markdown(document: dict) -> str:
    rows = [
        f"| `{item['host'].replace('.', '[.]')}:{item['port']}` | {item['role']} | 暗号化設定を静的復号 |"
        for item in document["configured_endpoints"]
    ]
    return "\n".join([
        f"# NanoCore追加静的C2解析：{document['sha256']}",
        "",
        "検体SHA-256に束縛したPE resourceをDES-CBCで復号し、PKCS#7と型付き設定列を検証しました。",
        f"設定versionは`{document['version']}`、暗号化resource長は`{document['encrypted_resource_length']}` bytesです。",
        "",
        "| 設定上の接続先 | 役割 | 根拠 |",
        "|---|---|---|",
        *rows,
        "",
        f"設定上の接続遅延は`{document['connect_delay_ms']}` ms、keep-alive timeoutは`{document['keep_alive_timeout_ms']}` msです。",
        "これらは設定値であり、実際の送信時刻を観測したものではありません。",
        "",
        "終端payloadの全経路、通信frame、command分岐、C2稼働は未確認です。"
        "したがって検体単位のC2解析結果は`unresolved`のままです。",
        "検体実行とC2へのライブ接続は行っていません。",
        "",
    ])


def publish(repository: Path, collection_id: str, one_shot_root: Path, digests: list[str], *, write: bool) -> dict:
    collection = repository / "analysis-results" / "collections" / collection_id
    summary = _object(collection / "publication-summary.json")
    indexed = {item["sha256"]: repository / item["case_path"] for item in summary.get("cases") or []}
    if not digests or len(set(digests)) != len(digests) or any(_SHA256.fullmatch(digest) is None for digest in digests):
        raise ValueError("重複しない完全SHA-256を指定してください")
    documents = []
    for digest in sorted(digests):
        case = indexed.get(digest)
        if case is None or case.parent.parent.parent.parent.name != "nanocore":
            raise ValueError(f"collection内のNanoCore caseではありません: {digest}")
        source = one_shot_root / "cases" / digest
        document, endpoints = _case_document(source, digest)
        existing = _object(case / "metadata.json")
        if existing.get("sha256") != digest or existing.get("family") != "nanocore":
            raise ValueError("公開caseの親SHA-256が一致しません")
        iocs = _updated_iocs(case / "iocs.json", digest, endpoints)
        if write:
            (case / "static-c2-followup.json").write_text(_render_json(document), encoding="utf-8")
            (case / "STATIC-C2-FOLLOWUP.md").write_text(_markdown(document), encoding="utf-8")
            (case / "iocs.json").write_text(_render_json(iocs), encoding="utf-8")
            (case / "IOC-LIST.md").write_text(render_canonical_ioc_document(iocs, expected_sha256=digest), encoding="utf-8")
            (case / "README.md").write_text(_readme_with_note(case / "README.md"), encoding="utf-8")
        documents.append({"sha256": digest, "case_path": case.relative_to(repository).as_posix(), "endpoints": [f"{item['host']}:{item['port']}" for item in endpoints]})
    result = {
        "schema_version": 1,
        "collection_id": collection_id,
        "reviewed_cases": len(documents),
        "confirmed_static_endpoint_count": sum(len(item["endpoints"]) for item in documents),
        "cases": documents,
        "protocol_confirmed": False,
        "live_checked": False,
        "samples_executed": False,
    }
    if write:
        (collection / "nanocore-c2-followup.json").write_text(_render_json(result), encoding="utf-8")
        rows = [f"| [`{item['sha256']}`](../../malware/nanocore/versions/unknown/cases/{item['sha256']}/STATIC-C2-FOLLOWUP.md) | {', '.join(value.replace('.', '[.]') for value in item['endpoints'])} |" for item in documents]
        (collection / "NANOCORE-C2-FOLLOWUP.md").write_text("\n".join([
            "# 2026-09-24 NanoCoreの追加静的C2解析", "",
            "2検体の暗号化resourceから設定を復号し、主・副の接続先を静的に確認しました。"
            "初回publication-summaryは初回解析時点のsnapshotです。"
            "終端payload・protocol・稼働確認は未了で、検体単位では未完了です。", "",
            "| SHA-256 | 設定上の接続先 |", "|---|---|", *rows, "",
            "検体とpayloadは実行せず、C2へ接続していません。", "",
        ]), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--one-shot-root", required=True, type=Path)
    parser.add_argument("--hash", action="append", required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = publish(args.repository.resolve(), args.collection_id, args.one_shot_root.resolve(), args.hash, write=args.write)
    print(json.dumps({"reviewed_cases": result["reviewed_cases"], "confirmed_static_endpoint_count": result["confirmed_static_endpoint_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
